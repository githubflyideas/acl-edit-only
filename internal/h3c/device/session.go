package device

import (
	"context"
	"fmt"
	"regexp"
	"io"
	"strings"
	"time"
)

const (
	promptUsername = "Username:"
	promptPassword = "Password:"
	promptUserView = ">"
	promptSysView  = "]"
	promptMore     = "---- More ----"
	promptSaveCFM  = "Y/N"
)

// rePrompt matches a device prompt that sits at the very end of the output.
// Requiring end-of-text is what makes reads safe against rule comments that
// happen to contain ">" or "]": those appear mid-line, never as the tail.
var rePrompt = regexp.MustCompile(`(?:^|\n)(?:<[^<>\n]{1,64}>|\[[^\[\]\n]{1,64}\])[ \t\r\x00]*\z`)

// reMore matches the paging marker. Devices pad it differently, so the spacing
// is deliberately loose.
var reMore = regexp.MustCompile(`----\s*More\s*----`)

var reSuccess = regexp.MustCompile(`(?i)success`)
var reSaveCFM = regexp.MustCompile(`\[Y/N\]|\(Y/N\)|Y/N`)

var moreLineRe = regexp.MustCompile(`(?m)[ \t]*----\s*More\s*----[^\n]*`)

var errorPatterns = []string{
	"Error:", "% Error", "% Unrecognized command",
	"% Wrong parameter", "% Too many", "^%",
	"% Ambiguous", "% Incomplete",
}

func aclViewPromptRe(aclNum int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`\[.*-acl-ipv4-adv-%d\]`, aclNum))
}

type Session struct {
	stream io.Writer
	tr      Transport
	cfg     DialConfig
	auth    *Auth
	aclNum  int
	timeout time.Duration
	rawBuf  strings.Builder
	inAuth  bool
}

func NewSession(tr Transport, cfg DialConfig, auth *Auth, aclNum int, readTimeout time.Duration) *Session {
	return &Session{tr: tr, cfg: cfg, auth: auth, aclNum: aclNum, timeout: readTimeout}
}

func (s *Session) Open(ctx context.Context) error {
	s.inAuth = true
	if err := s.tr.Connect(ctx, s.cfg); err != nil {
		return &SessionError{Stage: "connect", Cause: err}
	}
	if _, _, err := s.readUntil(ctx, []string{promptUsername, promptUserView, promptSysView}); err != nil {
		return &SessionError{Stage: "auth", Cause: fmt.Errorf("no login prompt: %w", err)}
	}
	if err := s.send(ctx, s.auth.Username+"\r\n"); err != nil {
		return &SessionError{Stage: "auth", Cause: err}
	}
	if _, _, err := s.readUntil(ctx, []string{promptPassword}); err != nil {
		return &SessionError{Stage: "auth", Cause: fmt.Errorf("no password prompt: %w", err)}
	}
	if err := s.tr.Send(ctx, append(s.auth.Password, '\r', '\n')); err != nil {
		return &SessionError{Stage: "auth", Cause: err}
	}
	_, idx, err := s.readUntil(ctx, []string{promptUserView, promptPassword})
	if err != nil {
		return &SessionError{Stage: "auth", Cause: fmt.Errorf("login failed: %w", err)}
	}
	if idx == 1 {
		return &SessionError{Stage: "auth", Cause: fmt.Errorf("authentication rejected")}
	}
	s.inAuth = false
	return nil
}

func (s *Session) DisplayACL(ctx context.Context) (string, error) {
	if err := s.send(ctx, fmt.Sprintf("display acl %d\r\n", s.aclNum)); err != nil {
		return "", &SessionError{Stage: "view", Cause: err}
	}
	// reMore is tested before rePrompt: a page that ends in the paging marker
	// must never be mistaken for the end of the output, or the tail of the ACL
	// is lost silently and rule-ID allocation reuses a live ID.
	pats := []*regexp.Regexp{reMore, rePrompt}
	var full strings.Builder
	for pages := 0; ; pages++ {
		if pages > maxPages {
			return full.String(), &SessionError{Stage: "view",
				Cause: fmt.Errorf("output did not end after %d pages", maxPages)}
		}
		out, idx, err := s.readUntilRe(ctx, pats)
		full.WriteString(out)
		if err != nil {
			return full.String(), err
		}
		if idx == 1 {
			break
		}
		if err := s.tr.Send(ctx, []byte{' '}); err != nil {
			return full.String(), &SessionError{Stage: "view", Cause: err}
		}
	}
	result := normalizeTerminal(full.String())
	if err := checkDeviceErrors(result); err != nil {
		return result, &SessionError{Stage: "view", Cause: err}
	}
	return result, nil
}

// maxPages bounds the paging loop so a device that keeps answering with the
// paging marker cannot spin forever. 4000 pages is far more than the largest
// possible ACL and small enough to fail in bounded time.
const maxPages = 4000

// normalizeTerminal replays carriage returns the way a terminal would: within
// a line, anything before the last CR has been overwritten on screen and is
// therefore not part of the text. This is what erases the "---- More ----"
// marker along with the spaces the device paints over it.
func normalizeTerminal(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		// The CR that terminates the line is punctuation, not an overwrite.
		l = strings.TrimSuffix(l, "\r")
		if idx := strings.LastIndex(l, "\r"); idx >= 0 {
			l = l[idx+1:]
		}
		lines[i] = moreLineRe.ReplaceAllString(l, "")
	}
	return strings.Join(lines, "\n")
}

func (s *Session) EnterSystemView(ctx context.Context) error {
	return s.Exec(ctx, "system-view", promptSysView)
}

func (s *Session) EnterACLView(ctx context.Context) error {
	out, err := s.ExecOutput(ctx, fmt.Sprintf("acl advanced %d", s.aclNum), "]")
	if err != nil { return err }
	if !aclViewPromptRe(s.aclNum).MatchString(out) {
		return &SessionError{Stage: "view",
			Cause: fmt.Errorf("prompt_mismatch: did not enter ACL %d view", s.aclNum)}
	}
	return nil
}

func (s *Session) ExecRule(ctx context.Context, cmd string) error    { return s.execInACLView(ctx, cmd) }
func (s *Session) ExecComment(ctx context.Context, cmd string) error { return s.execInACLView(ctx, cmd) }
func (s *Session) ExecUndoRule(ctx context.Context, cmd string) error { return s.execInACLView(ctx, cmd) }

func (s *Session) execInACLView(ctx context.Context, cmd string) error {
	out, err := s.ExecOutput(ctx, cmd, "]", ">")
	if err != nil { return err }
	if !aclViewPromptRe(s.aclNum).MatchString(out) {
		return &SessionError{Stage: "view", Cause: fmt.Errorf("prompt_mismatch: left ACL view")}
	}
	return checkDeviceErrors(out)
}

func (s *Session) Save(ctx context.Context) error {
	out, err := s.ExecOutput(ctx, "save force", promptUserView, promptSysView, "successfully")
	if err != nil { return &SessionError{Stage: "save", Cause: err} }
	if !strings.Contains(strings.ToLower(out), "success") {
		if strings.Contains(out, promptSaveCFM) {
			if err2 := s.send(ctx, "Y\r\n"); err2 != nil {
				return &SessionError{Stage: "save", Cause: err2}
			}
			out2, _, err2 := s.readUntil(ctx, []string{"successfully", promptUserView, promptSysView})
			if err2 != nil { return &SessionError{Stage: "save", Cause: err2} }
			if !strings.Contains(strings.ToLower(out2), "success") {
				return &SessionError{Stage: "save", Cause: fmt.Errorf("save did not report success")}
			}
			return nil
		}
		return &SessionError{Stage: "save", Cause: fmt.Errorf("save did not report success: %s", out)}
	}
	return nil
}

func (s *Session) QuitACLView(ctx context.Context) error { return s.Exec(ctx, "quit", promptSysView) }
func (s *Session) QuitSysView(ctx context.Context) error { return s.Exec(ctx, "quit", promptUserView) }

func (s *Session) Close(ctx context.Context) {
	_ = s.send(ctx, "quit\r\n")
	_ = s.tr.Close()
}

func (s *Session) RawOutput() string { return s.rawBuf.String() }

// TryExec runs a command whose failure is acceptable. The output is still
// recorded and the prompt is still consumed, so the session stays in sync.
func (s *Session) TryExec(ctx context.Context, cmd string, waitFor ...string) error {
	if err := s.send(ctx, cmd+"\r\n"); err != nil {
		return &SessionError{Stage: "write", Cause: err}
	}
	out, _, err := s.readUntil(ctx, waitFor)
	if err != nil {
		return err
	}
	return checkDeviceErrors(out)
}

func (s *Session) Exec(ctx context.Context, cmd string, waitFor ...string) error {
	_, err := s.ExecOutput(ctx, cmd, waitFor...)
	return err
}

func (s *Session) ExecOutput(ctx context.Context, cmd string, waitFor ...string) (string, error) {
	if err := s.send(ctx, cmd+"\r\n"); err != nil {
		return "", &SessionError{Stage: "write", Cause: err}
	}
	out, _, err := s.readUntil(ctx, waitFor)
	if err != nil { return out, err }
	if err := checkDeviceErrors(out); err != nil {
		return out, &SessionError{Stage: "write", Cause: err}
	}
	return out, nil
}

func (s *Session) send(ctx context.Context, txt string) error { return s.tr.Send(ctx, []byte(txt)) }

func (s *Session) readUntilRe(ctx context.Context, res []*regexp.Regexp) (string, int, error) {
	out, idx, err := s.tr.ReadUntilRe(ctx, res, time.Now().Add(s.timeout))
	s.record(out)
	if err != nil {
		return out, idx, &SessionError{Stage: "view", Cause: err}
	}
	return out, idx, nil
}

// record mirrors device output into the transcript and the live stream. The
// auth phase is excluded so the password never reaches either.
func (s *Session) record(out string) {
	if s.inAuth {
		return
	}
	s.rawBuf.WriteString(out)
	if s.stream != nil {
		s.stream.Write([]byte(out)) //nolint:errcheck
	}
}

func (s *Session) readUntil(ctx context.Context, patterns []string) (string, int, error) {
	out, idx, err := s.tr.ReadUntil(ctx, patterns, time.Now().Add(s.timeout))
	s.record(out)
	if err != nil { return out, idx, &SessionError{Stage: "view", Cause: err} }
	return out, idx, nil
}

func checkDeviceErrors(out string) error {
	for _, p := range errorPatterns {
		if strings.Contains(out, p) {
			return fmt.Errorf("device error: %s", offendingLine(out, p))
		}
	}
	return nil
}

// offendingLine returns the line that carries the error text. Reporting the
// last line instead would report the prompt, which says nothing about what
// went wrong.
func offendingLine(out, pattern string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, pattern) {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(out)
}

type SessionError struct{ Stage string; Cause error }
func (e *SessionError) Error() string { return fmt.Sprintf("[%s] %s", e.Stage, e.Cause) }
func (e *SessionError) Unwrap() error { return e.Cause }
