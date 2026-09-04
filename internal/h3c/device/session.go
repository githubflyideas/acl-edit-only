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
	promptPassword = "Password:"
	promptUserView = ">"
	promptSysView  = "]"
	promptMore     = "---- More ----"
	promptSaveCFM  = "Y/N"
)

// rePrompt matches a device prompt that sits at the very end of the output.
// Requiring end-of-text is what makes reads safe against rule comments that
// happen to contain ">" or "]": those appear mid-line, never as the tail.
//
// What may precede the prompt is any of the bytes a device uses to get back to
// the start of a line, not a newline alone. Insisting on "\n" was a guess about
// what a device does between the last banner line and the prompt, and the
// deployed switch pads its carriage returns with NUL, so the guess is not one
// worth keeping. This is a widening only: every prompt the newline form matched
// still matches. It was written while chasing a login timeout that turned out
// not to be caused by it, and it is not evidence that any device behaves this
// way.
var rePrompt = regexp.MustCompile(`(?:^|[\n\r\x00])(?:<[^<>\n]{1,64}>|\[[^\[\]\n]{1,64}\])[ \t\r\x00]*\z`)

// reMore matches the paging marker. Devices pad it differently, so the spacing
// is deliberately loose.
var reMore = regexp.MustCompile(`----\s*More\s*----`)

// reUsernamePrompt and rePasswordPrompt match the two login questions. Comware
// asks who is connecting with "Username:" on some versions and "login:" on
// others, and the word also depends on how the vty is authenticated, so neither
// spelling can be assumed. Both are anchored at the end of the output because a
// prompt is the last thing the device sends before it waits.
var reUsernamePrompt = regexp.MustCompile(`(?i)(?:username|login)\s*:[ \t\r\x00]*\z`)
var rePasswordPrompt = regexp.MustCompile(`(?i)password\s*:[ \t\r\x00]*\z`)

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

// aclViewNumberedRe matches a prompt that names the ACL some other way than
// Comware 7 does — "-acl-adv-N" on older builds, for instance. What has to be
// there is the number: the check exists to confirm which ACL the session is in,
// not to confirm the wording.
func aclViewNumberedRe(aclNum int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`\[[^\[\]\n]*\b%d\][ \t\r\x00]*\z`, aclNum))
}

// reDisplayThisACL matches the line "display this" prints to say which ACL the
// view belongs to. Comware writes "acl number N", "acl advanced N" and
// "acl ipv4 advanced N" depending on build.
func reDisplayThisACL(aclNum int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?im)^\s*acl\s+(?:ipv4\s+)?(?:number|advanced|basic)?\s*%d\b`, aclNum))
}

// trailingPrompt returns the prompt sitting at the end of the output, or "".
func trailingPrompt(out string) string {
	m := rePrompt.FindString(out)
	return strings.Trim(m, " \t\r\n\x00")
}

type Session struct {
	stream io.Writer
	// wire, when set, receives every chunk read from the device exactly as it
	// arrived, Go-quoted. Line endings and control bytes are invisible in a
	// transcript, and guessing at them from a hand-copied paste is how two
	// releases went out without fixing the right thing.
	wire io.Writer
	tr      Transport
	cfg     DialConfig
	auth    *Auth
	aclNum  int
	timeout time.Duration
	rawBuf  strings.Builder
	inAuth  bool
	// aclPrompt is the prompt the device showed once ACL view was established.
	aclPrompt string
}

func NewSession(tr Transport, cfg DialConfig, auth *Auth, aclNum int, readTimeout time.Duration) *Session {
	return &Session{tr: tr, cfg: cfg, auth: auth, aclNum: aclNum, timeout: readTimeout}
}

func (s *Session) Open(ctx context.Context) error {
	s.inAuth = true
	if err := s.tr.Connect(ctx, s.cfg); err != nil {
		return &SessionError{Stage: "connect", Cause: err}
	}
	// A switch configured with a password and no local user account goes straight
	// to "Password:" and never asks who is connecting. Which of the two prompts
	// arrives decides what to send, rather than assuming a username is always
	// wanted: sending one to a device that did not ask for it consumes the
	// password prompt and the login fails for a reason that looks nothing like
	// the cause.
	out, idx, err := s.readUntilRe(ctx, []*regexp.Regexp{reUsernamePrompt, rePasswordPrompt, rePrompt})
	if err != nil {
		return &SessionError{Stage: "auth", Cause: fmt.Errorf("no login prompt: %w; the device sent %s", err, quoteTail(out))}
	}
	if idx == 0 {
		if s.auth.Username == "" {
			return &SessionError{Stage: "auth", Cause: fmt.Errorf(
				"the device asked for a username but the credential file holds only a password; " +
					"put the username on the first line and the base64 of the password on the second")}
		}
		if err := s.send(ctx, s.auth.Username+"\r\n"); err != nil {
			return &SessionError{Stage: "auth", Cause: err}
		}
		out, _, err := s.readUntilRe(ctx, []*regexp.Regexp{rePasswordPrompt})
		if err != nil {
			return &SessionError{Stage: "auth", Cause: fmt.Errorf("no password prompt: %w; the device sent %s", err, quoteTail(out))}
		}
	}
	if err := s.tr.Send(ctx, append(s.auth.Password, '\r', '\n')); err != nil {
		return &SessionError{Stage: "auth", Cause: err}
	}
	out, idx, err = s.readUntilRe(ctx, []*regexp.Regexp{rePrompt, rePasswordPrompt})
	if err != nil {
		// The tail goes into the message with the password taken out of it. Without
		// it this timeout says only that something was expected and did not arrive,
		// which is the least useful thing an error about a prompt can say, and the
		// prompt is precisely what differs between switches.
		return &SessionError{Stage: "auth", Cause: fmt.Errorf("login failed: %w; the device sent %s",
			err, quoteTail(scrubPassword(out, s.auth.Password)))}
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
	// NUL bytes come first. Telnet spells a carriage return that is not a line
	// ending as CR NUL, and the switch this was deployed against ends lines that
	// way. They carry no text and only get in the way of the replay below.
	raw = strings.ReplaceAll(raw, "\x00", "")
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		lines[i] = moreLineRe.ReplaceAllString(replayCR(l), "")
	}
	return strings.Join(lines, "\n")
}

// replayCR resolves the carriage returns inside one line the way a terminal
// would: the cursor goes back to the start of the line and whatever follows is
// painted over what was there. Only a segment that actually paints something
// counts. A device that ends its lines with one or more bare carriage returns —
// CR LF, CR CR LF, CR NUL LF — writes nothing after the last one, and the text
// already on the line stands. Treating those as overwrites is what erased every
// line of a real switch's output and left a snapshot of blank lines.
func replayCR(line string) string {
	segs := strings.Split(line, "\r")
	for i := len(segs) - 1; i >= 0; i-- {
		if strings.TrimSpace(segs[i]) != "" { return segs[i] }
	}
	return ""
}

func (s *Session) EnterSystemView(ctx context.Context) error {
	return s.Exec(ctx, "system-view", promptSysView)
}

// EnterACLView enters the ACL's view and then establishes, by whatever evidence
// the device offers, that this really is ACL s.aclNum's view. A prompt naming
// the view is the cheapest evidence; a prompt naming only the host is not
// evidence at all, and there "display this" is asked instead, because entering
// the wrong ACL is the one mistake this check exists to prevent. Once settled,
// the exact prompt is remembered so every later command in the session can be
// held to it without asking again.
func (s *Session) EnterACLView(ctx context.Context) error {
	out, err := s.ExecOutput(ctx, fmt.Sprintf("acl advanced %d", s.aclNum), "]")
	if err != nil { return err }
	if aclViewPromptRe(s.aclNum).MatchString(out) || aclViewNumberedRe(s.aclNum).MatchString(out) {
		s.aclPrompt = trailingPrompt(out)
		return nil
	}
	if trailingPrompt(out) == "" {
		return &SessionError{Stage: "view",
			Cause: fmt.Errorf("prompt_mismatch: no prompt after entering ACL %d view; the device sent %s", s.aclNum, quoteTail(out))}
	}
	conf, err := s.ExecOutput(ctx, "display this", "]")
	if err != nil { return err }
	if !reDisplayThisACL(s.aclNum).MatchString(conf) {
		return &SessionError{Stage: "view",
			Cause: fmt.Errorf("view_mismatch: the prompt does not name a view and \"display this\" does not show ACL %d; the device sent %s", s.aclNum, quoteTail(conf))}
	}
	s.aclPrompt = trailingPrompt(conf)
	return nil
}

func (s *Session) ExecRule(ctx context.Context, cmd string) error    { return s.execInACLView(ctx, cmd) }
func (s *Session) ExecComment(ctx context.Context, cmd string) error { return s.execInACLView(ctx, cmd) }
func (s *Session) ExecUndoRule(ctx context.Context, cmd string) error { return s.execInACLView(ctx, cmd) }

func (s *Session) execInACLView(ctx context.Context, cmd string) error {
	out, err := s.ExecOutput(ctx, cmd, "]", ">")
	if err != nil { return err }
	// The prompt settled at entry is the one that has to come back. Comparing
	// against it rather than against a pattern is what keeps the relaxed entry
	// check honest: whatever evidence was accepted then, a command that changed
	// view afterwards still shows up as a different prompt.
	if got := trailingPrompt(out); got != s.aclPrompt {
		return &SessionError{Stage: "view", Cause: fmt.Errorf(
			"prompt_mismatch: left ACL view; prompt was %q, now %q; the device sent %s", s.aclPrompt, got, quoteTail(out))}
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
		// The transcript and the live stream stay out of the auth phase, but the
		// wire dump does not: every byte-level failure so far has been in the login
		// exchange, and a diagnostic that cannot see the part that breaks is not a
		// diagnostic. The password is removed rather than the whole chunk withheld.
		if s.wire != nil { fmt.Fprintf(s.wire, "%q\n", scrubPassword(out, s.auth.Password)) } //nolint:errcheck
		return
	}
	if s.wire != nil { fmt.Fprintf(s.wire, "%q\n", out) } //nolint:errcheck
	// The NUL half of telnet's CR NUL is punctuation, not text. It has no place
	// in a transcript a person reads or in the JSON a snapshot returns, where it
	// showed up as a line of "\u0000" and made a healthy session look broken.
	out = strings.ReplaceAll(out, "\x00", "")
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

// quoteTail renders the last of what the device sent, Go-quoted so that the
// control bytes that decide these questions are visible. It must not be used on
// a read that could carry credential bytes: an error string reaches the
// transcript and the browser stream, which the auth phase is deliberately kept
// out of. The two login reads it is used on both happen before the password
// goes out; the rest are device configuration output.
// scrubPassword removes the password from text that is about to be shown. It is
// what makes it safe to quote the device during authentication: the only way a
// password can appear in device output is an echo, and an echo is exactly the
// kind of thing worth seeing with the secret taken out of it.
func scrubPassword(out string, password []byte) string {
	pw := strings.TrimRight(string(password), "\r\n")
	if len(pw) < 3 { return out }
	return strings.ReplaceAll(out, pw, "<password>")
}

func quoteTail(out string) string {
	if out == "" { return "nothing at all" }
	if len(out) > 200 { out = "..." + out[len(out)-200:] }
	return fmt.Sprintf("%q instead", out)
}

type SessionError struct{ Stage string; Cause error }
func (e *SessionError) Error() string { return fmt.Sprintf("[%s] %s", e.Stage, e.Cause) }
func (e *SessionError) Unwrap() error { return e.Cause }
