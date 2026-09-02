package device

import (
	"context"
	"fmt"
	"regexp"
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

var errorPatterns = []string{
	"Error:", "% Error", "% Unrecognized command",
	"% Wrong parameter", "% Too many", "^%",
	"% Ambiguous", "% Incomplete",
}

func aclViewPromptRe(aclNum int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`\[.*-acl-ipv4-adv-%d\]`, aclNum))
}

type Session struct {
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
	if err := s.Exec(ctx, "screen-length disable", promptUserView, promptSysView); err != nil {
		return "", err
	}
	return s.ExecOutput(ctx, fmt.Sprintf("display acl %d", s.aclNum), promptUserView, promptSysView)
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

func (s *Session) Exec(ctx context.Context, cmd string, waitFor ...string) error {
	_, err := s.ExecOutput(ctx, cmd, waitFor...)
	return err
}

func (s *Session) ExecOutput(ctx context.Context, cmd string, waitFor ...string) (string, error) {
	if err := s.send(ctx, cmd+"\r\n"); err != nil {
		return "", &SessionError{Stage: "write", Cause: err}
	}
	all := append(waitFor, promptMore)
	out, idx, err := s.readUntil(ctx, all)
	if err != nil { return out, err }
	if idx == len(waitFor) {
		return out, &SessionError{Stage: "view", Cause: fmt.Errorf("paging detected – screen-length disable must be sent first")}
	}
	if err := checkDeviceErrors(out); err != nil {
		return out, &SessionError{Stage: "write", Cause: err}
	}
	return out, nil
}

func (s *Session) send(ctx context.Context, txt string) error { return s.tr.Send(ctx, []byte(txt)) }

func (s *Session) readUntil(ctx context.Context, patterns []string) (string, int, error) {
	out, idx, err := s.tr.ReadUntil(ctx, patterns, time.Now().Add(s.timeout))
	if !s.inAuth { s.rawBuf.WriteString(out) }
	if err != nil { return out, idx, &SessionError{Stage: "view", Cause: err} }
	return out, idx, nil
}

func checkDeviceErrors(out string) error {
	for _, p := range errorPatterns {
		if strings.Contains(out, p) {
			return fmt.Errorf("device error: %s", lastLine(out))
		}
	}
	return nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	if len(lines) == 0 { return s }
	return strings.TrimSpace(lines[len(lines)-1])
}

type SessionError struct{ Stage string; Cause error }
func (e *SessionError) Error() string { return fmt.Sprintf("[%s] %s", e.Stage, e.Cause) }
func (e *SessionError) Unwrap() error { return e.Cause }
