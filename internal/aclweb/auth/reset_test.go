package auth

import (
	"path/filepath"
	"testing"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/db"
	"golang.org/x/crypto/bcrypt"
)

// TestResetPasswordLetsTheOwnerBackIn covers the case the initial-password print
// leaves open: the line scrolled away, or the process was started with stderr
// redirected somewhere nobody kept. The reset must produce a password that works
// and must invalidate whatever sessions existed.
func TestResetPasswordLetsTheOwnerBackIn(t *testing.T) {
	sqlDB, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil { t.Fatalf("db: %v", err) }
	defer sqlDB.Close()
	s := NewService(sqlDB)
	if _, err := s.CreateInitialAdmin("admin"); err != nil { t.Fatalf("bootstrap: %v", err) }

	tok, err := s.Login("admin", mustInitial(t, s), "127.0.0.1")
	if err != nil { t.Fatalf("login before reset: %v", err) }

	pw, err := s.ResetPassword("admin")
	if err != nil { t.Fatalf("reset: %v", err) }
	if len(pw) < 16 { t.Errorf("reset password %q is too short to be the generated one", pw) }

	if _, err := s.ValidateSession(tok); err == nil {
		t.Error("the session held before the reset still validates; a reset must revoke sessions")
	}
	if _, err := s.Login("admin", pw, "127.0.0.2"); err != nil {
		t.Errorf("login with the reset password: %v", err)
	}
	if _, err := s.ResetPassword("nobody"); err == nil {
		t.Error("resetting an unknown user succeeded")
	}
}

// mustInitial reaches around CreateInitialAdmin returning the password only once:
// the account already exists here, so a second call returns nothing. A fresh
// reset gives us a password we know, which is all the test needs to log in with.
func mustInitial(t *testing.T, s *Service) string {
	t.Helper()
	pw := "Bootstrap-Password-1234"
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil { t.Fatalf("hash: %v", err) }
	if _, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE username='admin'`, string(hash)); err != nil {
		t.Fatalf("seed password: %v", err)
	}
	return pw
}
