package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCred(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(p, []byte(body), 0400); err != nil { t.Fatal(err) }
	return p
}

func TestLoadPasswordWellFormed(t *testing.T) {
	pw, err := loadPassword(writeCred(t, "admin\nczNjcmV0\n"))
	if err != nil { t.Fatalf("loadPassword: %v", err) }
	if string(pw) != "s3cret" { t.Errorf("password = %q, want s3cret", pw) }
	u, err := loadUsername(writeCred(t, "admin\nczNjcmV0\n"))
	if err != nil { t.Fatalf("loadUsername: %v", err) }
	if u != "admin" { t.Errorf("username = %q, want admin", u) }
}

// TestSingleLineIsAPasswordOnlyCredential covers a switch that authenticates on
// a password with no local user account. The file holds the base64 password and
// nothing else, and the username must come back empty rather than defaulting to
// something, so that the session sends no username at all.
func TestSingleLineIsAPasswordOnlyCredential(t *testing.T) {
	pw, err := loadPassword(writeCred(t, "czNjcmV0\n"))
	if err != nil { t.Fatalf("loadPassword: %v", err) }
	if string(pw) != "s3cret" { t.Errorf("password = %q, want s3cret", pw) }
	u, err := loadUsername(writeCred(t, "czNjcmV0\n"))
	if err != nil { t.Fatalf("loadUsername: %v", err) }
	if u != "" { t.Errorf("username = %q, want empty for a password-only file", u) }
}

// TestEmptyCredentialFileIsNamed keeps the one genuinely broken case from being
// read as a password-only login with an empty password.
func TestEmptyCredentialFileIsNamed(t *testing.T) {
	_, err := loadPassword(writeCred(t, "\n \n"))
	if err == nil { t.Fatal("expected an error for an empty credential file") }
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q, want it to say the file is empty", err)
	}
}

// TestLoadPasswordRejectsPlaintext catches the other easy mistake: writing the
// password itself instead of its base64.
func TestLoadPasswordRejectsPlaintext(t *testing.T) {
	_, err := loadPassword(writeCred(t, "admin\nnot base64 at all!\n"))
	if err == nil { t.Fatal("expected an error for a non-base64 second line") }
}
