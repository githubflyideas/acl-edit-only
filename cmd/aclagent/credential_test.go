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

// TestLoadPasswordRejectsSingleLine covers a misconfiguration that used to pass
// silently: a credential file holding only the base64 password. The username
// came back empty and the operator saw an authentication failure from the
// switch with nothing pointing at the file.
func TestLoadPasswordRejectsSingleLine(t *testing.T) {
	_, err := loadPassword(writeCred(t, "czNjcmV0\n"))
	if err == nil { t.Fatal("expected an error for a credential file with no username line") }
	if !strings.Contains(err.Error(), "two lines") {
		t.Errorf("error = %q, want it to say what the file should look like", err)
	}
}

// TestLoadPasswordRejectsPlaintext catches the other easy mistake: writing the
// password itself instead of its base64.
func TestLoadPasswordRejectsPlaintext(t *testing.T) {
	_, err := loadPassword(writeCred(t, "admin\nnot base64 at all!\n"))
	if err == nil { t.Fatal("expected an error for a non-base64 second line") }
}
