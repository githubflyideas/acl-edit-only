package device

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"
)

// TestOpenAgainstPasswordOnlyDevice covers a switch that authenticates on a
// password with no local user account: it goes straight to "Password:" and never
// asks who is connecting. Sending a username at that point would be swallowed as
// the password, and the login would fail as a rejected credential.
func TestOpenAgainstPasswordOnlyDevice(t *testing.T) {
	dev := fakedev.New("SW-PWONLY", 3977, "", "only-a-password", nil)
	addr, err := dev.Start()
	if err != nil { t.Fatalf("start fake device: %v", err) }
	defer dev.Close()

	s := NewSession(&TelnetTransport{}, DialConfig{Addr: addr, ConnectTimeout: 5 * time.Second},
		&Auth{Password: []byte("only-a-password")}, 3977, 5*time.Second)
	if err := s.Open(context.Background()); err != nil {
		t.Fatalf("open with a password-only credential: %v", err)
	}
	defer s.Close(context.Background())
	if _, err := s.DisplayACL(context.Background()); err != nil {
		t.Fatalf("display acl after password-only login: %v", err)
	}
}

// TestUsernamePromptWithoutUsernameIsNamed makes sure the opposite mistake — a
// credential file holding only a password, pointed at a device that does want a
// username — says which line is missing instead of reporting a rejected login.
func TestUsernamePromptWithoutUsernameIsNamed(t *testing.T) {
	dev := fakedev.New("SW-USER", 3977, "aclbot", "aclbot-pw", nil)
	addr, err := dev.Start()
	if err != nil { t.Fatalf("start fake device: %v", err) }
	defer dev.Close()

	s := NewSession(&TelnetTransport{}, DialConfig{Addr: addr, ConnectTimeout: 5 * time.Second},
		&Auth{Password: []byte("aclbot-pw")}, 3977, 5*time.Second)
	err = s.Open(context.Background())
	if err == nil { t.Fatal("open succeeded without the username the device asked for") }
	if !strings.Contains(err.Error(), "first line") {
		t.Errorf("error = %v, want it to name the missing username line", err)
	}
}
