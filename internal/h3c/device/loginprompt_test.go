package device

import (
	"context"
	"testing"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"
)

// TestOpenAgainstLowercaseLoginPrompt covers the switch that asks "login:"
// instead of "Username:". Comware uses both words depending on version and on
// how the vty authenticates, and a client that knows only one of them does not
// fail with a wrong-word error: it waits for a prompt that has already gone
// past and reports a timeout at the auth stage, which points suspicion at the
// credential file instead of at the prompt.
func TestOpenAgainstLowercaseLoginPrompt(t *testing.T) {
	for _, word := range []string{"login:", "login: ", "Login:", "Username:"} {
		t.Run(word, func(t *testing.T) {
			dev := fakedev.New("SW-LOGIN", 3977, "aclbot", "aclbot-pw", nil)
			dev.LoginPromptText = word
			addr, err := dev.Start()
			if err != nil { t.Fatalf("start fake device: %v", err) }
			defer dev.Close()

			s := NewSession(&TelnetTransport{}, DialConfig{Addr: addr, ConnectTimeout: 5 * time.Second},
				&Auth{Username: "aclbot", Password: []byte("aclbot-pw")}, 3977, 5*time.Second)
			if err := s.Open(context.Background()); err != nil {
				t.Fatalf("open against a device prompting %q: %v", word, err)
			}
			defer s.Close(context.Background())
			if _, err := s.DisplayACL(context.Background()); err != nil {
				t.Fatalf("display acl after login: %v", err)
			}
		})
	}
}
