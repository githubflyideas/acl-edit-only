package device

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"
)

func openTo(t *testing.T, dev *fakedev.Device) *Session {
	t.Helper()
	addr, err := dev.Start()
	if err != nil { t.Fatalf("start fake device: %v", err) }
	t.Cleanup(dev.Close)
	s := NewSession(&TelnetTransport{}, DialConfig{Addr: addr, ConnectTimeout: 5 * time.Second},
		&Auth{Username: "aclbot", Password: []byte("aclbot-pw")}, 3977, 5*time.Second)
	if err := s.Open(context.Background()); err != nil { t.Fatalf("open: %v", err) }
	t.Cleanup(func() { s.Close(context.Background()) })
	if err := s.EnterSystemView(context.Background()); err != nil { t.Fatalf("system-view: %v", err) }
	return s
}

// TestACLViewWithoutTheViewNameInThePrompt covers a device whose prompt does not
// change when it enters ACL view. Requiring the prompt to spell out
// "-acl-ipv4-adv-N" made such a switch unusable even though every command
// afterwards would have worked, and the wording of that prompt is a Comware
// build detail this project cannot pin down.
func TestACLViewWithoutTheViewNameInThePrompt(t *testing.T) {
	dev := fakedev.New("SW-PLAIN", 3977, "aclbot", "aclbot-pw", nil)
	dev.ACLViewPromptPlain = true
	s := openTo(t, dev)
	if err := s.EnterACLView(context.Background()); err != nil {
		t.Fatalf("enter acl view on a device that keeps its prompt: %v", err)
	}
	if err := s.ExecRule(context.Background(), "rule 2000 permit ip destination 10.0.0.1 0"); err != nil {
		t.Fatalf("rule command after entering acl view: %v", err)
	}
	if rules := dev.Rules(); len(rules) != 1 {
		t.Errorf("rules on device = %v, want exactly one", rules)
	}
}

// TestACLViewInTheWrongACLIsStillRefused is the other half: relaxing the prompt
// must not give up the guarantee the check exists for. A session sitting in some
// other ACL's view has to be refused, because a rule dispatched there lands in
// an ACL nobody approved.
func TestACLViewInTheWrongACLIsStillRefused(t *testing.T) {
	dev := fakedev.New("SW-LIAR", 3977, "aclbot", "aclbot-pw", nil)
	dev.ACLViewPromptPlain = true
	dev.ACLViewDisplayThisACL = 9999
	s := openTo(t, dev)
	err := s.EnterACLView(context.Background())
	if err == nil { t.Fatal("entered a view the device says belongs to ACL 9999") }
	if !strings.Contains(err.Error(), "9999") {
		t.Errorf("error = %v, want it to show what the device said", err)
	}
}
