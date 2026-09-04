package device_test

import (
	"context"
	"strings"
	"testing"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/device"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"
)

// Removing a rule had never been exercised against a device. The agent sent every
// plan through Apply, which renders a rule command out of match fields a delete
// plan does not carry, so this whole path was dead code.
func TestRemoveTakesTheRuleOutAndSaves(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(3))
	s := dial(t, d)
	if err := device.Remove(context.Background(), s, 101, 3); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, r := range d.Rules() {
		if r.ID == 101 { t.Fatalf("rule 101 is still there; rules are %v", d.Rules()) }
	}
	if len(d.Rules()) != 2 {
		t.Errorf("expected 2 rules left, got %d", len(d.Rules()))
	}
	if !d.Saved {
		t.Error("the removal was not saved")
	}
	if !strings.Contains(s.RawOutput(), "undo rule 101") {
		t.Error("the transcript does not show the rule being undone")
	}
}

// The delete guard is the mirror of the add guard: for a deletion the rule has to
// be there, and the ACL has to hold the number of rules the plan was built
// against. Both halves are what stops a deletion from acting on a device that has
// moved on since the diff was read.
func TestRemoveRefusesWhenTheRuleIsGone(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(3))
	s := dial(t, d)
	err := device.Remove(context.Background(), s, 999, 3)
	if err == nil { t.Fatal("removing a rule that is not there succeeded") }
	if !strings.Contains(err.Error(), "nothing to delete") {
		t.Errorf("error does not say the rule is absent: %v", err)
	}
}

func TestRemoveRefusesWhenTheCountMoved(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(3))
	s := dial(t, d)
	err := device.Remove(context.Background(), s, 101, 7)
	if err == nil { t.Fatal("removing against a stale rule count succeeded") }
	if !strings.Contains(err.Error(), "expected 7 rules, got 3") {
		t.Errorf("error does not name both counts: %v", err)
	}
}
