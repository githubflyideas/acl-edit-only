package core

import (
	"strings"
	"testing"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/plan"
)

const snap5 = `Advanced IPv4 ACL 3977, named -, 5 rules,
ACL's step is 5
 rule 100 permit tcp destination 10.20.0.1 0 destination-port eq 443
 rule 100 comment ACLSYS-REQ-CR-000001-aaaaaaaa
 rule 101 permit tcp destination 10.20.0.2 0 destination-port eq 443
 rule 101 comment ACLSYS-REQ-CR-000002-bbbbbbbb
 rule 102 permit ip destination 10.20.0.3 0
 rule 103 permit ip destination 10.20.0.4 0
 rule 104 permit ip destination 10.20.0.5 0
`

func TestParseRuleCountSignalsFailure(t *testing.T) {
	if got := parseRuleCount(snap5); got != 5 {
		t.Fatalf("parseRuleCount = %d, want 5", got)
	}
	// An unparseable snapshot must be distinguishable from an empty ACL,
	// otherwise the guard in allocateRuleID never fires and the plan carries
	// expect_count_before = 0 to the device.
	if got := parseRuleCount("connection reset by peer"); got >= 0 {
		t.Fatalf("parseRuleCount on garbage = %d, want negative", got)
	}
}

func TestAllocateRuleIDRejectsUnparseableSnapshot(t *testing.T) {
	if _, err := allocateRuleID("garbage output", 100, 199); err == nil {
		t.Fatal("allocation accepted an unparseable snapshot")
	}
}

func TestAllocateRuleID(t *testing.T) {
	got, err := allocateRuleID(snap5, 100, 199)
	if err != nil {
		t.Fatal(err)
	}
	if got != 105 {
		t.Fatalf("allocated %d, want 105", got)
	}
}

func TestAllocateRuleIDIgnoresRulesOutsideWindow(t *testing.T) {
	raw := snap5 + " rule 900 permit ip destination 10.30.0.1 0\n"
	got, err := allocateRuleID(raw, 100, 199)
	if err != nil {
		t.Fatal(err)
	}
	if got != 105 {
		t.Fatalf("allocated %d, want 105 (rule 900 is outside the window)", got)
	}
}

func TestAllocateRuleIDWindowExhausted(t *testing.T) {
	raw := "1 rules,\n rule 199 permit ip destination 10.0.0.1 0\n"
	if _, err := allocateRuleID(raw, 100, 199); err == nil {
		t.Fatal("expected exhaustion error")
	}
}

// TestExpectedConfigIncludesSource is the bug that made the diff lie: the
// predicted config rendered only the destination, so any request with a source
// showed the operator a diff that did not match what would be sent.
func TestExpectedConfigIncludesSource(t *testing.T) {
	p := &plan.Plan{
		RuleID: 105, Action: plan.ActionPermit, Protocol: "tcp",
		Src:     &plan.AddrMask{IP: "192.168.10.0", Wildcard: "0.0.0.255"},
		SrcPort: &plan.PortCond{Op: "gt", Value: 1024},
		Dst:     &plan.AddrMask{IP: "10.99.1.7", Wildcard: "0"},
		DstPort: &plan.PortCond{Op: "eq", Value: 8443},
		Comment: "ACLSYS-REQ-CR-000006-cccccccc",
	}
	got := buildExpectedConfig(snap5, p)
	want := " rule 105 permit tcp source 192.168.10.0 0.0.0.255 source-port gt 1024 destination 10.99.1.7 0 destination-port eq 8443"
	if !strings.Contains(got, want) {
		t.Fatalf("expected config missing source clause.\ngot:\n%s\nwant line:\n%s", got, want)
	}
}

// TestExpectedConfigMatchesTheCommandActuallySent closes the gap between the
// predicted line and the real one: if these two ever drift, the diff the
// operator approves is not the change that gets made.
func TestExpectedConfigMatchesTheCommandActuallySent(t *testing.T) {
	cases := []*plan.Plan{
		{RuleID: 105, Protocol: "ip", Dst: &plan.AddrMask{IP: "10.1.1.1", Wildcard: "0"}, Comment: "c"},
		{RuleID: 106, Protocol: "tcp",
			Src: &plan.AddrMask{IP: "10.0.0.0", Wildcard: "0.255.255.255"},
			Dst: &plan.AddrMask{IP: "10.1.1.2", Wildcard: "0"},
			DstPort: &plan.PortCond{Op: "range", Low: 8000, High: 8100}, Comment: "c"},
		{RuleID: 107, Protocol: "udp",
			Dst: &plan.AddrMask{IP: "10.1.1.3", Wildcard: "0.0.0.255"},
			DstPort: &plan.PortCond{Op: "eq", Value: 53}, Comment: "c"},
	}
	for _, p := range cases {
		p.Action = plan.ActionPermit
		cmd, err := renderRuleLine(p)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		cfg := buildExpectedConfig(snap5, p)
		if !strings.Contains(cfg, " "+cmd+"\n") {
			t.Errorf("expected config does not contain the command that will be sent\n cmd: %s\n cfg:\n%s", cmd, cfg)
		}
	}
}

func TestUnifiedDiffOnlyShowsTheAddition(t *testing.T) {
	p := &plan.Plan{
		RuleID: 105, Action: plan.ActionPermit, Protocol: "ip",
		Dst: &plan.AddrMask{IP: "10.99.1.7", Wildcard: "0"}, Comment: "ACLSYS-REQ-CR-000006-cccccccc",
	}
	newCfg := buildExpectedConfig(snap5, p)
	d := unifiedDiff(snap5, newCfg)
	var adds, dels int
	for _, l := range strings.Split(d, "\n") {
		switch {
		case strings.HasPrefix(l, "+++") || strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			adds++
		case strings.HasPrefix(l, "-"):
			dels++
		}
	}
	if dels != 1 {
		// The header line changes 5 rules -> 6 rules, so exactly one removal.
		t.Errorf("diff has %d removed lines, want 1\n%s", dels, d)
	}
	if adds != 3 {
		t.Errorf("diff has %d added lines, want 3 (header + rule + comment)\n%s", adds, d)
	}
}

// TestUnifiedDiffHandlesDuplicateLines is what the set-difference implementation
// got wrong: identical lines appearing more than once made changes vanish.
func TestUnifiedDiffHandlesDuplicateLines(t *testing.T) {
	a := "x\ndup\ndup\ny\n"
	b := "x\ndup\ny\n"
	d := unifiedDiff(a, b)
	if !strings.Contains(d, "-dup") {
		t.Errorf("removing one of two identical lines produced no removal:\n%s", d)
	}
}

func TestUnifiedDiffHandlesReordering(t *testing.T) {
	a := "a\nb\nc\n"
	b := "c\nb\na\n"
	d := unifiedDiff(a, b)
	if !strings.Contains(d, "+") || !strings.Contains(d, "-") {
		t.Errorf("reordering produced no diff at all:\n%s", d)
	}
}

func TestVerifyChangeRejectsCollateralEdits(t *testing.T) {
	pre := snap5
	// Post-state: our rule was added, but an unrelated rule was also altered.
	post := strings.Replace(snap5, "5 rules,", "6 rules,", 1)
	post = strings.Replace(post, " rule 102 permit ip destination 10.20.0.3 0",
		" rule 102 permit ip destination 10.20.99.3 0", 1)
	post += " rule 105 permit ip destination 10.99.1.7 0\n"
	if err := verifyChange(pre, post, 105); err == nil {
		t.Fatal("verifyChange accepted a post-state where another rule changed")
	}
}

func TestVerifyChangeAcceptsCleanAddition(t *testing.T) {
	pre := snap5
	post := strings.Replace(snap5, "5 rules,", "6 rules,", 1) +
		" rule 105 permit ip destination 10.99.1.7 0\n" +
		" rule 105 comment ACLSYS-REQ-CR-000006-cccccccc\n"
	if err := verifyChange(pre, post, 105); err != nil {
		t.Fatalf("verifyChange rejected a clean addition: %v", err)
	}
}

func TestFingerprintIsOrderIndependent(t *testing.T) {
	a := " rule 100 permit ip destination 10.0.0.1 0\n rule 101 permit ip destination 10.0.0.2 0\n"
	b := " rule 101 permit ip destination 10.0.0.2 0\n rule 100 permit ip destination 10.0.0.1 0\n"
	if fingerprintRaw(a) != fingerprintRaw(b) {
		t.Fatal("fingerprint depends on line order despite claiming to sort")
	}
	c := " rule 100 permit ip destination 10.0.0.9 0\n rule 101 permit ip destination 10.0.0.2 0\n"
	if fingerprintRaw(a) == fingerprintRaw(c) {
		t.Fatal("fingerprint ignored a real difference")
	}
}
