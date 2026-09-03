package aclout

import "testing"

const withRules = `Advanced IPv4 ACL 3977, named -, 3 rules,
ACL's step is 5
 rule 2000 permit tcp destination 10.20.0.1 0 destination-port eq 443
 rule 2005 permit tcp destination 10.20.0.2 0 destination-port eq 443
 rule 2010 permit tcp destination 10.20.0.3 0 destination-port eq 443
`

func TestCountFromHeader(t *testing.T) {
	n, err := Count(withRules, 3977)
	if err != nil { t.Fatalf("Count: %v", err) }
	if n != 3 { t.Errorf("count = %d, want 3", n) }
}

// TestEmptyACLIsZeroNotAnError is the case that stopped a real deployment: an ACL
// that exists and holds nothing. Whether the device prints "0 rules," or leaves
// the clause out altogether, the answer is zero — refusing to answer meant no
// rule could ever be allocated into a fresh ACL.
func TestEmptyACLIsZeroNotAnError(t *testing.T) {
	for _, raw := range []string{
		"Advanced IPv4 ACL 3977, named -, 0 rules,\nACL's step is 5\n",
		"Advanced IPv4 ACL 3977, named -, 0 rule,\nACL's step is 5\n",
		"Advanced IPv4 ACL 3977, named -,\nACL's step is 5\n",
		"Advanced IPv4 ACL 3977, named -\nACL's step is 5\n",
	} {
		n, err := Count(raw, 3977)
		if err != nil { t.Errorf("Count(%q): %v", raw, err) }
		if n != 0 { t.Errorf("Count(%q) = %d, want 0", raw, n) }
	}
}

// TestUnreadableOutputIsNotAnEmptyACL keeps the guarantee the old strict parser
// was there for. Nothing that fails to name this ACL may pass as a reading of it.
func TestUnreadableOutputIsNotAnEmptyACL(t *testing.T) {
	for _, raw := range []string{
		"",
		"\r\n\r\n",
		"% Unrecognized command found at '^' position.\r\n<SW-CORE01>",
		"display acl 3977\r\n<SW-CORE01>", // the echo alone, and nothing came back
	} {
		if n, err := Count(raw, 3977); err == nil {
			t.Errorf("Count(%q) = %d, want an error", raw, n)
		}
	}
}

// TestTruncatedOutputIsReported covers a read that stopped at a page boundary.
// The header still claims the full count, and believing it would put the highest
// rule ID out of reach — allocation is measured from exactly that.
func TestTruncatedOutputIsReported(t *testing.T) {
	truncated := "Advanced IPv4 ACL 3977, named -, 40 rules,\nACL's step is 5\n" +
		" rule 2000 permit tcp destination 10.20.0.1 0\n"
	_, err := Count(truncated, 3977)
	if err == nil { t.Fatal("a header claiming 40 rules with 1 read was accepted") }
}

// TestCommentLinesDoNotInflateTheCount pins down why IDs are counted and lines
// are not: a rule and its comment both begin "rule <N>".
func TestCommentLinesDoNotInflateTheCount(t *testing.T) {
	raw := "Advanced IPv4 ACL 3977, named -,\nACL's step is 5\n" +
		" rule 2000 permit tcp destination 10.20.0.1 0\n" +
		" rule 2000 comment ACLSYS-REQ-20260903-0001-ab12cd34\n"
	n, err := Count(raw, 3977)
	if err != nil { t.Fatalf("Count: %v", err) }
	if n != 1 { t.Errorf("count = %d, want 1", n) }
}
