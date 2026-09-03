package device

import "testing"

// TestCRNulLineEndingsKeepTheirText pins the shape a real H3C switch sent: every
// line ended CR NUL LF. The NUL used to survive into the carriage-return replay,
// which then read the CR as an overwrite and kept only the NUL, so a snapshot of
// a populated ACL arrived as blank lines and the rule count was unreadable.
func TestCRNulLineEndingsKeepTheirText(t *testing.T) {
	raw := "display acl 3767\r\x00\n" +
		"Advanced IPv4 ACL 3767, 2 rules,\r\x00\n" +
		"test-web-acl-0903\r\x00\n" +
		"ACL's step is 5, start ID is 0\r\x00\n" +
		" rule 200 permit udp tos max-reliability\r\x00\n" +
		" rule 5000 permit ospf tos 3\r\x00\n" +
		"<ij02>"
	got := normalizeTerminal(raw)
	for _, want := range []string{
		"Advanced IPv4 ACL 3767, 2 rules,",
		"rule 200 permit udp tos max-reliability",
		"rule 5000 permit ospf tos 3",
	} {
		if !contains(got, want) { t.Fatalf("normalized output lost %q:\n%q", want, got) }
	}
	if n := HeaderCount(got, 3767); n != 2 {
		t.Fatalf("HeaderCount = %d, want 2, from:\n%q", n, got)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle { return true }
		}
		return false
	})()
}
