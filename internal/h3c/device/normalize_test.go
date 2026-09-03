package device

import (
	"strings"
	"testing"
)

// TestCRNulLineEndingsKeepTheirText pins the shape a real H3C switch sent: every
// line ended CR NUL LF. The NUL used to survive into the carriage-return replay,
// which then read the CR as an overwrite and kept only the NUL, so a snapshot of
// a populated ACL arrived as blank lines and the rule count was unreadable.
func TestCRNulLineEndingsKeepTheirText(t *testing.T) {
	for _, tc := range []struct{ name, ending string }{
		{"CR LF", "\r\n"},
		{"CR NUL LF", "\r\x00\n"},
		{"CR CR LF", "\r\r\n"},
		{"CR NUL CR LF", "\r\x00\r\n"},
		{"LF alone", "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) { realACLOutput(t, tc.ending) })
	}
}

func realACLOutput(t *testing.T, ending string) {
	raw := strings.Join([]string{
		"display acl 3767",
		"Advanced IPv4 ACL 3767, 2 rules,",
		"test-web-acl-0903",
		"ACL's step is 5, start ID is 0",
		" rule 200 permit udp tos max-reliability",
		" rule 5000 permit ospf tos 3",
	}, ending) + ending + "<SW-CORE01>"
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

func contains(hay, needle string) bool { return strings.Contains(hay, needle) }

// TestMoreMarkerIsStillErased keeps the paging marker gone. It is the one place
// a carriage return really does overwrite text, and the reason the replay above
// exists at all.
func TestMoreMarkerIsStillErased(t *testing.T) {
	raw := " rule 200 permit udp\r\n---- More ----\r              \r rule 5000 permit ospf\r\n"
	got := normalizeTerminal(raw)
	if strings.Contains(got, "More") { t.Fatalf("paging marker survived: %q", got) }
	for _, want := range []string{"rule 200 permit udp", "rule 5000 permit ospf"} {
		if !strings.Contains(got, want) { t.Fatalf("lost %q from %q", want, got) }
	}
}
