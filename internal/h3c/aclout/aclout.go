// Package aclout reads what "display acl <n>" said. It exists so that the web
// side and the device side count rules by exactly the same rules: the count the
// web side records in a plan is compared, inside the write session, against the
// count the device side reads back, and two implementations of "how many rules
// are there" that disagree would turn a correct device into a failed dispatch.
package aclout

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// countRe matches the "N rules," clause of the ACL header. The space before
// "rules" must not be allowed to span lines: \s would let "ACL's step is 5"
// followed by a line beginning " rule 2000 ..." read as five rules.
var countRe = regexp.MustCompile(`(?m)(\d+)[ \t]+rules?\b`)

// ruleLineRe matches a rule line. Comment lines start the same way, so the same
// rule ID can appear more than once and IDs, not lines, are what get counted.
var ruleLineRe = regexp.MustCompile(`(?m)^\s*rule\s+(\d+)\s+`)

// stepRe matches the "ACL's step is 5" line, which is printed for an ACL whether
// or not it holds any rules.
var stepRe = regexp.MustCompile(`(?im)^\s*ACL'?s?\s+step\s+is\s+\d+`)

// headerRe matches the ACL header line naming this ACL. The comma is what keeps
// it from matching the echo of the "display acl <n>" command itself.
func headerRe(aclNum int) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?im)^[^\n]*\bACL\s+%d\s*,`, aclNum))
}

// RuleIDs returns the distinct rule IDs the output mentions.
func RuleIDs(raw string) map[int]bool {
	ids := make(map[int]bool)
	for _, m := range ruleLineRe.FindAllStringSubmatch(raw, -1) {
		if id, err := strconv.Atoi(m[1]); err == nil { ids[id] = true }
	}
	return ids
}

// Count returns how many rules the output shows.
//
// The header's own count is used when it is there. When it is not — which is how
// some devices print an ACL that holds no rules — the rules themselves are
// counted, but only once the output has been confirmed to be a real reading of
// this ACL. That confirmation is the whole point: output that was garbled, cut
// short at the first page, or never arrived must not pass as an empty ACL.
//
// A header that claims more rules than were read is reported rather than
// believed. It means the tail of the output was lost, and the tail is where the
// highest rule ID lives — the one every allocation is measured from.
func Count(raw string, aclNum int) (int, error) {
	ids := RuleIDs(raw)
	if m := countRe.FindStringSubmatch(raw); m != nil {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			if len(ids) < n {
				return 0, fmt.Errorf("the ACL header says %d rules but only %d were read: "+
					"the output was cut short, so the highest rule ID is unknown", n, len(ids))
			}
			return n, nil
		}
	}
	if headerRe(aclNum).MatchString(raw) || stepRe.MatchString(raw) {
		return len(ids), nil
	}
	return 0, fmt.Errorf("no readable ACL %d output: neither a rule count nor an ACL header "+
		"was found in %s", aclNum, describe(raw))
}

// describe renders the output for an error message: its size, and its tail,
// which is where a session that went wrong shows what it was doing instead.
func describe(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" { return "empty device output" }
	const keep = 200
	if len(trimmed) > keep {
		return fmt.Sprintf("%d bytes of device output ending in %q", len(trimmed), trimmed[len(trimmed)-keep:])
	}
	return fmt.Sprintf("%d bytes of device output: %q", len(trimmed), trimmed)
}
