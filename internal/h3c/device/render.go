package device

import (
	"fmt"
	"strings"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/plan"
)

const dangerousBytes = "\n\r?|;"

// BuildRuleCmd returns "rule <id> permit ...". Cannot produce deny.
func BuildRuleCmd(p *plan.Plan) (string, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "rule %d permit %s", p.RuleID, strings.ToLower(p.Protocol))
	if p.Src != nil {
		src, err := fmtAddr(p.Src)
		if err != nil { return "", fmt.Errorf("src: %w", err) }
		fmt.Fprintf(&sb, " source %s", src)
		if p.SrcPort != nil {
			sp, err := fmtPort("source-port", p.SrcPort)
			if err != nil { return "", fmt.Errorf("src_port: %w", err) }
			sb.WriteString(sp)
		}
	}
	dst, err := fmtAddr(p.Dst)
	if err != nil { return "", fmt.Errorf("dst: %w", err) }
	fmt.Fprintf(&sb, " destination %s", dst)
	if p.DstPort != nil {
		dp, err := fmtPort("destination-port", p.DstPort)
		if err != nil { return "", fmt.Errorf("dst_port: %w", err) }
		sb.WriteString(dp)
	}
	cmd := sb.String()
	if err := rejectInjection(cmd); err != nil { return "", err }
	return cmd, nil
}

func BuildCommentCmd(ruleID int, comment string) (string, error) {
	if err := rejectInjection(comment); err != nil { return "", fmt.Errorf("comment: %w", err) }
	if len(comment) < 1 || len(comment) > 127 {
		return "", fmt.Errorf("comment length %d out of [1,127]", len(comment))
	}
	return fmt.Sprintf("rule %d comment %s", ruleID, comment), nil
}

func BuildUndoRuleCmd(ruleID int) string { return fmt.Sprintf("undo rule %d", ruleID) }

func rejectInjection(s string) error {
	if strings.ContainsAny(s, dangerousBytes) {
		return fmt.Errorf("command contains illegal characters")
	}
	return nil
}

func fmtAddr(am *plan.AddrMask) (string, error) {
	if err := rejectInjection(am.IP + am.Wildcard); err != nil { return "", err }
	wc := am.Wildcard
	if wc == "0" || wc == "0.0.0.0" { return am.IP + " 0", nil }
	return am.IP + " " + wc, nil
}

func fmtPort(keyword string, pc *plan.PortCond) (string, error) {
	switch pc.Op {
	case "eq", "lt", "gt", "neq":
		return fmt.Sprintf(" %s %s %d", keyword, pc.Op, pc.Value), nil
	case "range":
		return fmt.Sprintf(" %s range %d %d", keyword, pc.Low, pc.High), nil
	default:
		return "", fmt.Errorf("unknown port op %q", pc.Op)
	}
}
