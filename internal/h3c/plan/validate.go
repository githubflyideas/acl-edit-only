package plan

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var commentRe = regexp.MustCompile(`^ACLSYS-REQ-[A-Za-z0-9_-]+-[0-9a-f]{8}$`)
var reqIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
const dangerousChars = "\n\r?|;"

// ValidateForAgent validates fields that acl-agent enforces independently.
func ValidateForAgent(p *Plan, rangeMin, rangeMax, allocMax int) error {
	switch p.Op {
	case OpSnapshot, OpAdd, OpDelete, OpRollback:
	default:
		return fmt.Errorf("unknown op %q", p.Op)
	}
	if p.Op == OpSnapshot {
		return nil
	}
	if p.RuleID < rangeMin || p.RuleID > rangeMax {
		return fmt.Errorf("rule_id %d outside legal range [%d, %d]", p.RuleID, rangeMin, rangeMax)
	}
	if p.Op == OpAdd && p.RuleID > allocMax {
		return fmt.Errorf("rule_id %d exceeds alloc_max %d", p.RuleID, allocMax)
	}
	if p.Op == OpAdd {
		if p.Action != ActionPermit {
			return fmt.Errorf("action must be %q, got %q", ActionPermit, p.Action)
		}
		if err := validateRuleFields(p); err != nil {
			return err
		}
	}
	return nil
}

// ValidateComment checks the ownership-mark format. An empty comment is legal:
// writing a comment is optional, and a plan carrying none tells the agent to
// leave no extra lines in the device configuration.
func ValidateComment(s string) error {
	if s == "" {
		return nil
	}
	if !commentRe.MatchString(s) {
		return fmt.Errorf("comment %q does not match ownership-mark format", s)
	}
	return nil
}

func ValidateRequestID(id string) error {
	if !reqIDRe.MatchString(id) {
		return fmt.Errorf("request_id %q contains illegal characters", id)
	}
	return nil
}

func validateRuleFields(p *Plan) error {
	proto := strings.ToLower(p.Protocol)
	switch proto {
	case "tcp", "udp", "icmp", "ip":
	case "":
		return fmt.Errorf("protocol is required")
	default:
		return fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
	if p.Dst == nil {
		return fmt.Errorf("dst is required")
	}
	if err := validateAddrMask(p.Dst); err != nil {
		return fmt.Errorf("dst: %w", err)
	}
	if p.Src != nil {
		if err := validateAddrMask(p.Src); err != nil {
			return fmt.Errorf("src: %w", err)
		}
	}
	if p.DstPort != nil {
		if err := validatePortCond(p.DstPort); err != nil {
			return fmt.Errorf("dst_port: %w", err)
		}
	}
	if p.SrcPort != nil {
		if err := validatePortCond(p.SrcPort); err != nil {
			return fmt.Errorf("src_port: %w", err)
		}
	}
	return ValidateComment(p.Comment)
}

func validateAddrMask(am *AddrMask) error {
	if net.ParseIP(am.IP) == nil {
		return fmt.Errorf("invalid IP %q", am.IP)
	}
	if net.ParseIP(am.Wildcard) == nil {
		return fmt.Errorf("invalid wildcard %q", am.Wildcard)
	}
	if err := requireContiguousWildcard(am.Wildcard); err != nil {
		return err
	}
	if strings.ContainsAny(am.IP+am.Wildcard, dangerousChars) {
		return fmt.Errorf("field contains illegal characters")
	}
	return nil
}

func requireContiguousWildcard(wc string) error {
	ip := net.ParseIP(wc).To4()
	if ip == nil {
		return fmt.Errorf("wildcard %q is not IPv4", wc)
	}
	var v uint32
	for _, b := range ip {
		v = v<<8 | uint32(b)
	}
	mask := ^v
	if mask != 0xffffffff && (mask&(mask+1)) != 0 {
		return fmt.Errorf("wildcard %q is not a contiguous mask", wc)
	}
	return nil
}

func validatePortCond(pc *PortCond) error {
	switch pc.Op {
	case "eq", "lt", "gt", "neq":
	case "range":
		if pc.Low > pc.High {
			return fmt.Errorf("range low %d > high %d", pc.Low, pc.High)
		}
	default:
		return fmt.Errorf("unknown port operator %q", pc.Op)
	}
	return nil
}
