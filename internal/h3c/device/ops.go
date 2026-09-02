package device

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/plan"
)

var ruleCountRe = regexp.MustCompile(`(\d+)\s+rules?`)

// Snapshot reads the whole ACL. Turning paging off is only an optimisation:
// some models and privilege levels reject "screen-length disable", and a
// device we cannot read is worse than one we have to page through, so the
// error is deliberately ignored and DisplayACL drives paging either way.
func Snapshot(ctx context.Context, s *Session) (string, error) {
	_ = s.TryExec(ctx, "screen-length disable", promptUserView, promptSysView)
	return s.DisplayACL(ctx)
}

func HeaderCount(displayOut string) int {
	m := ruleCountRe.FindStringSubmatch(displayOut)
	if m == nil { return -1 }
	n, _ := strconv.Atoi(m[1])
	return n
}

func GuardCheck(ctx context.Context, s *Session, ruleID, expectCount int) error {
	out, err := s.DisplayACL(ctx)
	if err != nil { return &SessionError{Stage: "view", Cause: fmt.Errorf("guard display: %w", err)} }
	prefix := fmt.Sprintf("rule %d ", ruleID)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return &SessionError{Stage: "view",
				Cause: fmt.Errorf("guard_failed: rule %d already exists", ruleID)}
		}
	}
	count := HeaderCount(out)
	if count < 0 {
		return &SessionError{Stage: "view", Cause: fmt.Errorf("guard_failed: cannot parse rule count")}
	}
	if count != expectCount {
		return &SessionError{Stage: "view",
			Cause: fmt.Errorf("guard_failed: expected %d rules, got %d", expectCount, count)}
	}
	return nil
}

func Apply(ctx context.Context, s *Session, p *plan.Plan, _ time.Duration) error {
	ruleCmd, err := BuildRuleCmd(p)
	if err != nil { return &SessionError{Stage: "write", Cause: err} }
	commentCmd, err := BuildCommentCmd(p.RuleID, p.Comment)
	if err != nil { return &SessionError{Stage: "comment", Cause: err} }

	if err := s.EnterSystemView(ctx); err != nil { return err }
	if err := s.EnterACLView(ctx); err != nil { return err }
	if err := GuardCheck(ctx, s, p.RuleID, p.ExpectCountBefore); err != nil { return err }

	if err := s.ExecRule(ctx, ruleCmd); err != nil {
		return &SessionError{Stage: "write", Cause: err}
	}
	if err := s.ExecComment(ctx, commentCmd); err != nil {
		undoErr := s.ExecUndoRule(ctx, BuildUndoRuleCmd(p.RuleID))
		if undoErr != nil {
			return &SessionError{Stage: "comment",
				Cause: fmt.Errorf("comment failed + undo failed: %v / %v", err, undoErr)}
		}
		return &SessionError{Stage: "comment", Cause: fmt.Errorf("comment failed, rule undone: %w", err)}
	}
	if err := s.QuitACLView(ctx); err != nil { return err }
	if err := s.QuitSysView(ctx); err != nil { return err }
	return s.Save(ctx)
}

func Remove(ctx context.Context, s *Session, ruleID int) error {
	if err := s.EnterSystemView(ctx); err != nil { return err }
	if err := s.EnterACLView(ctx); err != nil { return err }
	if err := s.ExecUndoRule(ctx, BuildUndoRuleCmd(ruleID)); err != nil {
		return &SessionError{Stage: "write", Cause: err}
	}
	if err := s.QuitACLView(ctx); err != nil { return err }
	if err := s.QuitSysView(ctx); err != nil { return err }
	return s.Save(ctx)
}

func Rollback(ctx context.Context, s *Session, ruleID int) error {
	if err := s.EnterSystemView(ctx); err != nil { return err }
	if err := s.EnterACLView(ctx); err != nil { return err }
	if err := s.ExecUndoRule(ctx, BuildUndoRuleCmd(ruleID)); err != nil {
		return &SessionError{Stage: "write", Cause: err}
	}
	if err := s.QuitACLView(ctx); err != nil { return err }
	_ = s.QuitSysView(ctx)
	return nil
}
