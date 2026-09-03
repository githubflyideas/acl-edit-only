// Package core contains the aclweb business logic:
// rule-ID allocation, artifact chain generation, approval flow,
// dispatch/verification, rollback, and reconciliation.
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/auth"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/device"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/aclout"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/plan"
)

// WebConfig is the aclweb-side configuration (does NOT contain device credentials).
type WebConfig struct {
	// Mirror of acl-agent binding – used to cross-check agent self-report.
	ACL      int
	RangeMin int
	RangeMax int
	AllocMax int

	// Path to the acl-agent binary (called via sudo).
	AgentBin string
	AgentCfg string // --config flag for acl-agent

	// Plan files directory (shared with acl-agent).
	PlanDir string

	// RuleComment turns on the ACLSYS-REQ ownership comment written beneath each
	// rule. It is off by default: the comment is a convenience for whoever reads
	// the switch configuration by hand, not something the tool depends on, and it
	// doubles the number of lines this tool adds to the device.
	RuleComment bool

	// Agent invocation timeout.
	AgentTimeout time.Duration

	// Global write mutex: only one agent subprocess at a time.
	// Enforced by the caller holding a sync.Mutex before calling Dispatch.
}

// Service holds all business logic.
type Service struct {
	db     *sql.DB
	cfg    *WebConfig
	auths  *auth.Service
}

func NewService(db *sql.DB, cfg *WebConfig, as *auth.Service) *Service {
	return &Service{db: db, cfg: cfg, auths: as}
}

// ──────────────────────────────────────────────────────────────────
// 1. Request submission
// ──────────────────────────────────────────────────────────────────

type SubmitRequest struct {
	Protocol    string
	SrcIP       string
	SrcWildcard string
	SrcPortOp   string
	SrcPortVal  int
	DstIP       string
	DstWildcard string
	DstPortOp   string
	DstPortVal  int
	Reason      string
}

// normalize fills in what the form cannot express. The source box on the new
// request page is a bare IP with no wildcard field beside it, so an empty
// wildcard means a single host; left as-is it reaches the validator as "" and
// every request naming a source is rejected.
func (r *SubmitRequest) normalize() {
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.SrcIP = strings.TrimSpace(r.SrcIP)
	r.DstIP = strings.TrimSpace(r.DstIP)
	r.SrcWildcard = strings.TrimSpace(r.SrcWildcard)
	r.DstWildcard = strings.TrimSpace(r.DstWildcard)
	if r.SrcIP != "" && r.SrcWildcard == "" {
		r.SrcWildcard = hostWildcard
	}
	if r.DstIP != "" && r.DstWildcard == "" {
		r.DstWildcard = hostWildcard
	}
}

// hostWildcard is the H3C wildcard for a single address.
const hostWildcard = "0.0.0.0"

// Submit validates, snapshots, allocates a rule ID, builds the artifact chain,
// and inserts a change_request in state "pending".
func (s *Service) Submit(ctx context.Context, actor *auth.User, req SubmitRequest) (int64, error) {
	if !canSubmit(actor.Role) {
		return 0, fmt.Errorf("role %s cannot submit requests", actor.Role)
	}
	// Action must be permit (add_rule).
	if strings.ToLower(req.Protocol) == "" {
		return 0, fmt.Errorf("protocol is required")
	}
	req.normalize()

	// Take snapshot (S1). How long it took is part of the error: a read that sat
	// waiting for a prompt it never recognised and a switch that refused the
	// connection immediately look identical otherwise, and they call for
	// completely different things to be checked.
	started := time.Now()
	snapshotRaw, err := s.runSnapshot(ctx)
	if err != nil {
		return 0, fmt.Errorf("snapshot failed after %s: %w", time.Since(started).Round(time.Second), err)
	}
	snapshotID, err := s.saveSnapshot(snapshotRaw, "pre_request")
	if err != nil {
		return 0, err
	}

	// Allocate rule ID from snapshot (max+1 in alloc window).
	ruleID, err := allocateRuleID(snapshotRaw, s.cfg.ACL, s.cfg.RangeMin, s.cfg.AllocMax)
	if err != nil { return 0, err }
	expectCount, err := aclout.Count(snapshotRaw, s.cfg.ACL)
	if err != nil { return 0, err }

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return 0, err }
	defer tx.Rollback() //nolint:errcheck

	// The request code is derived from the row's own primary key rather than
	// from COUNT(*). A count collides after any deletion and races between two
	// concurrent submits, and because the code names the plan file, a collision
	// meant one request silently overwrote another request's plan — detected
	// only later, as a SHA mismatch at dispatch time.
	placeholder := "PENDING-" + randomToken()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO change_requests(
			request_code, action, requester_id, state, reason,
			protocol, src_ip, src_wildcard, src_port_op, src_port_val,
			dst_ip, dst_wildcard, dst_port_op, dst_port_val,
			rule_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		placeholder, "add_rule", actor.ID, "pending", req.Reason,
		req.Protocol, req.SrcIP, req.SrcWildcard, req.SrcPortOp, req.SrcPortVal,
		req.DstIP, req.DstWildcard, req.DstPortOp, req.DstPortVal,
		ruleID,
	)
	if err != nil { return 0, err }
	crID, err := res.LastInsertId()
	if err != nil { return 0, err }

	code := fmt.Sprintf("REQ-%s-%04d", time.Now().Format("20060102"), crID)
	if _, err := tx.ExecContext(ctx,
		`UPDATE change_requests SET request_code=? WHERE id=?`, code, crID); err != nil {
		return 0, err
	}

	var comment string
	if s.cfg.RuleComment {
		comment = buildComment(code, req.DstIP+req.DstWildcard+req.Protocol+req.DstPortOp+strconv.Itoa(req.DstPortVal))
	}

	p := plan.Plan{
		RequestID:         code,
		Op:                plan.OpAdd,
		RuleID:            ruleID,
		Action:            plan.ActionPermit,
		Protocol:          req.Protocol,
		Dst:               &plan.AddrMask{IP: req.DstIP, Wildcard: req.DstWildcard},
		Comment:           comment,
		ExpectCountBefore: expectCount,
	}
	if req.SrcIP != "" {
		p.Src = &plan.AddrMask{IP: req.SrcIP, Wildcard: req.SrcWildcard}
	}
	if req.DstPortOp != "" {
		p.DstPort = &plan.PortCond{Op: req.DstPortOp, Value: uint16(req.DstPortVal)}
	}
	if req.SrcPortOp != "" {
		p.SrcPort = &plan.PortCond{Op: req.SrcPortOp, Value: uint16(req.SrcPortVal)}
	}
	// Reject a plan the agent would refuse, here, while there is a human to
	// tell about it — rather than at dispatch time.
	if err := plan.ValidateForAgent(&p, s.cfg.RangeMin, s.cfg.RangeMax, s.cfg.AllocMax); err != nil {
		return 0, fmt.Errorf("plan rejected: %w", err)
	}

	planJSON, err := json.Marshal(p)
	if err != nil { return 0, err }

	oldCfg := snapshotRaw
	newCfg := buildExpectedConfig(snapshotRaw, &p)
	diffText := unifiedDiff(oldCfg, newCfg)

	if err := writePlanFile(s.cfg.PlanDir, code, planJSON); err != nil {
		return 0, err
	}

	if _, err = tx.ExecContext(ctx, `
		INSERT INTO change_artifacts(
			request_id, snapshot_before_id, old_config, new_config, diff_text, plan_json,
			old_sha256, new_sha256, diff_sha256, plan_sha256)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		crID, snapshotID, oldCfg, newCfg, diffText, string(planJSON),
		sha256hex([]byte(oldCfg)), sha256hex([]byte(newCfg)),
		sha256hex([]byte(diffText)), sha256hex(planJSON),
	); err != nil {
		removePlanFile(s.cfg.PlanDir, code)
		return 0, err
	}

	s.audit(tx, actor, "change_request", crID, "submitted", map[string]interface{}{
		"request_code": code, "rule_id": ruleID, "plan_sha256": sha256hex(planJSON),
	})

	if err := tx.Commit(); err != nil {
		removePlanFile(s.cfg.PlanDir, code)
		return 0, err
	}
	return crID, nil
}

// ──────────────────────────────────────────────────────────────────
// 2. Approval
// ──────────────────────────────────────────────────────────────────

// Approve transitions a pending request to approved.
func (s *Service) Approve(ctx context.Context, actor *auth.User, crID int64, comment string) error {
	if !canApprove(actor.Role) {
		return fmt.Errorf("role %s cannot approve", actor.Role)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()

	// SQLite has no SELECT ... FOR UPDATE; the UPDATE below is guarded by
	// state='pending' instead, which is what makes a concurrent approval lose.
	var requesterID int64
	var state string
	if err := tx.QueryRowContext(ctx,
		`SELECT requester_id, state FROM change_requests WHERE id=?`, crID,
	).Scan(&requesterID, &state); err != nil {
		return fmt.Errorf("request %d not found", crID)
	}

	// Single-operator mode: the submitter may confirm their own request. The
	// safeguard is the diff they have to read, not a second person.
	res, err := tx.ExecContext(ctx,
		`UPDATE change_requests SET state='approved', approver_id=?, approved_at=?, approve_comment=?
		 WHERE id=? AND state='pending'`,
		actor.ID, time.Now().Unix(), comment, crID,
	)
	if err != nil { return err }
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("request %d is no longer pending (concurrent modification)", crID)
	}
	s.audit(tx, actor, "change_request", crID, "approved", map[string]interface{}{"comment": comment})
	return tx.Commit()
}

// Reject transitions a pending request to rejected.
func (s *Service) Reject(ctx context.Context, actor *auth.User, crID int64, comment string) error {
	if !canApprove(actor.Role) { return fmt.Errorf("role %s cannot reject", actor.Role) }
	_, err := s.db.ExecContext(ctx,
		`UPDATE change_requests SET state='rejected', approver_id=?, approved_at=?, approve_comment=?
		 WHERE id=? AND state='pending'`,
		actor.ID, time.Now().Unix(), comment, crID,
	)
	if err != nil { return err }
	s.auditDirect(actor, "change_request", crID, "rejected", map[string]interface{}{"comment": comment})
	return nil
}

// ──────────────────────────────────────────────────────────────────
// 3. Dispatch (must be called under a global write mutex)
// ──────────────────────────────────────────────────────────────────

// Dispatch executes a confirmed change request without streaming.
// It must be called while holding the application-level single-writer mutex.
func (s *Service) Dispatch(ctx context.Context, actor *auth.User, crID int64) error {
	return s.DispatchStream(ctx, actor, crID, nil)
}

func (s *Service) handleDispatchFailure(
	ctx context.Context, actor *auth.User,
	crID int64, code string, ruleID int, preRaw string,
) error {
	// Try rollback.
	rollbackResp, _ := s.runAgent(ctx, "rollback", "--request", code)
	_ = rollbackResp

	// Post-rollback snapshot.
	postRollbackRaw, _ := s.runSnapshot(ctx)
	preFP := fingerprintRaw(preRaw)
	postFP := fingerprintRaw(postRollbackRaw)

	if preFP == postFP {
		s.db.ExecContext(ctx, `UPDATE change_requests SET state='dispatch_failed' WHERE id=?`, crID)
		s.auditDirect(actor, "change_request", crID, "dispatch_failed_clean", map[string]interface{}{
			"rule_id": ruleID,
		})
		return fmt.Errorf("dispatch failed cleanly; rollback confirmed")
	}
	s.db.ExecContext(ctx, `UPDATE change_requests SET state='inconsistent' WHERE id=?`, crID)
	s.auditDirect(actor, "change_request", crID, "inconsistent", map[string]interface{}{
		"rule_id": ruleID,
	})
	return fmt.Errorf("INCONSISTENT: dispatch failed and rollback did not restore pre-state; manual intervention required")
}

// ──────────────────────────────────────────────────────────────────
// 4. Rule deletion (same approval flow)
// ──────────────────────────────────────────────────────────────────

// SubmitDelete creates a delete change request for an existing active rule.
func (s *Service) SubmitDelete(ctx context.Context, actor *auth.User, existingCRID int64, reason string) (int64, error) {
	if !canSubmit(actor.Role) { return 0, fmt.Errorf("role %s cannot submit", actor.Role) }

	var ruleID int
	var state, reqCode string
	err := s.db.QueryRowContext(ctx,
		`SELECT rule_id, state, request_code FROM change_requests WHERE id=?`, existingCRID,
	).Scan(&ruleID, &state, &reqCode)
	if err != nil { return 0, fmt.Errorf("original request not found") }
	if state != "active" { return 0, fmt.Errorf("can only delete an active rule (current state: %s)", state) }

	// Snapshot to confirm rule still exists.
	snapshotRaw, err := s.runSnapshot(ctx)
	if err != nil { return 0, err }
	if !ruleExistsInSnapshot(snapshotRaw, ruleID) {
		return 0, fmt.Errorf("rule %d not found in current device snapshot", ruleID)
	}

	expectCount, err := aclout.Count(snapshotRaw, s.cfg.ACL)
	if err != nil { return 0, err }
	snapshotID, _ := s.saveSnapshot(snapshotRaw, "pre_request")

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return 0, err }
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `
		INSERT INTO change_requests(
			request_code, action, requester_id, state, reason,
			dst_ip, dst_wildcard, rule_id)
		VALUES(?,?,?,?,?,?,?,?)`,
		"PENDING-"+randomToken(), "delete_rule", actor.ID, "pending", reason, "N/A", "N/A", ruleID,
	)
	if err != nil { return 0, err }
	newCRID, err := res.LastInsertId()
	if err != nil { return 0, err }

	code := fmt.Sprintf("REQ-%s-%04d", time.Now().Format("20060102"), newCRID)
	if _, err := tx.ExecContext(ctx,
		`UPDATE change_requests SET request_code=? WHERE id=?`, code, newCRID); err != nil {
		return 0, err
	}

	p := plan.Plan{
		RequestID:         code,
		Op:                plan.OpDelete,
		RuleID:            ruleID,
		Action:            plan.ActionPermit,
		ExpectCountBefore: expectCount,
	}
	planJSON, err := json.Marshal(p)
	if err != nil { return 0, err }
	if err := writePlanFile(s.cfg.PlanDir, code, planJSON); err != nil { return 0, err }

	oldCfg := snapshotRaw
	newCfg := removeRuleFromConfig(snapshotRaw, ruleID)
	diffText := unifiedDiff(oldCfg, newCfg)

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO change_artifacts(
			request_id, snapshot_before_id, old_config, new_config, diff_text, plan_json,
			old_sha256, new_sha256, diff_sha256, plan_sha256)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		newCRID, snapshotID, oldCfg, newCfg, diffText, string(planJSON),
		sha256hex([]byte(oldCfg)), sha256hex([]byte(newCfg)),
		sha256hex([]byte(diffText)), sha256hex(planJSON),
	); err != nil {
		removePlanFile(s.cfg.PlanDir, code)
		return 0, err
	}
	s.audit(tx, actor, "change_request", newCRID, "delete_submitted", map[string]interface{}{
		"rule_id": ruleID, "original_req": reqCode,
	})
	if err := tx.Commit(); err != nil {
		removePlanFile(s.cfg.PlanDir, code)
		return 0, err
	}
	return newCRID, nil
}

// ──────────────────────────────────────────────────────────────────
// 5. Reconciliation
// ──────────────────────────────────────────────────────────────────

// Reconcile snaps the device and compares against the DB-tracked active rules.
func (s *Service) Reconcile(ctx context.Context) error {
	raw, err := s.runSnapshot(ctx)
	if err != nil { return err }
	s.saveSnapshot(raw, "reconcile")

	// Load all active rule IDs from DB.
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, request_code FROM change_requests WHERE state='active'`)
	if err != nil { return err }
	defer rows.Close()

	var mismatches []string
	for rows.Next() {
		var rid int; var code string
		rows.Scan(&rid, &code)
		if !ruleExistsInSnapshot(raw, rid) {
			mismatches = append(mismatches, fmt.Sprintf("rule %d (req %s) missing from device", rid, code))
		}
	}
	if len(mismatches) > 0 {
		s.auditDirect(nil, "system", 0, "reconcile_mismatch", map[string]interface{}{
			"mismatches": mismatches,
		})
		return fmt.Errorf("reconcile found %d mismatch(es): %s", len(mismatches), strings.Join(mismatches, "; "))
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────

func (s *Service) runSnapshot(ctx context.Context) (string, error) {
	resp, err := s.runAgent(ctx, "snapshot")
	if err != nil { return "", err }
	if resp.Result != plan.ResultOK {
		return "", fmt.Errorf("agent reported %s", describeResponse(resp, ""))
	}
	return resp.Raw, nil
}

func (s *Service) runAgent(ctx context.Context, subcmd string, extraArgs ...string) (plan.Response, error) {
	return s.runAgentStream(ctx, nil, subcmd, extraArgs...)
}

// runAgentStream is like runAgent but streams stderr (terminal output) to w in real time.
// Pass w=nil to discard. The --stream flag is added automatically when w != nil.
func (s *Service) runAgentStream(ctx context.Context, w io.Writer, subcmd string, extraArgs ...string) (plan.Response, error) {
	tctx, cancel := context.WithTimeout(ctx, s.cfg.AgentTimeout)
	defer cancel()

	args := []string{s.cfg.AgentBin, subcmd, "--config", s.cfg.AgentCfg}
	if w != nil {
		args = append(args, "--stream")
	}
	args = append(args, extraArgs...)
	cmd := exec.CommandContext(tctx, args[0], args[1:]...)

	// The agent's stderr is kept in every case, streaming or not. It is where
	// the agent says why it gave up — a file whose mode or owner failed the
	// check, an unparsable config, a refused telnet connection — and discarding
	// it left the operator with nothing but "agent exited with error".
	tail := &tailWriter{max: 4096}
	if w != nil {
		cmd.Stderr = io.MultiWriter(w, tail)
	} else {
		cmd.Stderr = tail
	}
	out, err := cmd.Output()
	if err != nil {
		stderrText := strings.TrimSpace(tail.String())
		if len(out) > 0 {
			if resp, jerr := plan.UnmarshalResponse(out); jerr == nil {
				return resp, fmt.Errorf("agent reported %s", describeResponse(resp, stderrText))
			}
		}
		if stderrText != "" {
			return plan.Response{Result: plan.ResultInconsistent}, fmt.Errorf("%v: %s", err, stderrText)
		}
		return plan.Response{Result: plan.ResultInconsistent}, err
	}
	resp, err := plan.UnmarshalResponse(out)
	if err != nil {
		return plan.Response{Result: plan.ResultInconsistent},
			fmt.Errorf("decode agent response: %w", err)
	}
	return resp, nil
}

// describeResponse turns an agent response into the one line an operator needs:
// what it decided, where it got to, and why. The agent's own detail is
// preferred; its stderr is the fallback for the cases where it exits before
// filling the field in.
func describeResponse(r plan.Response, stderrText string) string {
	var sb strings.Builder
	sb.WriteString(string(r.Result))
	if r.Stage != "" {
		sb.WriteString(" at stage ")
		sb.WriteString(string(r.Stage))
	}
	detail := strings.TrimSpace(r.Detail)
	if detail == "" { detail = stderrText }
	if detail == "" { detail = "no detail reported" }
	sb.WriteString(": ")
	sb.WriteString(detail)
	return sb.String()
}

// tailWriter keeps the last max bytes written to it. The tail is the useful end
// of a process's stderr: whatever killed it was the last thing it said.
type tailWriter struct {
	max int
	buf []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailWriter) String() string { return string(t.buf) }

func (s *Service) saveSnapshot(raw, trigger string) (int64, error) {
	fp := fingerprintRaw(raw)
	// A snapshot is stored even when its rule count cannot be read: it is the
	// evidence of what the device said, and that is most valuable exactly when
	// what it said made no sense. -1 records that the count is unknown.
	count, err := aclout.Count(raw, s.cfg.ACL)
	if err != nil { count = -1 }
	res, err := s.db.Exec(
		`INSERT INTO acl_snapshots(acl_num, raw_text, fingerprint, rule_count, trigger) VALUES(?,?,?,?,?)`,
		s.cfg.ACL, raw, fp, count, trigger,
	)
	if err != nil { return 0, err }
	return res.LastInsertId()
}

// randomToken is used only for the placeholder request code that reserves the
// row before its real code is known.
func randomToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return fmt.Sprintf("%x", b[:])
}

func (s *Service) audit(tx *sql.Tx, actor *auth.User, entity string, entityID int64, event string, detail interface{}) {
	b, _ := json.Marshal(detail)
	actorID := sql.NullInt64{}
	actorLabel := "system"
	if actor != nil {
		actorID = sql.NullInt64{Int64: actor.ID, Valid: true}
		actorLabel = actor.Username
	}
	tx.Exec(`INSERT INTO audit_logs(actor_id, actor_label, entity_type, entity_id, event, detail)
		VALUES(?,?,?,?,?,?)`,
		actorID, actorLabel, entity, entityID, event, string(b))
}

func (s *Service) auditDirect(actor *auth.User, entity string, entityID int64, event string, detail interface{}) {
	b, _ := json.Marshal(detail)
	actorID := sql.NullInt64{}
	actorLabel := "system"
	if actor != nil {
		actorID = sql.NullInt64{Int64: actor.ID, Valid: true}
		actorLabel = actor.Username
	}
	s.db.Exec(`INSERT INTO audit_logs(actor_id, actor_label, entity_type, entity_id, event, detail)
		VALUES(?,?,?,?,?,?)`,
		actorID, actorLabel, entity, entityID, event, string(b))
}

// ─── Allocation ──────────────────────────────────────────────────

var ruleLineRe = regexp.MustCompile(`(?m)^\s*rule\s+(\d+)\s+`)

// allocateRuleID implements max+1 in the [rangeMin, allocMax] window. An empty
// ACL allocates rangeMin: the count is read only to establish that the snapshot
// is a real reading of the ACL, so that unreadable output cannot be taken for an
// ACL with nothing in it.
func allocateRuleID(snapshotRaw string, aclNum, rangeMin, allocMax int) (int, error) {
	if _, err := aclout.Count(snapshotRaw, aclNum); err != nil {
		return 0, fmt.Errorf("rule ID allocation: %w", err)
	}

	occupied := occupiedIDs(snapshotRaw, rangeMin, allocMax)

	if len(occupied) == 0 { return rangeMin, nil }

	maxID := 0
	for id := range occupied { if id > maxID { maxID = id } }

	next := maxID + 1
	if next > allocMax {
		return 0, fmt.Errorf("allocation window exhausted: max rule_id %d, alloc_max %d", maxID, allocMax)
	}
	if occupied[next] {
		return 0, fmt.Errorf("computed max+1=%d is already occupied", next)
	}
	return next, nil
}

func occupiedIDs(raw string, lo, hi int) map[int]bool {
	ids := make(map[int]bool)
	for _, m := range ruleLineRe.FindAllStringSubmatch(raw, -1) {
		id, _ := strconv.Atoi(m[1])
		if id >= lo && id <= hi { ids[id] = true }
	}
	return ids
}

// ruleCountRe matches the "N rules," clause on a single line. It is used only to
// rewrite that clause; reading a count goes through package aclout, which both
// this side and the device side share.
var ruleCountRe = regexp.MustCompile(`(?m)(\d+)[ \t]+rules?\b`)

// countClauseRe matches the same clause together with the comma that follows it,
// so removing it leaves a header that reads the same as one printed without it.
var countClauseRe = regexp.MustCompile(`(?m)\d+[ \t]+rules?\b,?`)

func ruleExistsInSnapshot(raw string, ruleID int) bool {
	prefix := fmt.Sprintf("rule %d ", ruleID)
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) { return true }
	}
	return false
}

// ─── Artifacts ───────────────────────────────────────────────────

// renderRuleLine produces the exact command the agent will send. The predicted
// config is built from this same function so the diff the operator approves
// cannot drift from the change that is actually made.
func renderRuleLine(p *plan.Plan) (string, error) {
	return device.BuildRuleCmd(p)
}

// buildExpectedConfig predicts the post-change output of "display acl N":
// the rule count in the header goes up by one and the new rule and its comment
// appear in rule-ID order.
func buildExpectedConfig(base string, p *plan.Plan) string {
	cmd, err := renderRuleLine(p)
	if err != nil {
		// A plan that cannot be rendered cannot be dispatched either; surface
		// the reason in the diff rather than showing a plausible-looking one.
		return strings.TrimRight(base, "\n") + "\n" +
			fmt.Sprintf(" !! cannot render rule %d: %v\n", p.RuleID, err)
	}
	newLines := []string{" " + cmd}
	if p.Comment != "" {
		newLines = append(newLines, fmt.Sprintf(" rule %d comment %s", p.RuleID, p.Comment))
	}
	lines := strings.Split(strings.TrimRight(base, "\n"), "\n")
	out := make([]string, 0, len(lines)+len(newLines))
	inserted := false
	for _, l := range lines {
		if !inserted {
			if id, ok := ruleIDOfLine(l); ok && id > p.RuleID {
				out = append(out, newLines...)
				inserted = true
			}
		}
		out = append(out, bumpRuleCount(l))
	}
	if !inserted {
		out = append(out, newLines...)
	}
	return strings.Join(out, "\n") + "\n"
}

// bumpRuleCount rewrites the "N rules," header to N+1. Leaving it alone would
// show a stale count as an unexplained context line in the diff.
func bumpRuleCount(line string) string {
	m := ruleCountRe.FindStringSubmatchIndex(line)
	if m == nil { return line }
	n, err := strconv.Atoi(line[m[2]:m[3]])
	if err != nil { return line }
	return line[:m[2]] + strconv.Itoa(n+1) + line[m[3]:]
}

func ruleIDOfLine(line string) (int, bool) {
	m := ruleLineRe.FindStringSubmatch(line)
	if m == nil { return 0, false }
	id, err := strconv.Atoi(m[1])
	if err != nil { return 0, false }
	return id, true
}

func removeRuleFromConfig(base string, ruleID int) string {
	prefix := fmt.Sprintf(" rule %d ", ruleID)
	var lines []string
	for _, l := range strings.Split(base, "\n") {
		if !strings.HasPrefix(l, prefix) { lines = append(lines, l) }
	}
	return strings.Join(lines, "\n")
}

// unifiedDiff produces a unified diff with three lines of context, using a
// longest-common-subsequence match. The previous implementation compared sets
// of lines, which lost duplicate lines entirely and reported reorderings as no
// change at all — unacceptable when this diff is the artifact a human approves.
func unifiedDiff(a, b string) string {
	aLines := splitKeep(a)
	bLines := splitKeep(b)
	ops := diffOps(aLines, bLines)

	var out strings.Builder
	out.WriteString("--- before\n+++ after\n")

	const context = 3
	// Mark which ops to print: every change plus `context` ops around it.
	keep := make([]bool, len(ops))
	for i, op := range ops {
		if op.kind == opEqual { continue }
		for j := i - context; j <= i+context; j++ {
			if j >= 0 && j < len(ops) { keep[j] = true }
		}
	}
	skipping := false
	for i, op := range ops {
		if !keep[i] {
			if !skipping {
				out.WriteString("@@\n")
				skipping = true
			}
			continue
		}
		skipping = false
		switch op.kind {
		case opEqual:
			fmt.Fprintf(&out, " %s\n", op.text)
		case opDelete:
			fmt.Fprintf(&out, "-%s\n", op.text)
		case opInsert:
			fmt.Fprintf(&out, "+%s\n", op.text)
		}
	}
	return out.String()
}

// splitKeep splits into lines and drops a single trailing empty element, so a
// trailing newline is not reported as a change.
func splitKeep(s string) []string {
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type diffOp struct {
	kind opKind
	text string
}

// diffOps computes an LCS-based edit script. ACL snapshots are a few hundred
// lines, so the quadratic table is cheap and the simplicity is worth more than
// the speed of a Myers implementation.
func diffOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs { lcs[i] = make([]int, m+1) }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{opEqual, a[i]}); i++; j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{opDelete, a[i]}); i++
		default:
			ops = append(ops, diffOp{opInsert, b[j]}); j++
		}
	}
	for ; i < n; i++ { ops = append(ops, diffOp{opDelete, a[i]}) }
	for ; j < m; j++ { ops = append(ops, diffOp{opInsert, b[j]}) }
	return ops
}

// verifyChange decides, from before/after snapshots alone, whether exactly the
// approved change landed on the device. It deliberately does not consult the
// agent's own report: the point is to check the device, not to check whether
// the agent agrees with itself.
func verifyChange(preRaw, postRaw string, aclNum, ruleID int) error {
	preCount, err := aclout.Count(preRaw, aclNum)
	if err != nil { return fmt.Errorf("pre-change snapshot: %w", err) }
	postCount, err := aclout.Count(postRaw, aclNum)
	if err != nil { return fmt.Errorf("post-change snapshot: %w", err) }
	// A: the rule count went up by exactly one.
	if postCount != preCount+1 {
		return fmt.Errorf("assertion A failed: pre count %d, post count %d", preCount, postCount)
	}
	// C: the new rule is present.
	if !ruleExistsInSnapshot(postRaw, ruleID) {
		return fmt.Errorf("assertion C failed: rule %d not found in post-dispatch snapshot", ruleID)
	}
	// B: nothing else moved. Strip every line belonging to the new rule from
	// the post-state and it must equal the pre-state, ignoring the header count
	// that assertion A already accounted for. Without this check a dispatch
	// that also modified an unrelated rule would be reported as success.
	if err := assertOnlyRuleChanged(preRaw, postRaw, ruleID); err != nil {
		return err
	}
	return nil
}

func assertOnlyRuleChanged(preRaw, postRaw string, ruleID int) error {
	pre := significantLines(preRaw, ruleID)
	post := significantLines(postRaw, ruleID)
	if len(pre) != len(post) {
		return fmt.Errorf("assertion B failed: %d unrelated lines before, %d after",
			len(pre), len(post))
	}
	for i := range pre {
		if pre[i] != post[i] {
			return fmt.Errorf("assertion B failed: unrelated line changed\n  before: %s\n   after: %s",
				pre[i], post[i])
		}
	}
	return nil
}

// significantLines returns the comparable content of a snapshot: trimmed,
// blank lines dropped, the header rule count neutralised, and every line
// belonging to ruleID removed.
func significantLines(raw string, ruleID int) []string {
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l == "" { continue }
		if id, ok := ruleIDOfLine(l); ok && id == ruleID { continue }
		out = append(out, neutralizeRuleCount(l))
	}
	return out
}

// neutralizeRuleCount removes the "N rules," clause so that a header carrying a
// count compares equal to one that carries none. Rewriting the number to a
// placeholder is not enough: a device that prints no clause at all for an empty
// ACL would then differ from its own output one rule later, and assertion B
// would call a correct dispatch a change to an unrelated line.
func neutralizeRuleCount(line string) string {
	if !countClauseRe.MatchString(line) { return line }
	return strings.Join(strings.Fields(countClauseRe.ReplaceAllString(line, "")), " ")
}

func fingerprintRaw(raw string) string {
	// Normalise: trim each line, sort, sha256.
	lines := strings.Split(raw, "\n")
	var cleaned []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" { cleaned = append(cleaned, l) }
	}
	sort.Strings(cleaned)
	joined := strings.Join(cleaned, "\n")
	h := sha256.Sum256([]byte(joined))
	return fmt.Sprintf("%x", h)
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}

func buildComment(code, content string) string {
	h := sha256.Sum256([]byte(content))
	fp := fmt.Sprintf("%x", h)[:8]
	return fmt.Sprintf("ACLSYS-REQ-%s-%s", code, fp)
}

// ─── Plan file I/O ───────────────────────────────────────────────

func writePlanFile(planDir, code string, data []byte) error {
	if err := os.MkdirAll(planDir, 0750); err != nil { return err }
	tmp := filepath.Join(planDir, code+".json.tmp")
	if err := os.WriteFile(tmp, data, 0440); err != nil { return err }
	return os.Rename(tmp, filepath.Join(planDir, code+".json"))
}

// removePlanFile cleans up a plan whose request never committed. A leftover
// plan file is harmless but confusing during reconciliation.
func removePlanFile(planDir, code string) {
	_ = os.Remove(filepath.Join(planDir, code+".json"))
}

func planFileSHA(planDir, code string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(planDir, code+".json"))
	if err != nil { return "", err }
	return sha256hex(raw), nil
}

func updatePlanExpectCount(planDir, code string, expectCount int) error {
	path := filepath.Join(planDir, code+".json")
	raw, err := os.ReadFile(path)
	if err != nil { return err }
	var p plan.Plan
	if err := json.Unmarshal(raw, &p); err != nil { return err }
	p.ExpectCountBefore = expectCount
	updated, err := json.Marshal(p)
	if err != nil { return err }
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, updated, 0440); err != nil { return err }
	return os.Rename(tmp, path)
}

// ─── Permission helpers ──────────────────────────────────────────

func canSubmit(role string) bool {
	return role == auth.RoleAdmin || role == auth.RoleApprover || role == auth.RoleOperator
}
func canApprove(role string) bool {
	return role == auth.RoleAdmin || role == auth.RoleApprover
}
func canDispatch(role string) bool {
	return role == auth.RoleAdmin || role == auth.RoleOperator
}

// ──────────────────────────────────────────────────────────────────
// 6. Streaming dispatch (for real-time terminal view in browser)
// ──────────────────────────────────────────────────────────────────

// DispatchStream executes a change request, streaming the device session to w
// as it happens (pass nil to discard). It must be called while holding the
// application-level single-writer mutex, so only one agent ever touches the
// switch at a time.
//
// This is the only dispatch implementation; Dispatch delegates here. Keeping
// two copies is how the drift check went missing from the streaming path.
func (s *Service) DispatchStream(ctx context.Context, actor *auth.User, crID int64, w io.Writer) error {
	if !canDispatch(actor.Role) {
		return fmt.Errorf("role %s cannot dispatch", actor.Role)
	}

	var code string
	var ruleID int
	var planSHA, state string
	// Single-operator mode: a request may be executed straight from 'pending'
	// after the operator has read the diff. The confirmation is still recorded
	// below, so the audit trail is the same either way.
	err := s.db.QueryRowContext(ctx, `
		SELECT cr.request_code, cr.rule_id, cr.state, ca.plan_sha256
		FROM change_requests cr
		JOIN change_artifacts ca ON ca.request_id = cr.id
		WHERE cr.id=? AND cr.state IN ('pending','approved')`, crID,
	).Scan(&code, &ruleID, &state, &planSHA)
	if err != nil {
		return fmt.Errorf("request %d is not awaiting execution: %w", crID, err)
	}

	preResp, err := s.runAgent(ctx, "snapshot")
	if err != nil {
		return fmt.Errorf("pre-dispatch snapshot: %w", err)
	}
	preRaw := preResp.Raw
	if err := s.assertBinding(preResp); err != nil {
		return err
	}
	preSnapshotID, _ := s.saveSnapshot(preRaw, "pre_dispatch")

	// Drift detection: the diff the operator approved described a specific
	// device state. If the ACL has changed since, the approval no longer means
	// what it said, so refuse rather than apply it to a different config.
	var approvalFingerprint string
	_ = s.db.QueryRowContext(ctx, `
		SELECT acl_snapshots.fingerprint
		FROM change_artifacts
		JOIN acl_snapshots ON acl_snapshots.id = change_artifacts.snapshot_before_id
		WHERE change_artifacts.request_id=?`, crID,
	).Scan(&approvalFingerprint)
	preFP := fingerprintRaw(preRaw)
	if approvalFingerprint != "" && preFP != approvalFingerprint {
		s.mustExec(ctx, `UPDATE change_requests SET state='drift' WHERE id=?`, crID)
		s.auditDirect(actor, "change_request", crID, "drift", map[string]interface{}{
			"approval_fp": approvalFingerprint, "current_fp": preFP,
		})
		return fmt.Errorf("drift: the ACL changed since this diff was produced; " +
			"submit the request again to review a current diff")
	}

	expectCount, err := aclout.Count(preRaw, s.cfg.ACL)
	if err != nil { return err }
	if err := updatePlanExpectCount(s.cfg.PlanDir, code, expectCount); err != nil {
		return fmt.Errorf("update plan expect_count: %w", err)
	}
	planSHA, err = planFileSHA(s.cfg.PlanDir, code)
	if err != nil {
		return err
	}

	// Claim the request. The state guard makes a concurrent second click lose
	// instead of running the agent twice.
	res, err := s.db.ExecContext(ctx, `
		UPDATE change_requests
		SET state='dispatching', dispatched_at=?,
		    approver_id=COALESCE(approver_id,?), approved_at=COALESCE(approved_at,?)
		WHERE id=? AND state IN ('pending','approved')`,
		time.Now().Unix(), actor.ID, time.Now().Unix(), crID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("request %d is already being executed", crID)
	}

	agentResp, runErr := s.runAgentStream(ctx, w, "apply",
		"--request", code, "--plan-sha256", planSHA)

	postResp, _ := s.runAgent(ctx, "snapshot")
	postRaw := postResp.Raw
	postSnapshotID, _ := s.saveSnapshot(postRaw, "post_dispatch")

	s.mustExec(ctx, `
		INSERT INTO agent_runs(
			request_id, plan_sha256, op, result, stage, detail, raw_output,
			snapshot_before, snapshot_after,
			bound_acl, bound_range_min, bound_range_max, bound_alloc_max,
			config_sha256, agent_version, finished_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		crID, planSHA, "apply",
		agentResp.Result, agentResp.Stage, agentResp.Detail, agentResp.Raw,
		preSnapshotID, postSnapshotID,
		agentResp.BoundACL, agentResp.BoundRangeMin, agentResp.BoundRangeMax, agentResp.BoundAllocMax,
		agentResp.ConfigSHA256, agentResp.AgentVersion, time.Now().Unix(),
	)

	// The binding cross-check is the one error a diff cannot catch: if the two
	// sides are bound to different ACLs, both snapshots come from the same
	// wrong ACL and the diff looks perfect.
	if err := s.assertBinding(agentResp); err != nil {
		s.mustExec(ctx, `UPDATE change_requests SET state='inconsistent' WHERE id=?`, crID)
		s.auditDirect(actor, "change_request", crID, "binding_mismatch", map[string]interface{}{
			"agent_acl": agentResp.BoundACL, "expected_acl": s.cfg.ACL,
		})
		return err
	}

	if runErr != nil || agentResp.Result != plan.ResultOK {
		return s.handleDispatchFailure(ctx, actor, crID, code, ruleID, preRaw)
	}
	if err := verifyChange(preRaw, postRaw, s.cfg.ACL, ruleID); err != nil {
		s.auditDirect(actor, "change_request", crID, "verify_failed",
			map[string]interface{}{"error": err.Error()})
		return s.handleDispatchFailure(ctx, actor, crID, code, ruleID, preRaw)
	}

	s.mustExec(ctx, `UPDATE change_requests SET state='active' WHERE id=?`, crID)
	s.auditDirect(actor, "change_request", crID, "dispatched", map[string]interface{}{
		"rule_id": ruleID, "plan_sha256": planSHA,
	})
	return nil
}

// assertBinding verifies the agent is bound to the same ACL and the same
// allocation window as aclweb. Every response carries the binding, including
// failures, and an absent binding is treated as a mismatch rather than as
// permission to continue.
func (s *Service) assertBinding(r plan.Response) error {
	if r.BoundACL != s.cfg.ACL ||
		r.BoundRangeMin != s.cfg.RangeMin ||
		r.BoundRangeMax != s.cfg.RangeMax ||
		r.BoundAllocMax != s.cfg.AllocMax {
		return fmt.Errorf("agent binding mismatch: agent reports acl=%d range=[%d,%d] alloc_max=%d, "+
			"aclweb expects acl=%d range=[%d,%d] alloc_max=%d",
			r.BoundACL, r.BoundRangeMin, r.BoundRangeMax, r.BoundAllocMax,
			s.cfg.ACL, s.cfg.RangeMin, s.cfg.RangeMax, s.cfg.AllocMax)
	}
	return nil
}

// mustExec runs a statement whose failure is worth logging but not worth
// aborting a dispatch that has already touched the device.
func (s *Service) mustExec(ctx context.Context, query string, args ...interface{}) {
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		log.Printf("aclweb: db exec failed: %v (query: %.60s)", err, query)
	}
}
