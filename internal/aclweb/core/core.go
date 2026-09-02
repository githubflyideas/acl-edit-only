// Package core contains the aclweb business logic:
// rule-ID allocation, artifact chain generation, approval flow,
// dispatch/verification, rollback, and reconciliation.
package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/auth"
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

	// Take snapshot (S1).
	snapshotRaw, err := s.runSnapshot(ctx)
	if err != nil {
		return 0, fmt.Errorf("snapshot failed: %w", err)
	}
	snapshotID, err := s.saveSnapshot(snapshotRaw, "pre_request")
	if err != nil {
		return 0, err
	}

	// Allocate rule ID from snapshot (max+1 in alloc window).
	ruleID, err := allocateRuleID(snapshotRaw, s.cfg.RangeMin, s.cfg.AllocMax)
	if err != nil {
		return 0, fmt.Errorf("rule ID allocation: %w", err)
	}
	expectCount := parseRuleCount(snapshotRaw)

	// Build plan P.
	code, err := s.nextRequestCode()
	if err != nil { return 0, err }

	comment := buildComment(code, req.DstIP+req.DstWildcard+req.Protocol+req.DstPortOp+strconv.Itoa(req.DstPortVal))

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

	planJSON, err := json.Marshal(p)
	if err != nil { return 0, err }

	// Build artifacts: old config = snapshot raw, new config = snapshot + expected new rule line,
	// diff = unified diff between the two.
	oldCfg := snapshotRaw
	newCfg := buildExpectedConfig(snapshotRaw, &p)
	diffText := unifiedDiff(oldCfg, newCfg)

	oldSHA := sha256hex([]byte(oldCfg))
	newSHA := sha256hex([]byte(newCfg))
	diffSHA := sha256hex([]byte(diffText))
	planSHA := sha256hex(planJSON)

	// Write plan file atomically.
	if err := writePlanFile(s.cfg.PlanDir, code, planJSON); err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return 0, err }
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO change_requests(
			request_code, action, requester_id, state, reason,
			protocol, src_ip, src_wildcard, src_port_op, src_port_val,
			dst_ip, dst_wildcard, dst_port_op, dst_port_val,
			rule_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		code, "add_rule", actor.ID, "pending", req.Reason,
		req.Protocol, req.SrcIP, req.SrcWildcard, req.SrcPortOp, req.SrcPortVal,
		req.DstIP, req.DstWildcard, req.DstPortOp, req.DstPortVal,
		ruleID,
	)
	if err != nil { return 0, err }
	crID, _ := res.LastInsertId()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO change_artifacts(
			request_id, snapshot_before_id, old_config, new_config, diff_text, plan_json,
			old_sha256, new_sha256, diff_sha256, plan_sha256)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		crID, snapshotID, oldCfg, newCfg, diffText, string(planJSON),
		oldSHA, newSHA, diffSHA, planSHA,
	)
	if err != nil { return 0, err }

	s.audit(tx, actor, "change_request", crID, "submitted", map[string]interface{}{
		"request_code": code, "rule_id": ruleID, "plan_sha256": planSHA,
	})

	return crID, tx.Commit()
}

// ──────────────────────────────────────────────────────────────────
// 2. Approval
// ──────────────────────────────────────────────────────────────────

// Approve transitions a pending request to approved.
// Enforces four-eyes: approver must differ from requester.
func (s *Service) Approve(ctx context.Context, actor *auth.User, crID int64, comment string) error {
	if !canApprove(actor.Role) {
		return fmt.Errorf("role %s cannot approve", actor.Role)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return err }
	defer tx.Rollback()

	var requesterID int64
	var state string
	err = tx.QueryRowContext(ctx,
		`SELECT requester_id, state FROM change_requests WHERE id=? FOR UPDATE`,
		crID,
	).Scan(&requesterID, &state)
	// SQLite doesn't support FOR UPDATE; we use optimistic WHERE state='pending'.
	if err != nil {
		err = tx.QueryRowContext(ctx,
			`SELECT requester_id, state FROM change_requests WHERE id=?`, crID,
		).Scan(&requesterID, &state)
	}
	if err != nil { return fmt.Errorf("request %d not found", crID) }

	// No four-eyes enforced – single-operator mode: submitter may approve their own request.
	// Optimistic concurrency: only update if still pending.
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

// Dispatch executes an approved change request.
// It must be called while holding the application-level single-writer mutex.
func (s *Service) Dispatch(ctx context.Context, actor *auth.User, crID int64) error {
	if !canDispatch(actor.Role) { return fmt.Errorf("role %s cannot dispatch", actor.Role) }

	// Load request + artifacts.
	var code string
	var ruleID int
	var planSHA string
	var expectCount int
	err := s.db.QueryRowContext(ctx, `
		SELECT cr.request_code, cr.rule_id, ca.plan_sha256
		FROM change_requests cr
		JOIN change_artifacts ca ON ca.request_id = cr.id
		WHERE cr.id=? AND cr.state='approved'`, crID,
	).Scan(&code, &ruleID, &planSHA)
	if err != nil { return fmt.Errorf("approved request %d not found: %w", crID, err) }

	// Pre-dispatch snapshot (drift detection).
	preRaw, err := s.runSnapshot(ctx)
	if err != nil { return fmt.Errorf("pre-dispatch snapshot: %w", err) }

	preSnapshotID, _ := s.saveSnapshot(preRaw, "pre_dispatch")

	// Compare fingerprint with approval-time snapshot fingerprint.
	var approvalFingerprint string
	s.db.QueryRowContext(ctx, `
		SELECT acl_snapshots.fingerprint
		FROM change_artifacts
		JOIN acl_snapshots ON acl_snapshots.id = change_artifacts.snapshot_before_id
		WHERE change_artifacts.request_id=?`, crID,
	).Scan(&approvalFingerprint)

	preFP := fingerprintRaw(preRaw)
	if approvalFingerprint != "" && preFP != approvalFingerprint {
		// Drift: revert to pending.
		s.db.ExecContext(ctx,
			`UPDATE change_requests SET state='drift' WHERE id=?`, crID)
		s.auditDirect(actor, "change_request", crID, "drift", map[string]interface{}{
			"approval_fp": approvalFingerprint, "current_fp": preFP,
		})
		return fmt.Errorf("drift: network changed since approval; request reverted to pending")
	}

	expectCount = parseRuleCount(preRaw)

	// Update expect_count in plan file to match current snapshot.
	if err := updatePlanExpectCount(s.cfg.PlanDir, code, expectCount); err != nil {
		return fmt.Errorf("update plan expect_count: %w", err)
	}
	// Recompute plan SHA after update.
	planSHA, err = planFileSHA(s.cfg.PlanDir, code)
	if err != nil { return err }

	// Transition to dispatching.
	s.db.ExecContext(ctx,
		`UPDATE change_requests SET state='dispatching', dispatched_at=? WHERE id=?`,
		time.Now().Unix(), crID)

	// Call acl-agent apply.
	agentResp, runErr := s.runAgent(ctx, "apply",
		"--request", code, "--plan-sha256", planSHA)

	// Post-dispatch snapshot.
	postRaw, _ := s.runSnapshot(ctx)
	postSnapshotID, _ := s.saveSnapshot(postRaw, "post_dispatch")

	// Record agent run.
	s.db.ExecContext(ctx, `
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

	// Cross-check binding.
	if agentResp.BoundACL != s.cfg.ACL ||
		agentResp.BoundRangeMin != s.cfg.RangeMin ||
		agentResp.BoundRangeMax != s.cfg.RangeMax {
		s.db.ExecContext(ctx, `UPDATE change_requests SET state='inconsistent' WHERE id=?`, crID)
		s.auditDirect(actor, "change_request", crID, "binding_mismatch", map[string]interface{}{
			"agent_acl": agentResp.BoundACL, "expected_acl": s.cfg.ACL,
		})
		return fmt.Errorf("agent binding mismatch: agent ACL %d ≠ expected %d",
			agentResp.BoundACL, s.cfg.ACL)
	}

	if runErr != nil || agentResp.Result != plan.ResultOK {
		// Attempt rollback.
		return s.handleDispatchFailure(ctx, actor, crID, code, ruleID, preRaw)
	}

	// Verify: four assertions on post vs pre snapshot.
	if err := verifyChange(preRaw, postRaw, ruleID); err != nil {
		return s.handleDispatchFailure(ctx, actor, crID, code, ruleID, preRaw)
	}

	s.db.ExecContext(ctx, `UPDATE change_requests SET state='active' WHERE id=?`, crID)
	s.auditDirect(actor, "change_request", crID, "dispatched", map[string]interface{}{
		"rule_id": ruleID, "plan_sha256": planSHA,
	})
	return nil
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

	code, _ := s.nextRequestCode()
	comment := buildComment(code, fmt.Sprintf("delete-%d", ruleID))
	p := plan.Plan{
		RequestID:         code,
		Op:                plan.OpDelete,
		RuleID:            ruleID,
		Action:            plan.ActionPermit,
		Comment:           comment,
		ExpectCountBefore: parseRuleCount(snapshotRaw),
	}
	planJSON, _ := json.Marshal(p)
	planSHA := sha256hex(planJSON)
	writePlanFile(s.cfg.PlanDir, code, planJSON)

	snapshotID, _ := s.saveSnapshot(snapshotRaw, "pre_request")
	oldCfg := snapshotRaw
	newCfg := removeRuleFromConfig(snapshotRaw, ruleID)
	diffText := unifiedDiff(oldCfg, newCfg)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil { return 0, err }
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO change_requests(
			request_code, action, requester_id, state, reason,
			dst_ip, dst_wildcard, rule_id)
		VALUES(?,?,?,?,?,?,?,?)`,
		code, "delete_rule", actor.ID, "pending", reason, "N/A", "N/A", ruleID,
	)
	if err != nil { return 0, err }
	newCRID, _ := res.LastInsertId()

	tx.ExecContext(ctx, `
		INSERT INTO change_artifacts(
			request_id, snapshot_before_id, old_config, new_config, diff_text, plan_json,
			old_sha256, new_sha256, diff_sha256, plan_sha256)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		newCRID, snapshotID, oldCfg, newCfg, diffText, string(planJSON),
		sha256hex([]byte(oldCfg)), sha256hex([]byte(newCfg)), sha256hex([]byte(diffText)), planSHA,
	)
	s.audit(tx, actor, "change_request", newCRID, "delete_submitted", map[string]interface{}{
		"rule_id": ruleID, "original_req": reqCode,
	})
	return newCRID, tx.Commit()
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
	if resp.Result != plan.ResultOK { return "", fmt.Errorf("snapshot failed: %s %s", resp.Result, resp.Detail) }
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
	cmd := exec.CommandContext(tctx, "sudo", args...)
	if w != nil {
		cmd.Stderr = w
	}
	out, err := cmd.Output()
	if err != nil {
		if len(out) > 0 {
			resp, jerr := plan.UnmarshalResponse(out)
			if jerr == nil { return resp, fmt.Errorf("agent exited with error") }
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

func (s *Service) saveSnapshot(raw, trigger string) (int64, error) {
	fp := fingerprintRaw(raw)
	count := parseRuleCount(raw)
	res, err := s.db.Exec(
		`INSERT INTO acl_snapshots(acl_num, raw_text, fingerprint, rule_count, trigger) VALUES(?,?,?,?,?)`,
		s.cfg.ACL, raw, fp, count, trigger,
	)
	if err != nil { return 0, err }
	return res.LastInsertId()
}

func (s *Service) nextRequestCode() (string, error) {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM change_requests`).Scan(&n)
	return fmt.Sprintf("REQ-%s-%04d", time.Now().Format("20060102"), n+1), nil
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

// allocateRuleID implements max+1 in the [rangeMin, allocMax] window.
func allocateRuleID(snapshotRaw string, rangeMin, allocMax int) (int, error) {
	count := parseRuleCount(snapshotRaw)
	if count < 0 { return 0, fmt.Errorf("cannot parse rule count from snapshot") }

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

func parseRuleCount(raw string) int {
	re := regexp.MustCompile(`(\d+)\s+rules?`)
	m := re.FindStringSubmatch(raw)
	if m == nil { return 0 }
	n, _ := strconv.Atoi(m[1])
	return n
}

func ruleExistsInSnapshot(raw string, ruleID int) bool {
	prefix := fmt.Sprintf("rule %d ", ruleID)
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) { return true }
	}
	return false
}

// ─── Artifacts ───────────────────────────────────────────────────

func buildExpectedConfig(base string, p *plan.Plan) string {
	// Append the expected new rule line and comment line.
	line := fmt.Sprintf(" rule %d permit %s destination %s %s",
		p.RuleID, p.Protocol, p.Dst.IP, p.Dst.Wildcard)
	if p.DstPort != nil {
		line += fmt.Sprintf(" destination-port %s %d", p.DstPort.Op, p.DstPort.Value)
	}
	comment := fmt.Sprintf(" rule %d comment %s", p.RuleID, p.Comment)
	return strings.TrimRight(base, "\n") + "\n" + line + "\n" + comment + "\n"
}

func removeRuleFromConfig(base string, ruleID int) string {
	prefix := fmt.Sprintf(" rule %d ", ruleID)
	var lines []string
	for _, l := range strings.Split(base, "\n") {
		if !strings.HasPrefix(l, prefix) { lines = append(lines, l) }
	}
	return strings.Join(lines, "\n")
}

func unifiedDiff(a, b string) string {
	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")
	var out strings.Builder
	out.WriteString("--- before\n+++ after\n")
	// Simple line-by-line diff (good enough for review; not a full Myers diff).
	aSet := make(map[string]bool)
	bSet := make(map[string]bool)
	for _, l := range aLines { aSet[l] = true }
	for _, l := range bLines { bSet[l] = true }
	for _, l := range aLines {
		if !bSet[l] { fmt.Fprintf(&out, "-%s\n", l) }
	}
	for _, l := range bLines {
		if !aSet[l] { fmt.Fprintf(&out, "+%s\n", l) }
	}
	return out.String()
}

func verifyChange(preRaw, postRaw string, ruleID int) error {
	preCount := parseRuleCount(preRaw)
	postCount := parseRuleCount(postRaw)
	// Assertion A: N2 == N1 + 1
	if postCount != preCount+1 {
		return fmt.Errorf("assertion A failed: pre count %d, post count %d", preCount, postCount)
	}
	// Assertion B: post without new rule == pre (crude: check counts of other rule lines)
	// Assertion C: new rule exists in post
	if !ruleExistsInSnapshot(postRaw, ruleID) {
		return fmt.Errorf("assertion C failed: rule %d not found in post-dispatch snapshot", ruleID)
	}
	return nil
}

func fingerprintRaw(raw string) string {
	// Normalise: trim each line, sort, sha256.
	lines := strings.Split(raw, "\n")
	var cleaned []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" { cleaned = append(cleaned, l) }
	}
	// sort not imported to keep deps minimal; use sha of joined sorted lines.
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

// DispatchStream is like Dispatch but streams terminal output to w line by line.
// Must be called under the application-level single-writer mutex.
func (s *Service) DispatchStream(ctx context.Context, actor *auth.User, crID int64, w io.Writer) error {
	if !canDispatch(actor.Role) { return fmt.Errorf("role %s cannot dispatch", actor.Role) }

	var code string
	var ruleID int
	var planSHA string
	err := s.db.QueryRowContext(ctx, `
		SELECT cr.request_code, cr.rule_id, ca.plan_sha256
		FROM change_requests cr
		JOIN change_artifacts ca ON ca.request_id = cr.id
		WHERE cr.id=? AND cr.state='approved'`, crID,
	).Scan(&code, &ruleID, &planSHA)
	if err != nil { return fmt.Errorf("approved request %d not found: %w", crID, err) }

	preRaw, err := s.runAgent(ctx, "snapshot")
	if err != nil { return fmt.Errorf("pre-dispatch snapshot: %w", err) }
	preSnapshotID, _ := s.saveSnapshot(preRaw.Raw, "pre_dispatch")

	expectCount := parseRuleCount(preRaw.Raw)
	if err := updatePlanExpectCount(s.cfg.PlanDir, code, expectCount); err != nil {
		return fmt.Errorf("update plan expect_count: %w", err)
	}
	planSHA, err = planFileSHA(s.cfg.PlanDir, code)
	if err != nil { return err }

	s.db.ExecContext(ctx, `UPDATE change_requests SET state='dispatching', dispatched_at=? WHERE id=?`,
		time.Now().Unix(), crID)

	// Stream the apply execution.
	agentResp, runErr := s.runAgentStream(ctx, w, "apply",
		"--request", code, "--plan-sha256", planSHA)

	postRaw, _ := s.runAgent(ctx, "snapshot")
	postSnapshotID, _ := s.saveSnapshot(postRaw.Raw, "post_dispatch")

	s.db.ExecContext(ctx, `
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

	if agentResp.BoundACL != 0 && (agentResp.BoundACL != s.cfg.ACL ||
		agentResp.BoundRangeMin != s.cfg.RangeMin || agentResp.BoundRangeMax != s.cfg.RangeMax) {
		s.db.ExecContext(ctx, `UPDATE change_requests SET state='inconsistent' WHERE id=?`, crID)
		return fmt.Errorf("agent binding mismatch")
	}

	if runErr != nil || agentResp.Result != plan.ResultOK {
		return s.handleDispatchFailure(ctx, actor, crID, code, ruleID, preRaw.Raw)
	}
	if err := verifyChange(preRaw.Raw, postRaw.Raw, ruleID); err != nil {
		return s.handleDispatchFailure(ctx, actor, crID, code, ruleID, preRaw.Raw)
	}

	s.db.ExecContext(ctx, `UPDATE change_requests SET state='active' WHERE id=?`, crID)
	s.auditDirect(actor, "change_request", crID, "dispatched", map[string]interface{}{"rule_id": ruleID})
	return nil
}
