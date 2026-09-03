package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/cfgpath"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/device"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/plan"
)

const agentVersion = "0.4.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "acl-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: acl-agent <snapshot|apply|rollback> [flags]")
	}
	subcmd := os.Args[1]
	switch subcmd {
	case "snapshot", "apply", "rollback":
	default:
		return fmt.Errorf("unknown subcommand %q", subcmd)
	}

	fs := flag.NewFlagSet(subcmd, flag.ContinueOnError)
	configPath := fs.String("config", cfgpath.Sibling("aclagent.json"),
		"agent config file; defaults to the one next to this binary")
	requestID  := fs.String("request", "", "change request ID")
	planSHA256 := fs.String("plan-sha256", "", "expected SHA-256 of plan file")
	streamMode := fs.Bool("stream", false, "write terminal output to stderr line by line")
	if err := fs.Parse(os.Args[2:]); err != nil { return err }

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		writeFailResponse(nil, plan.ResultPlanRejected, plan.StageConnect, err.Error())
		return err
	}

	if err := checkSecretFile(cfg.CredentialFile); err != nil {
		writeFailResponse(cfg, plan.ResultPlanRejected, plan.StageConnect,
			"credential perm check: "+err.Error())
		return err
	}

	password, err := loadPassword(cfg.CredentialFile)
	if err != nil {
		writeFailResponse(cfg, plan.ResultAuthFailed, plan.StageAuth,
			"credential load failed: "+sanitise(err.Error()))
		return err
	}
	defer zeroBytes(password)

	ctx := context.Background()
	switch subcmd {
	case "snapshot":
		var sw io.Writer
	if *streamMode { sw = os.Stderr }
	return doSnapshot(ctx, cfg, password, sw)
	case "apply":
		if *requestID == "" || *planSHA256 == "" {
			writeFailResponse(cfg, plan.ResultPlanRejected, plan.StageConnect, "--request and --plan-sha256 required")
			return fmt.Errorf("missing flags")
		}
		var sw2 io.Writer
	if *streamMode { sw2 = os.Stderr }
	return doApply(ctx, cfg, password, sw2, *requestID, *planSHA256)
	case "rollback":
		if *requestID == "" {
			writeFailResponse(cfg, plan.ResultPlanRejected, plan.StageConnect, "--request required")
			return fmt.Errorf("missing --request")
		}
		var sw3 io.Writer
	if *streamMode { sw3 = os.Stderr }
	return doRollback(ctx, cfg, password, sw3, *requestID)
	}
	return nil
}

func doSnapshot(ctx context.Context, cfg *AgentConfig, password []byte, stream io.Writer) error {
	s, err := openSession(ctx, cfg, password, stream)
	if err != nil {
		writeFailResponse(cfg, resultFromSE(err), stageFromSE(err), sanitise(err.Error()))
		return err
	}
	defer s.Close(ctx)
	raw, err := device.Snapshot(ctx, s)
	if err != nil {
		writeFailResponse(cfg, resultFromSE(err), stageFromSE(err), sanitise(err.Error()))
		return err
	}
	writeResponse(cfg, plan.Response{Result: plan.ResultOK, Raw: raw})
	return nil
}

func doApply(ctx context.Context, cfg *AgentConfig, password []byte, stream io.Writer, reqID, wantSHA string) error {
	if err := checkAndIncrementQuota(cfg); err != nil {
		writeFailResponse(cfg, plan.ResultGuardFailed, plan.StageConnect, err.Error())
		return err
	}
	p, err := loadAndVerifyPlan(cfg, reqID, wantSHA)
	if err != nil {
		writeFailResponse(cfg, plan.ResultPlanRejected, plan.StageConnect, sanitise(err.Error()))
		return err
	}
	if err := plan.ValidateForAgent(p, cfg.RangeMin, cfg.RangeMax, cfg.AllocMax); err != nil {
		writeFailResponse(cfg, plan.ResultGuardFailed, plan.StageConnect, err.Error())
		return err
	}
	if err := absoluteGuard(p); err != nil {
		writeFailResponse(cfg, plan.ResultGuardFailed, plan.StageConnect, err.Error())
		return err
	}
	s, err := openSession(ctx, cfg, password, stream)
	if err != nil {
		writeFailResponse(cfg, resultFromSE(err), stageFromSE(err), sanitise(err.Error()))
		return err
	}
	defer s.Close(ctx)
	timeout := time.Duration(cfg.ReadTimeout) * time.Second
	if err := device.Apply(ctx, s, p, timeout); err != nil {
		writeFailResponse(cfg, resultFromSE(err), stageFromSE(err), sanitise(err.Error()))
		return err
	}
	writeResponse(cfg, plan.Response{Result: plan.ResultOK, Stage: plan.StageSave, Raw: s.RawOutput()})
	return nil
}

func doRollback(ctx context.Context, cfg *AgentConfig, password []byte, stream io.Writer, reqID string) error {
	p, err := loadPlanFile(cfg, reqID)
	if err != nil {
		writeFailResponse(cfg, plan.ResultPlanRejected, plan.StageConnect, sanitise(err.Error()))
		return err
	}
	if p.RuleID < cfg.RangeMin || p.RuleID > cfg.RangeMax {
		msg := fmt.Sprintf("rollback rule_id %d outside [%d,%d]", p.RuleID, cfg.RangeMin, cfg.RangeMax)
		writeFailResponse(cfg, plan.ResultGuardFailed, plan.StageConnect, msg)
		return fmt.Errorf("%s", msg)
	}
	s, err := openSession(ctx, cfg, password, stream)
	if err != nil {
		writeFailResponse(cfg, resultFromSE(err), stageFromSE(err), sanitise(err.Error()))
		return err
	}
	defer s.Close(ctx)
	if err := device.Rollback(ctx, s, p.RuleID); err != nil {
		writeFailResponse(cfg, resultFromSE(err), stageFromSE(err), sanitise(err.Error()))
		return err
	}
	writeResponse(cfg, plan.Response{Result: plan.ResultRolledBack, Raw: s.RawOutput()})
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func openSession(ctx context.Context, cfg *AgentConfig, password []byte, stream io.Writer) (*device.Session, error) {
	tr := &device.TelnetTransport{}
	dialCfg := device.DialConfig{
		Addr:           cfg.DeviceAddr,
		ConnectTimeout: time.Duration(cfg.ConnectTimeout) * time.Second,
		ReadTimeout:    time.Duration(cfg.ReadTimeout) * time.Second,
	}
	// An empty username is passed through as empty on purpose. It used to default
	// to "admin", which turned a password-only credential file into a login
	// attempt as a user that may not exist on the device.
	username, _ := loadUsername(cfg.CredentialFile)
	auth := &device.Auth{Username: username, Password: password}
	s := device.NewSession(tr, dialCfg, auth, cfg.ACL, time.Duration(cfg.ReadTimeout)*time.Second)
	if stream != nil { s.SetStream(stream) }
	return s, s.Open(ctx)
}

// credLines splits a credential file into a username and the base64 of a
// password. Two lines mean both; a single line is the password alone, which is
// what a switch authenticating on a password with no local user account wants.
//
// The one-line form used to be read as a username-less login regardless of what
// the device asked for, so a file that was simply missing its first line failed
// as a rejected login and pointed nowhere near the mistake. It is now a declared
// mode, and the session reports it by name if the device does ask for a username.
func credLines(credFile string) (string, string, error) {
	raw, err := os.ReadFile(credFile)
	if err != nil { return "", "", err }
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for i := range lines { lines[i] = strings.TrimSpace(lines[i]) }
	switch len(lines) {
	case 1:
		if lines[0] == "" {
			return "", "", fmt.Errorf("credential file %s is empty: it needs the base64 of the "+
				"password, optionally preceded by a line holding the username", credFile)
		}
		return "", lines[0], nil
	default:
		return lines[0], lines[1], nil
	}
}

func loadPassword(credFile string) ([]byte, error) {
	_, b64, err := credLines(credFile)
	if err != nil { return nil, err }
	pw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("credential file %s: the password line is not valid base64: %w", credFile, err)
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("credential file %s: the password is empty", credFile)
	}
	return pw, nil
}

func loadUsername(credFile string) (string, error) {
	user, _, err := credLines(credFile)
	return user, err
}

func loadPlanFile(cfg *AgentConfig, reqID string) (*plan.Plan, error) {
	if err := plan.ValidateRequestID(reqID); err != nil { return nil, err }
	raw, err := os.ReadFile(filepath.Join(cfg.PlanDir, reqID+".json"))
	if err != nil { return nil, fmt.Errorf("read plan: %w", err) }
	if len(raw) > 4096 { return nil, fmt.Errorf("plan file too large") }
	var p plan.Plan
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return &p, dec.Decode(&p)
}

func loadAndVerifyPlan(cfg *AgentConfig, reqID, wantSHA string) (*plan.Plan, error) {
	if err := plan.ValidateRequestID(reqID); err != nil { return nil, err }
	path := filepath.Join(cfg.PlanDir, reqID+".json")
	f, err := os.Open(path)
	if err != nil { return nil, fmt.Errorf("open plan: %w", err) }
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil { return nil, err }
	if len(raw) >= 8192 { return nil, fmt.Errorf("plan file too large") }
	h := sha256.Sum256(raw)
	if got := fmt.Sprintf("%x", h); got != wantSHA {
		return nil, fmt.Errorf("plan SHA256 mismatch: got %s want %s", got, wantSHA)
	}
	var p plan.Plan
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return &p, dec.Decode(&p)
}

func absoluteGuard(p *plan.Plan) error {
	if strings.ToLower(p.Protocol) == "ip" {
		return fmt.Errorf("guard_failed: permit ip not allowed; use tcp/udp/icmp")
	}
	srcAny := p.Src == nil
	dstAny := p.Dst == nil || (p.Dst.IP == "0.0.0.0" && p.Dst.Wildcard == "255.255.255.255")
	if srcAny && dstAny {
		return fmt.Errorf("guard_failed: both src and dst are any; too broad")
	}
	return plan.ValidateComment(p.Comment)
}

type agentState struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

func checkAndIncrementQuota(cfg *AgentConfig) error {
	today := time.Now().Format("2006-01-02")
	var state agentState
	if raw, err := os.ReadFile(cfg.StateFile); err == nil {
		_ = json.Unmarshal(raw, &state)
	}
	if state.Date != today { state = agentState{Date: today} }
	if state.Count >= cfg.DailyLimit {
		return fmt.Errorf("daily apply limit %d reached for %s", cfg.DailyLimit, today)
	}
	state.Count++
	raw, _ := json.Marshal(state)
	return os.WriteFile(cfg.StateFile, raw, 0600)
}

func writeResponse(cfg *AgentConfig, r plan.Response) {
	fillBinding(cfg, &r)
	b, _ := plan.MarshalResponse(r)
	fmt.Println(string(b))
}

func writeFailResponse(cfg *AgentConfig, result plan.Result, stage plan.Stage, detail string) {
	r := plan.Response{Result: result, Stage: stage, Detail: detail}
	fillBinding(cfg, &r)
	b, _ := plan.MarshalResponse(r)
	fmt.Println(string(b))
}

func fillBinding(cfg *AgentConfig, r *plan.Response) {
	if cfg == nil { return }
	r.BoundACL = cfg.ACL; r.BoundRangeMin = cfg.RangeMin; r.BoundRangeMax = cfg.RangeMax
	r.BoundAllocMax = cfg.AllocMax; r.ConfigSHA256 = cfg.SHA256(); r.AgentVersion = agentVersion
}

func resultFromSE(err error) plan.Result {
	se, ok := err.(*device.SessionError)
	if !ok { return plan.ResultInconsistent }
	msg := se.Error()
	switch {
	case strings.Contains(msg, "guard_failed"):   return plan.ResultGuardFailed
	case strings.Contains(msg, "prompt_mismatch"): return plan.ResultPromptMismatch
	case strings.Contains(msg, "device error"):   return plan.ResultDeviceError
	case strings.Contains(msg, "timeout"):        return plan.ResultTimeout
	case se.Stage == "auth":                       return plan.ResultAuthFailed
	case se.Stage == "connect":                    return plan.ResultConnectFailed
	case se.Stage == "save":                       return plan.ResultSaveFailed
	default:                                       return plan.ResultInconsistent
	}
}

func stageFromSE(err error) plan.Stage {
	se, ok := err.(*device.SessionError)
	if !ok { return plan.StageConnect }
	switch se.Stage {
	case "connect": return plan.StageConnect
	case "auth":    return plan.StageAuth
	case "view":    return plan.StageView
	case "write":   return plan.StageWrite
	case "comment": return plan.StageComment
	case "save":    return plan.StageSave
	case "quit":    return plan.StageQuit
	default:        return plan.StageView
	}
}

func sanitise(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' { return -1 }
		return r
	}, s)
}

func zeroBytes(b []byte) { for i := range b { b[i] = 0 } }
