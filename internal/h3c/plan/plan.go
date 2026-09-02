// Package plan defines the cross-process contract between aclweb and acl-agent.
// The plan file contains typed fields only – no "command", no "acl_num", no "range".
// acl-agent decodes the file, recomputes its SHA-256, and rejects any mismatch.
package plan

import "encoding/json"

type Op string
const (
	OpSnapshot Op = "snapshot"
	OpAdd      Op = "add"
	OpDelete   Op = "delete"
	OpRollback Op = "rollback"
)

type Action string
const ActionPermit Action = "permit"

type AddrMask struct {
	IP       string `json:"ip"`
	Wildcard string `json:"wildcard"`
}

type PortCond struct {
	Op    string `json:"op"`
	Value uint16 `json:"value,omitempty"`
	Low   uint16 `json:"low,omitempty"`
	High  uint16 `json:"high,omitempty"`
}

// Plan is written by aclweb and read by acl-agent.
// NO ACL number and NO command text live here.
type Plan struct {
	RequestID         string    `json:"request_id"`
	Op                Op        `json:"op"`
	RuleID            int       `json:"rule_id"`
	Action            Action    `json:"action"`
	Protocol          string    `json:"protocol,omitempty"`
	Src               *AddrMask `json:"src,omitempty"`
	Dst               *AddrMask `json:"dst,omitempty"`
	SrcPort           *PortCond `json:"src_port,omitempty"`
	DstPort           *PortCond `json:"dst_port,omitempty"`
	Comment           string    `json:"comment"`
	ExpectCountBefore int       `json:"expect_count_before"`
}

type Stage string
const (
	StageConnect Stage = "connect"
	StageAuth    Stage = "auth"
	StageView    Stage = "view"
	StageWrite   Stage = "write"
	StageComment Stage = "comment"
	StageSave    Stage = "save"
	StageQuit    Stage = "quit"
)

type Result string
const (
	ResultOK             Result = "ok"
	ResultPlanRejected   Result = "plan_rejected"
	ResultGuardFailed    Result = "guard_failed"
	ResultConnectFailed  Result = "connect_failed"
	ResultAuthFailed     Result = "auth_failed"
	ResultTimeout        Result = "timeout"
	ResultPromptMismatch Result = "prompt_mismatch"
	ResultDeviceError    Result = "device_error"
	ResultRolledBack     Result = "rolled_back"
	ResultSaveFailed     Result = "save_failed"
	ResultInconsistent   Result = "inconsistent"
)

// Response is written by acl-agent to stdout (JSON).
// Self-reported binding fields are present in every response including failures.
type Response struct {
	Result Result `json:"result"`
	Stage  Stage  `json:"stage,omitempty"`
	Detail string `json:"detail,omitempty"`
	Raw    string `json:"raw,omitempty"`

	BoundACL      int    `json:"bound_acl"`
	BoundRangeMin int    `json:"bound_range_min"`
	BoundRangeMax int    `json:"bound_range_max"`
	BoundAllocMax int    `json:"bound_alloc_max"`
	ConfigSHA256  string `json:"config_sha256"`
	AgentVersion  string `json:"agent_version"`
}

func MarshalResponse(r Response) ([]byte, error) { return json.Marshal(r) }
func UnmarshalResponse(b []byte) (Response, error) {
	var r Response
	return r, json.Unmarshal(b, &r)
}
