package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMinimalConfigNeedsNoPaths mirrors the agent's promise on the web side: the
// database, the plan directory, the agent binary and the agent config are all
// found relative to this config, and the plan directory is created rather than
// demanded.
func TestMinimalConfigNeedsNoPaths(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"aclagent", "aclagent.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0700); err != nil { t.Fatal(err) }
	}
	cfgPath := filepath.Join(dir, "aclweb.json")
	body := `{"acl":3977,"range_min":2000,"range_max":4999,"agent_bin":"aclagent"}`
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil { t.Fatal(err) }

	cfg, err := loadConfig(cfgPath)
	if err != nil { t.Fatalf("loadConfig: %v", err) }

	if want := filepath.Join(dir, "aclweb.db"); cfg.DBPath != want {
		t.Errorf("db_path = %q, want %q", cfg.DBPath, want)
	}
	if want := filepath.Join(dir, "plans"); cfg.PlanDir != want {
		t.Errorf("plan_dir = %q, want %q", cfg.PlanDir, want)
	}
	if want := filepath.Join(dir, "aclagent.json"); cfg.AgentCfg != want {
		t.Errorf("agent_cfg = %q, want %q", cfg.AgentCfg, want)
	}
	if cfg.AllocMax != 4999 {
		t.Errorf("alloc_max = %d, want it to default to range_max", cfg.AllocMax)
	}
	if st, err := os.Stat(cfg.PlanDir); err != nil || !st.IsDir() {
		t.Errorf("plan dir was not created: %v", err)
	}
}

// TestMissingAgentIsReportedAtStartup: a wrong agent path used to surface much
// later, as a failed dispatch.
func TestMissingAgentIsReportedAtStartup(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aclweb.json")
	body := `{"acl":3977,"range_min":2000,"range_max":4999,"agent_bin":"nope"}`
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil { t.Fatal(err) }
	if _, err := loadConfig(cfgPath); err == nil {
		t.Fatal("expected an error naming the missing agent binary")
	}
}
