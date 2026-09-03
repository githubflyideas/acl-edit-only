package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMinimalConfigNeedsNoPaths is the deployment promise: unpack into any
// directory, name the ACL, the rule range and the switch, and every file the
// agent uses is found beside the config.
func TestMinimalConfigNeedsNoPaths(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aclagent.json")
	body := `{"acl":3977,"range_min":2000,"range_max":4999,"device_addr":"192.168.1.1:23"}`
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil { t.Fatal(err) }

	cfg, err := LoadConfig(cfgPath)
	if err != nil { t.Fatalf("LoadConfig: %v", err) }

	if want := filepath.Join(dir, "credential"); cfg.CredentialFile != want {
		t.Errorf("credential_file = %q, want %q", cfg.CredentialFile, want)
	}
	if want := filepath.Join(dir, "plans"); cfg.PlanDir != want {
		t.Errorf("plan_dir = %q, want %q", cfg.PlanDir, want)
	}
	if want := filepath.Join(dir, "agent-state.json"); cfg.StateFile != want {
		t.Errorf("state_file = %q, want %q", cfg.StateFile, want)
	}
	if cfg.AllocMax != 4999 {
		t.Errorf("alloc_max = %d, want it to default to range_max", cfg.AllocMax)
	}
}

// TestRelativePathsFollowTheConfig checks that a relative path in the config is
// read against the config's own directory, not the working directory the process
// was started from — otherwise the same deployment behaves differently under a
// shell and under a service manager.
func TestRelativePathsFollowTheConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aclagent.json")
	body := `{"acl":3977,"range_min":2000,"range_max":4999,"device_addr":"1.2.3.4:23",
	          "credential_file":"secrets/cred","plan_dir":"work/plans"}`
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil { t.Fatal(err) }

	cfg, err := LoadConfig(cfgPath)
	if err != nil { t.Fatalf("LoadConfig: %v", err) }
	if want := filepath.Join(dir, "secrets", "cred"); cfg.CredentialFile != want {
		t.Errorf("credential_file = %q, want %q", cfg.CredentialFile, want)
	}
	if want := filepath.Join(dir, "work", "plans"); cfg.PlanDir != want {
		t.Errorf("plan_dir = %q, want %q", cfg.PlanDir, want)
	}
}

func TestAbsolutePathsAreLeftAlone(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "aclagent.json")
	body := `{"acl":3977,"range_min":2000,"range_max":4999,"device_addr":"1.2.3.4:23",
	          "credential_file":"/etc/aclagent/credential"}`
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil { t.Fatal(err) }
	cfg, err := LoadConfig(cfgPath)
	if err != nil { t.Fatalf("LoadConfig: %v", err) }
	if cfg.CredentialFile != "/etc/aclagent/credential" {
		t.Errorf("credential_file = %q, want it unchanged", cfg.CredentialFile)
	}
}
