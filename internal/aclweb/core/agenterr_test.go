package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAgent writes a script that stands in for acl-agent, emitting the given
// stdout and stderr and exiting with the given status.
func fakeAgent(t *testing.T, stdout, stderr string, code int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-agent")
	body := "#!/bin/sh\n"
	if stdout != "" { body += "printf '%s' " + shquote(stdout) + "\n" }
	if stderr != "" { body += "printf '%s' " + shquote(stderr) + " >&2\n" }
	body += "exit " + itoa(code) + "\n"
	if err := os.WriteFile(path, []byte(body), 0700); err != nil { t.Fatal(err) }
	return path
}

func shquote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func itoa(n int) string       { return string(rune('0' + n)) }

func agentService(t *testing.T, bin string) *Service {
	t.Helper()
	return NewService(nil, &WebConfig{
		ACL: 3977, RangeMin: 100, RangeMax: 199, AllocMax: 199,
		AgentBin: bin, AgentCfg: filepath.Join(t.TempDir(), "agent.json"),
		AgentTimeout: 10 * time.Second,
	}, nil)
}

// TestAgentErrorCarriesReportedDetail covers the common case: the agent runs,
// decides it cannot proceed, prints a JSON response saying why, and exits
// non-zero. The reason it gave must reach the caller.
func TestAgentErrorCarriesReportedDetail(t *testing.T) {
	bin := fakeAgent(t,
		`{"result":"rejected","stage":"auth","detail":"credential file /etc/aclagent/credential is mode 0644, want 0400"}`,
		"", 1)
	_, err := agentService(t, bin).runAgent(context.Background(), "snapshot")
	if err == nil { t.Fatal("expected an error") }
	if !strings.Contains(err.Error(), "mode 0644") {
		t.Errorf("error = %q, want the detail the agent reported", err)
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Errorf("error = %q, want the stage the agent reported", err)
	}
}

// TestAgentErrorCarriesStderr covers the case that produced a bare "agent
// exited with error" in the browser: the agent died before it could print a
// JSON response, so everything it had to say went to stderr.
func TestAgentErrorCarriesStderr(t *testing.T) {
	bin := fakeAgent(t, "", "aclagent: config /etc/aclagent/config.json: permission denied\n", 1)
	_, err := agentService(t, bin).runAgent(context.Background(), "snapshot")
	if err == nil { t.Fatal("expected an error") }
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %q, want the agent's stderr", err)
	}
}

// TestAgentErrorStderrSurvivesStreaming repeats it with a stream writer
// attached, which is the dispatch path: the operator's terminal gets the text
// and the error still has to carry it too.
func TestAgentErrorStderrSurvivesStreaming(t *testing.T) {
	bin := fakeAgent(t, "", "aclagent: dial 192.168.1.1:23: connection refused\n", 1)
	var term strings.Builder
	_, err := agentService(t, bin).runAgentStream(context.Background(), &term, "snapshot")
	if err == nil { t.Fatal("expected an error") }
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %q, want the agent's stderr", err)
	}
	if !strings.Contains(term.String(), "connection refused") {
		t.Errorf("terminal = %q, want the streamed text as well", term.String())
	}
}
