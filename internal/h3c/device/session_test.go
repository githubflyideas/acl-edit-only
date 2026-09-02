package device_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/device"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/plan"
)

const (
	testACL  = 3977
	testUser = "aclbot"
	testPass = "s3cret-pass"
)

// bigACL returns n rules starting at 100, enough to force several pages.
func bigACL(n int) []fakedev.Rule {
	out := make([]fakedev.Rule, 0, n)
	for i := 0; i < n; i++ {
		id := 100 + i
		out = append(out, fakedev.Rule{
			ID:      id,
			Body:    fmt.Sprintf("permit tcp destination 10.20.%d.%d 0 destination-port eq 443", i/256, i%256),
			Comment: fmt.Sprintf("ACLSYS-REQ-CR-0000%d-deadbeef", i),
		})
	}
	return out
}

func dial(t *testing.T, d *fakedev.Device) *device.Session {
	t.Helper()
	addr, err := d.Start()
	if err != nil {
		t.Fatalf("start fake device: %v", err)
	}
	t.Cleanup(d.Close)
	s := device.NewSession(&device.TelnetTransport{},
		device.DialConfig{Addr: addr, ConnectTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second},
		&device.Auth{Username: testUser, Password: []byte(testPass)},
		testACL, 5*time.Second)
	ctx := context.Background()
	if err := s.Open(ctx); err != nil {
		t.Fatalf("open session: %v", err)
	}
	t.Cleanup(func() { s.Close(context.Background()) })
	return s
}

func TestOpenAndSnapshotSmallACL(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(3))
	s := dial(t, d)
	raw, err := device.Snapshot(context.Background(), s)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if n := device.HeaderCount(raw); n != 3 {
		t.Fatalf("HeaderCount = %d, want 3\n---\n%s", n, raw)
	}
	if !strings.Contains(raw, "rule 102 permit tcp") {
		t.Fatalf("snapshot missing last rule:\n%s", raw)
	}
}

func TestAuthRejected(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(1))
	addr, err := d.Start()
	if err != nil { t.Fatal(err) }
	defer d.Close()
	s := device.NewSession(&device.TelnetTransport{},
		device.DialConfig{Addr: addr, ConnectTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second},
		&device.Auth{Username: testUser, Password: []byte("wrong-password")},
		testACL, 3*time.Second)
	if err := s.Open(context.Background()); err == nil {
		t.Fatal("expected auth failure, got nil")
	}
}

// TestSnapshotPagedACL is the regression test for the paging path: 120 rules
// with comments is ~240 lines, ten pages at the device's default screen length.
func TestSnapshotPagedACL(t *testing.T) {
	const n = 120
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(n))
	s := dial(t, d)
	raw, err := device.Snapshot(context.Background(), s)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := device.HeaderCount(raw); got != n {
		t.Fatalf("HeaderCount = %d, want %d", got, n)
	}
	for _, id := range []int{100, 100 + n/2, 100 + n - 1} {
		if !strings.Contains(raw, fmt.Sprintf("rule %d permit", id)) {
			t.Errorf("snapshot lost rule %d", id)
		}
	}
	if strings.Contains(raw, "More") {
		t.Errorf("snapshot still contains a More marker:\n%s", tail(raw))
	}
}

// TestDisplayACLPagesWithSpace forces paging to stay on (the device ignores
// screen-length disable) to prove the space-paging loop works on its own.
func TestDisplayACLPagesWithSpace(t *testing.T) {
	const n = 60
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(n))
	d.PageLines = 10
	s := dial(t, d)
	raw, err := s.DisplayACL(context.Background())
	if err != nil {
		t.Fatalf("DisplayACL: %v", err)
	}
	if got := device.HeaderCount(raw); got != n {
		t.Fatalf("HeaderCount = %d, want %d", got, n)
	}
	if !strings.Contains(raw, fmt.Sprintf("rule %d permit", 100+n-1)) {
		t.Fatalf("paged read lost the highest rule ID — allocation would reuse it")
	}
	if strings.Contains(raw, "More") {
		t.Errorf("More marker leaked into text")
	}
}

func TestApplyAddsRuleAndComment(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(5))
	s := dial(t, d)
	ctx := context.Background()
	p := &plan.Plan{
		RequestID: "CR-000001", Op: plan.OpAdd, RuleID: 105, Action: plan.ActionPermit,
		Protocol: "tcp",
		Src:      &plan.AddrMask{IP: "192.168.10.0", Wildcard: "0.0.0.255"},
		Dst:      &plan.AddrMask{IP: "10.99.1.7", Wildcard: "0"},
		DstPort:  &plan.PortCond{Op: "eq", Value: 8443},
		Comment:  "ACLSYS-REQ-CR-000001-abcd1234",
		ExpectCountBefore: 5,
	}
	if err := device.Apply(ctx, s, p, 0); err != nil {
		t.Fatalf("Apply: %v\n--- session ---\n%s", err, tail(s.RawOutput()))
	}
	var got *fakedev.Rule
	for _, r := range d.Rules() {
		if r.ID == 105 { rr := r; got = &rr }
	}
	if got == nil {
		t.Fatalf("rule 105 not created; device has %v", d.Rules())
	}
	want := "permit tcp source 192.168.10.0 0.0.0.255 destination 10.99.1.7 0 destination-port eq 8443"
	if got.Body != want {
		t.Errorf("rule body\n got: %s\nwant: %s", got.Body, want)
	}
	if got.Comment != p.Comment {
		t.Errorf("comment = %q, want %q", got.Comment, p.Comment)
	}
	if !d.Saved {
		t.Error("configuration was not saved")
	}
}

// TestGuardBlocksOccupiedID is the important safety test: if the target rule ID
// already exists, Apply must refuse rather than overwrite it.
func TestGuardBlocksOccupiedID(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(5))
	s := dial(t, d)
	before := d.Rules()
	p := &plan.Plan{
		RequestID: "CR-000002", Op: plan.OpAdd, RuleID: 102, Action: plan.ActionPermit,
		Protocol: "tcp",
		Dst:      &plan.AddrMask{IP: "10.99.1.8", Wildcard: "0"},
		Comment:  "ACLSYS-REQ-CR-000002-abcd1234",
		ExpectCountBefore: 5,
	}
	err := device.Apply(context.Background(), s, p, 0)
	if err == nil {
		t.Fatal("Apply overwrote an existing rule — guard did not fire")
	}
	if !strings.Contains(err.Error(), "guard_failed") {
		t.Errorf("error = %v, want guard_failed", err)
	}
	if len(d.Rules()) != len(before) {
		t.Errorf("device changed despite guard failure")
	}
}

// TestGuardBlocksCountMismatch covers concurrent modification: the plan was
// built when the ACL had 5 rules but someone else has since added one.
func TestGuardBlocksCountMismatch(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(6))
	s := dial(t, d)
	p := &plan.Plan{
		RequestID: "CR-000003", Op: plan.OpAdd, RuleID: 200, Action: plan.ActionPermit,
		Protocol: "ip",
		Dst:      &plan.AddrMask{IP: "10.99.1.9", Wildcard: "0"},
		Comment:  "ACLSYS-REQ-CR-000003-abcd1234",
		ExpectCountBefore: 5,
	}
	err := device.Apply(context.Background(), s, p, 0)
	if err == nil || !strings.Contains(err.Error(), "guard_failed") {
		t.Fatalf("expected guard_failed on count mismatch, got %v", err)
	}
}

func TestPasswordNeverAppearsInRawOutput(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(2))
	s := dial(t, d)
	if _, err := device.Snapshot(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.RawOutput(), testPass) {
		t.Fatal("password leaked into session transcript")
	}
}

func TestStreamMirrorsTranscriptWithoutPassword(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(4))
	addr, err := d.Start()
	if err != nil { t.Fatal(err) }
	defer d.Close()
	var sb strings.Builder
	s := device.NewSession(&device.TelnetTransport{},
		device.DialConfig{Addr: addr, ConnectTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second},
		&device.Auth{Username: testUser, Password: []byte(testPass)}, testACL, 5*time.Second)
	s.SetStream(&sb)
	ctx := context.Background()
	if err := s.Open(ctx); err != nil { t.Fatal(err) }
	defer s.Close(ctx)
	if _, err := device.Snapshot(ctx, s); err != nil { t.Fatal(err) }
	if strings.Contains(sb.String(), testPass) {
		t.Fatal("password leaked into live stream")
	}
	if !strings.Contains(sb.String(), "rule 100 permit") {
		t.Fatalf("stream did not carry device output:\n%s", sb.String())
	}
}

func TestUnknownCommandIsDetected(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(2))
	s := dial(t, d)
	err := s.Exec(context.Background(), "no-such-command", ">", "]")
	if err == nil {
		t.Fatal("expected device error for unknown command")
	}
}

func TestSaveFailureIsReported(t *testing.T) {
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(5))
	d.SaveFail = true
	s := dial(t, d)
	p := &plan.Plan{
		RequestID: "CR-000004", Op: plan.OpAdd, RuleID: 105, Action: plan.ActionPermit,
		Protocol: "ip",
		Dst:      &plan.AddrMask{IP: "10.99.1.10", Wildcard: "0"},
		Comment:  "ACLSYS-REQ-CR-000004-abcd1234",
		ExpectCountBefore: 5,
	}
	err := device.Apply(context.Background(), s, p, 0)
	if err == nil {
		t.Fatal("expected save failure")
	}
	// The rule must still be present: a save failure must never roll back.
	found := false
	for _, r := range d.Rules() { if r.ID == 105 { found = true } }
	if !found {
		t.Error("rule was rolled back after save failure — must not happen")
	}
}

func tail(s string) string {
	lines := strings.Split(s, "\n")
	if len(lines) > 40 { lines = lines[len(lines)-40:] }
	return strings.Join(lines, "\n")
}

// TestSnapshotWorksWithoutScreenLengthDisable covers devices (or privilege
// levels) that reject "screen-length disable". Snapshot must fall back to
// space-paging instead of failing: refusing to read the ACL at all is worse
// than paging through it.
func TestSnapshotWorksWithoutScreenLengthDisable(t *testing.T) {
	const n = 40
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, bigACL(n))
	d.NoScreenLength = true
	d.PageLines = 12
	s := dial(t, d)
	raw, err := device.Snapshot(context.Background(), s)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got := device.HeaderCount(raw); got != n {
		t.Fatalf("HeaderCount = %d, want %d", got, n)
	}
	if !strings.Contains(raw, fmt.Sprintf("rule %d permit", 100+n-1)) {
		t.Fatal("snapshot lost the highest rule ID")
	}
}

// TestPagingSurvivesPromptCharactersInOutput guards the pattern-priority bug:
// ReadUntil returns the first matching pattern, so if ">" is tested before
// "---- More ----" any existing comment containing ">" ends the read early and
// silently truncates the ACL — which would make max+1 allocation reuse a live
// rule ID.
func TestPagingSurvivesPromptCharactersInOutput(t *testing.T) {
	rules := bigACL(30)
	rules[3].Comment = "allow app -> db per ticket 4412"
	rules[7].Comment = "temp [staging] access"
	d := fakedev.New("SW-CORE01", testACL, testUser, testPass, rules)
	d.NoScreenLength = true
	d.PageLines = 5
	s := dial(t, d)
	raw, err := s.DisplayACL(context.Background())
	if err != nil {
		t.Fatalf("DisplayACL: %v", err)
	}
	if got := device.HeaderCount(raw); got != 30 {
		t.Fatalf("HeaderCount = %d, want 30", got)
	}
	if !strings.Contains(raw, "rule 129 permit") {
		t.Fatalf("output truncated at a '>' inside a comment; highest rule lost:\n%s", tail(raw))
	}
}
