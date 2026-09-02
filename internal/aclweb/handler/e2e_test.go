package handler_test

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/auth"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/core"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/db"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/handler"
	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"

	_ "github.com/glebarez/sqlite"
)

const (
	e2eACL      = 3977
	e2eRangeMin = 100
	e2eRangeMax = 199
	e2eUser     = "aclbot"
	e2ePass     = "device-secret-pw"
)

type harness struct {
	dev  *fakedev.Device
	srv  *httptest.Server
	cli  *http.Client
	db   *sql.DB
	pass string // initial admin password
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil { t.Fatal(err) }
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the test directory")
	return ""
}

// buildAgent compiles the real acl-agent binary; the web layer only ever talks
// to the device by executing it, so a test that stubs it out would not test the
// thing that breaks.
func buildAgent(t *testing.T, root, out string) {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH; cannot build acl-agent for the end-to-end test")
	}
	cmd := exec.Command(goBin, "build", "-o", out, "./cmd/aclagent/")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build acl-agent: %v\n%s", err, b)
	}
}

func newHarness(t *testing.T, rules []fakedev.Rule) *harness {
	t.Helper()
	return newHarnessCfg(t, rules, false)
}

// newHarnessCfg is newHarness with the ownership-comment switch exposed, so the
// flow can be driven both with and without it.
func newHarnessCfg(t *testing.T, rules []fakedev.Rule, ruleComment bool) *harness {
	t.Helper()
	root := repoRoot(t)
	tmp := t.TempDir()

	dev := fakedev.New("SW-CORE01", e2eACL, e2eUser, e2ePass, rules)
	addr, err := dev.Start()
	if err != nil { t.Fatal(err) }
	t.Cleanup(dev.Close)

	agentBin := filepath.Join(tmp, "acl-agent")
	buildAgent(t, root, agentBin)

	credFile := filepath.Join(tmp, "cred")
	credBody := e2eUser + "\n" + base64Std(e2ePass)
	if err := os.WriteFile(credFile, []byte(credBody), 0400); err != nil { t.Fatal(err) }

	planDir := filepath.Join(tmp, "plans")
	if err := os.MkdirAll(planDir, 0750); err != nil { t.Fatal(err) }

	agentCfg := filepath.Join(tmp, "agent.json")
	cfgBody := fmt.Sprintf(`{
	  "acl": %d, "range_min": %d, "range_max": %d, "alloc_max": %d,
	  "credential_file": %q, "device_addr": %q,
	  "connect_timeout_s": 5, "read_timeout_s": 10, "daily_limit": 50,
	  "plan_dir": %q, "state_file": %q
	}`, e2eACL, e2eRangeMin, e2eRangeMax, e2eRangeMax,
		credFile, addr, planDir, filepath.Join(tmp, "agent-state.json"))
	if err := os.WriteFile(agentCfg, []byte(cfgBody), 0400); err != nil { t.Fatal(err) }

	sqlDB, err := db.Open(filepath.Join(tmp, "aclweb.db"))
	if err != nil { t.Fatalf("db open: %v", err) }
	t.Cleanup(func() { sqlDB.Close() })

	as := auth.NewService(sqlDB)
	adminPw, err := as.CreateInitialAdmin("admin")
	if err != nil { t.Fatalf("initial admin: %v", err) }

	svc := core.NewService(sqlDB, &core.WebConfig{
		ACL: e2eACL, RangeMin: e2eRangeMin, RangeMax: e2eRangeMax, AllocMax: e2eRangeMax,
		AgentBin: agentBin, AgentCfg: agentCfg, PlanDir: planDir,
		AgentTimeout: 30 * time.Second,
		RuleComment: ruleComment,
	}, as)

	tplFS := os.DirFS(filepath.Join(root, "cmd", "aclweb", "templates"))
	h, err := handler.New(sqlDB, svc, as, tplFS)
	if err != nil { t.Fatalf("templates: %v", err) }

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	cli := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &harness{dev: dev, srv: srv, cli: cli, db: sqlDB, pass: adminPw}
}

func base64Std(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 { n |= uint32(b[i+1]) << 8 }
		if rem > 2 { n |= uint32(b[i+2]) }
		sb.WriteByte(alpha[(n>>18)&63])
		sb.WriteByte(alpha[(n>>12)&63])
		if rem > 1 { sb.WriteByte(alpha[(n>>6)&63]) } else { sb.WriteByte('=') }
		if rem > 2 { sb.WriteByte(alpha[n&63]) } else { sb.WriteByte('=') }
	}
	return sb.String()
}

func (h *harness) login(t *testing.T) {
	t.Helper()
	resp, err := h.cli.PostForm(h.srv.URL+"/login", url.Values{
		"username": {"admin"}, "password": {h.pass},
	})
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status %d, want 303\n%s", resp.StatusCode, snippet(body))
	}
	u, _ := url.Parse(h.srv.URL)
	if len(h.cli.Jar.Cookies(u)) == 0 {
		t.Fatal("login set no usable session cookie: the client would be bounced straight back to /login")
	}
}

func (h *harness) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := h.cli.Get(h.srv.URL + path)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// csrf scrapes the token out of a rendered page, the way a browser would carry
// it back, rather than assuming what it is derived from.
func (h *harness) csrf(t *testing.T) string {
	t.Helper()
	_, body := h.get(t, "/requests")
	const marker = `name="csrf_token" value="`
	i := strings.Index(body, marker)
	if i < 0 { t.Fatal("no csrf token on the request list page") }
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j <= 0 { t.Fatal("empty csrf token") }
	return rest[:j]
}

func snippet(b []byte) string {
	s := string(b)
	if i := strings.Index(s, "</style>"); i >= 0 { s = s[i+8:] }
	if len(s) > 1500 { s = s[:1500] + "…" }
	return s
}

func e2eRules(n int) []fakedev.Rule {
	out := make([]fakedev.Rule, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fakedev.Rule{
			ID:      e2eRangeMin + i,
			Body:    fmt.Sprintf("permit tcp destination 10.20.0.%d 0 destination-port eq 443", i+1),
			Comment: fmt.Sprintf("ACLSYS-REQ-REQ-20260101-%04d-aaaaaaaa", i+1),
		})
	}
	return out
}

// ─── the tests ───────────────────────────────────────────────────

func TestLoginAndRequestListRender(t *testing.T) {
	h := newHarness(t, e2eRules(3))
	h.login(t)
	code, body := h.get(t, "/requests")
	if code != http.StatusOK {
		t.Fatalf("GET /requests = %d, want 200\n%s", code, snippet([]byte(body)))
	}
}

func TestFullFlowSubmitReviewExecute(t *testing.T) {
	t.Run("no comment", func(t *testing.T) { fullFlow(t, false) })
	t.Run("with comment", func(t *testing.T) { fullFlow(t, true) })
}

// fullFlow walks the whole operator path — login, submit, read the diff,
// execute, watch the terminal — and checks the device afterwards. It runs twice,
// once with the ownership comment enabled and once without, because the comment
// is the one part of the written configuration that is configurable.
func fullFlow(t *testing.T, ruleComment bool) {
	h := newHarnessCfg(t, e2eRules(5), ruleComment)
	h.login(t)
	tok := h.csrf(t)

	resp, err := h.cli.PostForm(h.srv.URL+"/requests/new", url.Values{
		"csrf_token":   {tok},
		"protocol":     {"tcp"},
		// Only the fields the real form actually posts: it offers src_ip with
		// no wildcard box, so a host source must work without one.
		"src_ip":       {"192.168.10.5"},
		"dst_ip":       {"10.99.1.7"},
		"dst_wildcard": {"0.0.0.0"},
		"dst_port_op":  {"eq"},
		"dst_port_val": {"8443"},
		"reason":       {"payment service needs access to the new gateway"},
	})
	if err != nil { t.Fatal(err) }
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("submit status %d, want 303\n%s", resp.StatusCode, snippet(body))
	}
	loc := resp.Header.Get("Location")
	if loc == "" { t.Fatal("submit returned no Location") }

	// Step 2: the operator reads the diff.
	code, detail := h.get(t, loc)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200\n%s", loc, code, snippet([]byte(detail)))
	}
	wantLine := "rule 105 permit tcp source 192.168.10.5 0 destination 10.99.1.7 0 destination-port eq 8443"
	if !strings.Contains(detail, wantLine) {
		t.Errorf("detail page does not show the rule that will be sent:\nwant: %s", wantLine)
	}
	if !strings.Contains(detail, "确认执行") {
		t.Error("detail page shows no execute button for a pending request")
	}

	// Step 3: execute, watching the terminal stream.
	crID := strings.TrimPrefix(loc, "/requests/")
	term, done, sseErr := h.stream(t, crID, tok)
	if sseErr != "" {
		t.Fatalf("dispatch stream reported an error: %s\n--- terminal ---\n%s", sseErr, term)
	}
	if !done {
		t.Fatalf("dispatch stream never reported completion\n--- terminal ---\n%s", term)
	}
	for _, want := range []string{"display acl 3977", "rule 105 permit tcp", "Configuration is saved"} {
		if !strings.Contains(term, want) {
			t.Errorf("terminal stream missing %q\n--- terminal ---\n%s", want, term)
		}
	}
	if strings.Contains(term, e2ePass) {
		t.Error("device password appeared in the browser stream")
	}

	// Step 4: the device really changed.
	var got *fakedev.Rule
	for _, r := range h.dev.Rules() {
		if r.ID == 105 { rr := r; got = &rr }
	}
	if got == nil {
		t.Fatalf("rule 105 absent from the device; rules are %v", h.dev.Rules())
	}
	if got.Body != "permit tcp source 192.168.10.5 0 destination 10.99.1.7 0 destination-port eq 8443" {
		t.Errorf("device rule body = %q", got.Body)
	}
	if ruleComment {
		if !strings.HasPrefix(got.Comment, "ACLSYS-REQ-REQ-") {
			t.Errorf("device rule comment = %q, want an ownership mark", got.Comment)
		}
	} else if got.Comment != "" {
		t.Errorf("device rule comment = %q, want none: the tool must add exactly "+
			"one line unless comments are switched on", got.Comment)
	}
	if !h.dev.Saved {
		t.Error("configuration was not saved on the device")
	}

	// Step 5: the request is recorded as active.
	var state string
	if err := h.db.QueryRow(`SELECT state FROM change_requests WHERE request_code LIKE 'REQ-%'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Errorf("request state = %q, want active", state)
	}
}

// stream consumes the SSE endpoint, returning the terminal text, whether a
// completion event arrived, and any error event.
func (h *harness) stream(t *testing.T, crID, tok string) (string, bool, string) {
	t.Helper()
	u := fmt.Sprintf("%s/dispatch/stream?cr_id=%s&csrf_token=%s",
		h.srv.URL, crID, url.QueryEscape(tok))
	resp, err := h.cli.Get(u)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("SSE status %d: %s", resp.StatusCode, snippet(b))
	}
	var term strings.Builder
	var done bool
	var errMsg, event string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			switch event {
			case "done":
				done = true
			case "error":
				errMsg = data
			default:
				term.WriteString(data)
				term.WriteString("\n")
			}
		case line == "":
			event = ""
		}
	}
	return term.String(), done, errMsg
}

func TestExecuteRejectsBadCSRF(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	h.login(t)
	resp, err := h.cli.Get(h.srv.URL + "/dispatch/stream?cr_id=1&csrf_token=not-the-token")
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
}

func TestUnauthenticatedAccessIsRefused(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	for _, path := range []string{"/requests", "/requests/1", "/reconcile", "/admin/users"} {
		code, _ := h.get(t, path)
		if code == http.StatusOK {
			t.Errorf("%s served content without a session", path)
		}
	}
}

// A request whose artifacts row is missing must still be viewable: the detail
// page is the only place the operator can see what happened to it.
func TestDetailPageSurvivesMissingArtifacts(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	h.login(t)
	var uid int64
	if err := h.db.QueryRow(`SELECT id FROM users WHERE username='admin'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	res, err := h.db.Exec(`
		INSERT INTO change_requests(request_code, action, requester_id, state, reason,
			protocol, src_ip, src_wildcard, src_port_op, src_port_val,
			dst_ip, dst_wildcard, dst_port_op, dst_port_val, rule_id)
		VALUES('REQ-19700101-9999','add_rule',?,'dispatch_failed','historical row',
			'tcp','','','',0,'10.0.0.9','0.0.0.0','eq',443,150)`, uid)
	if err != nil { t.Fatal(err) }
	id, _ := res.LastInsertId()

	code, body := h.get(t, fmt.Sprintf("/requests/%d", id))
	if code != http.StatusOK {
		t.Fatalf("GET detail of a request without artifacts = %d, want 200", code)
	}
	if !strings.Contains(body, "REQ-19700101-9999") {
		t.Errorf("detail page does not identify the request\n%s", snippet([]byte(body)))
	}
}

// A stolen session must not be enough to take the account over permanently.
func TestChangePasswordRequiresTheOldOne(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	h.login(t)
	tok := h.csrf(t)

	resp, err := h.cli.PostForm(h.srv.URL+"/admin/password", url.Values{
		"csrf_token":   {tok},
		"old_password": {"definitely-not-the-current-password"},
		"new_password": {"attacker-chosen-password"},
	})
	if err != nil { t.Fatal(err) }
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("password change with a wrong old password = %d, want 400\n%s",
			resp.StatusCode, snippet(body))
	}

	// The original password must still work.
	jar, _ := cookiejar.New(nil)
	h.cli.Jar = jar
	h.login(t)
}

// The CSRF token travels in the SSE query string, so it must not be the session
// token itself: query strings land in access logs, proxy logs and Referer.
func TestCSRFTokenIsNotTheSessionToken(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	h.login(t)
	var session string
	u, _ := url.Parse(h.srv.URL)
	for _, c := range h.cli.Jar.Cookies(u) {
		if c.Name == "session" { session = c.Value }
	}
	if session == "" { t.Fatal("no session cookie") }

	_, body := h.get(t, "/requests")
	i := strings.Index(body, `name="csrf_token" value="`)
	if i < 0 { t.Fatal("no csrf token rendered on the request list page") }
	rest := body[i+len(`name="csrf_token" value="`):]
	tok := rest[:strings.Index(rest, `"`)]
	if tok == "" { t.Fatal("empty csrf token") }
	if tok == session {
		t.Error("the CSRF token is the session token; putting it in the SSE URL leaks the session")
	}
}

// Reconcile logs into the switch. A viewer must not be able to start it.
func TestReconcileIsRestrictedByRole(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	h.login(t)
	if _, err := h.db.Exec(`UPDATE users SET role='viewer' WHERE username='admin'`); err != nil {
		t.Fatal(err)
	}
	tok := h.csrf(t)
	resp, err := h.cli.PostForm(h.srv.URL+"/reconcile", url.Values{"csrf_token": {tok}})
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("viewer reconcile = %d, want 403\n%s", resp.StatusCode, snippet(body))
	}
}

// The login rate limiter is a security control that had never been executed.
func TestLoginRateLimitEngages(t *testing.T) {
	h := newHarness(t, e2eRules(2))
	// A username that does not exist keeps bcrypt out of the loop, so this
	// exercises the limiter rather than the hash cost.
	for i := 0; i < 10; i++ {
		resp, err := h.cli.PostForm(h.srv.URL+"/login", url.Values{
			"username": {"nobody"}, "password": {"wrong"},
		})
		if err != nil { t.Fatal(err) }
		resp.Body.Close()
	}
	// The per-IP counter is now at the limit, so even the real password must be
	// refused for the rest of the window.
	resp, err := h.cli.PostForm(h.srv.URL+"/login", url.Values{
		"username": {"admin"}, "password": {h.pass},
	})
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Error("login succeeded after ten failed attempts from the same address")
	}
	var count int
	if err := h.db.QueryRow(`SELECT count FROM rate_limits WHERE key='ip:127.0.0.1'`).Scan(&count); err != nil {
		t.Fatalf("no per-IP rate limit record was written: %v", err)
	}
	if count < 10 {
		t.Errorf("per-IP failure count = %d, want at least 10", count)
	}
}

// A change approved against one configuration must not be applied to another.
func TestDriftBetweenSubmitAndExecuteStopsTheChange(t *testing.T) {
	h := newHarness(t, e2eRules(5))
	h.login(t)
	tok := h.csrf(t)

	resp, err := h.cli.PostForm(h.srv.URL+"/requests/new", url.Values{
		"csrf_token": {tok}, "protocol": {"ip"},
		"dst_ip": {"10.99.2.8"}, "dst_wildcard": {"0.0.0.0"},
		"reason": {"drift check"},
	})
	if err != nil { t.Fatal(err) }
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("submit status %d", resp.StatusCode)
	}
	crID := strings.TrimPrefix(resp.Header.Get("Location"), "/requests/")

	// Someone edits the switch by hand after the diff was reviewed.
	h.dev.SetRule(fakedev.Rule{
		ID:      130,
		Body:    "permit ip destination 10.77.0.1 0",
		Comment: "added by hand during the change window",
	})

	term, done, sseErr := h.stream(t, crID, tok)
	if done && sseErr == "" {
		t.Fatalf("the change was executed against a configuration nobody approved\n%s", term)
	}
	var state string
	if err := h.db.QueryRow(`SELECT state FROM change_requests WHERE id=?`, crID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "drift" {
		t.Errorf("request state = %q, want drift", state)
	}
	for _, r := range h.dev.Rules() {
		if r.Body == "permit ip destination 10.99.2.8 0" {
			t.Error("the rule was written to the switch despite the drift")
		}
	}
}
