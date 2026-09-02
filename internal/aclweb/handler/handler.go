// Package handler wires HTTP routes to core.Service.
// CSRF is enforced on all state-mutating endpoints (POST/PUT/DELETE).
// Sessions are validated on every authenticated route via middleware.
package handler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/auth"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/core"
)

// ctxKey is the context key type for this package.
type ctxKey int

const (
	ctxUser    ctxKey = iota
	ctxSession ctxKey = iota
)

// Handler groups all HTTP handlers and their shared state.
type Handler struct {
	db     *sql.DB
	svc    *core.Service
	auths  *auth.Service

	// pages holds one independent template set per page. Every page file
	// defines a block named "body", so parsing them all into a single set
	// leaves only the last definition standing and every route renders the
	// same page.
	pages map[string]*template.Template

	// csrfKey derives CSRF tokens from session tokens. It lives only in memory,
	// so a restart invalidates outstanding forms; that is a page reload for the
	// operator and no weaker than the session it protects.
	csrfKey []byte

	// dispatchMu ensures only one acl-agent subprocess runs at a time.
	dispatchMu sync.Mutex
}

func New(db *sql.DB, svc *core.Service, as *auth.Service, tplFS fs.FS) (*Handler, error) {
	pages, err := parsePages(tplFS)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("csrf key: %w", err)
	}
	return &Handler{db: db, svc: svc, auths: as, pages: pages, csrfKey: key}, nil
}

// parsePages builds one template set per page file, each carrying its own copy
// of base.html.
func parsePages(tplFS fs.FS) (map[string]*template.Template, error) {
	names, err := fs.Glob(tplFS, "*.html")
	if err != nil {
		return nil, err
	}
	pages := make(map[string]*template.Template)
	for _, name := range names {
		if name == "base.html" {
			continue
		}
		t, err := template.New(name).ParseFS(tplFS, "base.html", name)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		pages[name] = t
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("no page templates found")
	}
	return pages, nil
}

// Register attaches all routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	// Public.
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.requireSession(h.handleLogout))

	// Requests.
	mux.HandleFunc("/requests", h.requireSession(h.handleRequests))
	mux.HandleFunc("/requests/new", h.requireSession(h.handleNewRequest))
	mux.HandleFunc("/requests/delete", h.requireSession(h.handleDeleteRequest))
	mux.HandleFunc("/requests/", h.requireSession(h.handleRequestDetail))

	// Approval actions.
	mux.HandleFunc("/approve", h.requireSession(h.handleApprove))
	mux.HandleFunc("/reject", h.requireSession(h.handleReject))

	// Dispatch.
	mux.HandleFunc("/dispatch", h.requireSession(h.handleDispatch))
	mux.HandleFunc("/dispatch/stream", h.requireSession(h.handleDispatchSSE))

	// Admin.
	mux.HandleFunc("/admin/users", h.requireSession(h.requireRole(auth.RoleAdmin, h.handleAdminUsers)))
	mux.HandleFunc("/admin/users/new", h.requireSession(h.requireRole(auth.RoleAdmin, h.handleAdminNewUser)))
	mux.HandleFunc("/admin/users/toggle", h.requireSession(h.requireRole(auth.RoleAdmin, h.handleAdminToggleUser)))
	mux.HandleFunc("/admin/password", h.requireSession(h.handleChangePassword))

	// Reconcile (admin or operator).
	mux.HandleFunc("/reconcile", h.requireSession(h.handleReconcile))

	// Static assets (embedded under /static/).
	mux.HandleFunc("/", h.handleRoot)
}

// ─── Auth handlers ───────────────────────────────────────────────

// isTLS reports whether the request reached us over HTTPS, either directly or
// through a reverse proxy that says so.
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.render(w, r, "login.html", map[string]interface{}{
			"Flash": r.URL.Query().Get("msg"),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	ip := clientIP(r)

	sessionToken, err := h.auths.Login(username, password, ip)
	var u *auth.User
	if err == nil {
		u, err = h.auths.ValidateSession(sessionToken)
	}
	if err != nil {
		log.Printf("login failed user=%s ip=%s: %v", username, ip, err)
		h.render(w, r, "login.html", map[string]interface{}{"Error": "Invalid credentials or account locked."})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		// Secure only under TLS. Setting it unconditionally means the browser
		// never returns the cookie on the plain-HTTP deployment the README
		// documents, and every login silently bounces back to the login page.
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((8 * time.Hour).Seconds()),
	})
	log.Printf("login ok user=%s role=%s ip=%s", u.Username, u.Role, ip)
	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if tok, err := r.Cookie("session"); err == nil {
		h.auths.Logout(tok.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/login?msg=logged+out", http.StatusSeeOther)
}

// ─── Request handlers ─────────────────────────────────────────────

func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT cr.id, cr.request_code, cr.action, cr.state, cr.reason,
		       cr.rule_id, u.username, cr.submitted_at
		FROM change_requests cr
		JOIN users u ON u.id = cr.requester_id
		ORDER BY cr.submitted_at DESC LIMIT 200`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type row struct {
		ID, RuleID               int64
		Code, Action, State, Reason string
		Requester                string
		CreatedAt                int64
	}
	var items []row
	for rows.Next() {
		var rid sql.NullInt64
		var item row
		rows.Scan(&item.ID, &item.Code, &item.Action, &item.State, &item.Reason,
			&rid, &item.Requester, &item.CreatedAt)
		if rid.Valid { item.RuleID = rid.Int64 }
		items = append(items, item)
	}
	actor := r.Context().Value(ctxUser).(*auth.User)
	h.render(w, r, "requests.html", map[string]interface{}{
		"Items": items,
		"Actor": actor,
		"CSRF":  h.csrfToken(r),
	})
}

func (h *Handler) handleNewRequest(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(ctxUser).(*auth.User)
	if r.Method == http.MethodGet {
		h.render(w, r, "new_request.html", map[string]interface{}{
			"Actor": actor, "CSRF": h.csrfToken(r),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.checkCSRF(r); err != nil {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}

	dstPortVal, _ := strconv.Atoi(r.FormValue("dst_port_val"))
	srcPortVal, _ := strconv.Atoi(r.FormValue("src_port_val"))
	req := core.SubmitRequest{
		Protocol:    r.FormValue("protocol"),
		SrcIP:       r.FormValue("src_ip"),
		SrcWildcard: r.FormValue("src_wildcard"),
		SrcPortOp:   r.FormValue("src_port_op"),
		SrcPortVal:  srcPortVal,
		DstIP:       r.FormValue("dst_ip"),
		DstWildcard: r.FormValue("dst_wildcard"),
		DstPortOp:   r.FormValue("dst_port_op"),
		DstPortVal:  dstPortVal,
		Reason:      r.FormValue("reason"),
	}
	id, err := h.svc.Submit(r.Context(), actor, req)
	if err != nil {
		h.render(w, r, "new_request.html", map[string]interface{}{
			"Actor": actor, "CSRF": h.csrfToken(r), "Error": err.Error(),
		})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

func (h *Handler) handleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	actor := r.Context().Value(ctxUser).(*auth.User)
	existingID, _ := strconv.ParseInt(r.FormValue("cr_id"), 10, 64)
	id, err := h.svc.SubmitDelete(r.Context(), actor, existingID, r.FormValue("reason"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

func (h *Handler) handleRequestDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/requests/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil { http.NotFound(w, r); return }

	type detail struct {
		ID, RuleID                  int64
		Code, Action, State, Reason string
		Protocol, SrcIP, DstIP      string
		SrcPortOp, DstPortOp        string
		SrcPortVal, DstPortVal      int64
		Requester, Approver         string
		ApproveComment              string
		CreatedAt                   int64
		DiffText, PlanJSON          string
		PlanSHA256                  string
	}
	var d detail
	var approver sql.NullString
	var approveComment sql.NullString
	var ruleID sql.NullInt64
	// The artifacts are LEFT JOINed, so all three columns are NULL for a
	// request that has none — a request that failed before the artifact chain
	// was written, or one restored from an older database. Scanning those into
	// plain strings fails, and the failure used to be reported as 404, hiding
	// the one page that would explain what happened.
	var diffText, planJSON, planSHA sql.NullString
	err = h.db.QueryRowContext(r.Context(), `
		SELECT cr.id, cr.request_code, cr.action, cr.state, cr.reason,
		       cr.protocol, cr.src_ip, cr.dst_ip,
		       cr.src_port_op, cr.src_port_val, cr.dst_port_op, cr.dst_port_val,
		       req.username, COALESCE(app.username,''), cr.approve_comment, cr.rule_id, cr.submitted_at,
		       ca.diff_text, ca.plan_json, ca.plan_sha256
		FROM change_requests cr
		JOIN users req ON req.id = cr.requester_id
		LEFT JOIN users app ON app.id = cr.approver_id
		LEFT JOIN change_artifacts ca ON ca.request_id = cr.id
		WHERE cr.id=?`, id,
	).Scan(
		&d.ID, &d.Code, &d.Action, &d.State, &d.Reason,
		&d.Protocol, &d.SrcIP, &d.DstIP,
		&d.SrcPortOp, &d.SrcPortVal, &d.DstPortOp, &d.DstPortVal,
		&d.Requester, &approver, &approveComment, &ruleID, &d.CreatedAt,
		&diffText, &planJSON, &planSHA,
	)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("request detail %d: %v", id, err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	d.DiffText = diffText.String
	d.PlanJSON = planJSON.String
	d.PlanSHA256 = planSHA.String
	if approver.Valid { d.Approver = approver.String }
	if approveComment.Valid { d.ApproveComment = approveComment.String }
	if ruleID.Valid { d.RuleID = ruleID.Int64 }

	actor := r.Context().Value(ctxUser).(*auth.User)
	h.render(w, r, "request_detail.html", map[string]interface{}{
		"D": d, "Actor": actor, "CSRF": h.csrfToken(r),
		"CanExecute": d.State == "pending" || d.State == "approved",
	})
}

// ─── Approve / Reject / Dispatch ─────────────────────────────────

func (h *Handler) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	actor := r.Context().Value(ctxUser).(*auth.User)
	id, _ := strconv.ParseInt(r.FormValue("cr_id"), 10, 64)
	comment := r.FormValue("comment")
	if err := h.svc.Approve(r.Context(), actor, id, comment); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

func (h *Handler) handleReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	actor := r.Context().Value(ctxUser).(*auth.User)
	id, _ := strconv.ParseInt(r.FormValue("cr_id"), 10, 64)
	if err := h.svc.Reject(r.Context(), actor, id, r.FormValue("comment")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

func (h *Handler) handleDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	actor := r.Context().Value(ctxUser).(*auth.User)
	id, _ := strconv.ParseInt(r.FormValue("cr_id"), 10, 64)

	// Serialise all dispatches.
	h.dispatchMu.Lock()
	defer h.dispatchMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := h.svc.Dispatch(ctx, actor, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/requests/%d", id), http.StatusSeeOther)
}

// ─── Admin handlers ───────────────────────────────────────────────

func (h *Handler) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.db.QueryContext(r.Context(),
		`SELECT id, username, role, active FROM users ORDER BY id`)
	defer rows.Close()
	type urow struct{ ID int64; Username, Role string; Active bool }
	var users []urow
	for rows.Next() {
		var u urow
		rows.Scan(&u.ID, &u.Username, &u.Role, &u.Active)
		users = append(users, u)
	}
	// The actor is passed typed, the way every other page passes it: templates
	// cannot perform a type assertion, and an interface value here is what made
	// admin_users.html reach for Go syntax and break the whole template set.
	h.render(w, r, "admin_users.html", map[string]interface{}{
		"Users": users, "Actor": r.Context().Value(ctxUser).(*auth.User), "CSRF": h.csrfToken(r),
	})
}

func (h *Handler) handleAdminNewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	_ = r.Context().Value(ctxUser)
	username := strings.TrimSpace(r.FormValue("username"))
	role := r.FormValue("role")
	password := r.FormValue("password")
	if _, err := h.auths.CreateUser(username, password, role); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *Handler) handleAdminToggleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	actor := r.Context().Value(ctxUser).(*auth.User)
	targetID, _ := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	active := r.FormValue("active") == "1"
	if err := h.auths.SetActive(actor.ID, targetID, active); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	actor := r.Context().Value(ctxUser).(*auth.User)
	oldPw := r.FormValue("old_password")
	newPw := r.FormValue("new_password")
	if err := h.auths.ChangePassword(actor.ID, oldPw, newPw); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/requests?msg=password+changed", http.StatusSeeOther)
}

func (h *Handler) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
	if err := h.checkCSRF(r); err != nil { http.Error(w, "CSRF", 403); return }
	// Reconcile logs into the switch and rewrites request state from what it
	// finds. requireSession alone let a viewer start it.
	actor := r.Context().Value(ctxUser).(*auth.User)
	if !canDispatchRole(actor.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.svc.Reconcile(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/requests", http.StatusSeeOther)
}

// ─── Middleware ───────────────────────────────────────────────────

func (h *Handler) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := h.auths.ValidateSession(cookie.Value)
		if err != nil {
			http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Path: "/"})
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxSession, cookie.Value)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (h *Handler) requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(ctxUser).(*auth.User)
		if u.Role != auth.RoleAdmin && u.Role != role {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// ─── Template rendering ───────────────────────────────────────────

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	t, ok := h.pages[name]
	if !ok {
		log.Printf("template %s not found", name)
		http.Error(w, "rendering error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s error: %v", name, err)
		http.Error(w, "rendering error", http.StatusInternalServerError)
	}
}

// ─── CSRF helpers ─────────────────────────────────────────────────

// csrfToken returns the CSRF token for this request's session. It is derived
// from the session token with a per-process key rather than being the session
// token itself: the token is passed in the query string of the SSE endpoint,
// where it would otherwise be written to access logs, proxy logs and any
// Referer the browser sends, handing the session to anyone who reads them.
func (h *Handler) csrfToken(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.csrfKey)
	mac.Write([]byte(cookie.Value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) checkCSRF(r *http.Request) error {
	tok := r.FormValue("csrf_token")
	want := h.csrfToken(r)
	if tok == "" || want == "" || !hmac.Equal([]byte(tok), []byte(want)) {
		return fmt.Errorf("csrf mismatch")
	}
	return nil
}

// ─── Misc helpers ─────────────────────────────────────────────────

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 { return strings.TrimSpace(xff[:i]) }
		return strings.TrimSpace(xff)
	}
	if ip, _, err := strings.Cut(r.RemoteAddr, ":"); err {
		return ip
	}
	return r.RemoteAddr
}

func canApproveRole(role string) bool { return role == auth.RoleAdmin || role == auth.RoleApprover }
func canDispatchRole(role string) bool { return role == auth.RoleAdmin || role == auth.RoleOperator }
