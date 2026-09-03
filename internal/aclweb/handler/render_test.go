package handler

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenderFailureDoesNotSendAPartialPage covers what a real deployment hit: a
// template that fails part way through. Executing straight into the
// ResponseWriter had already committed a 200 and the opening markup, so the
// error page could not be sent — the server logged "superfluous WriteHeader" and
// the operator got a page that stopped mid-sentence with no indication why.
func TestRenderFailureDoesNotSendAPartialPage(t *testing.T) {
	tpl := template.Must(template.New("boom.html").Parse(
		`<html><body>before the failure{{ .Missing.Field }}after</body></html>`))
	h := &Handler{pages: map[string]*template.Template{"boom.html": tpl}}

	rec := httptest.NewRecorder()
	h.render(rec, httptest.NewRequest(http.MethodGet, "/", nil), "boom.html", struct{}{})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if body := rec.Body.String(); strings.Contains(body, "before the failure") {
		t.Errorf("body carries markup written before the failure: %q", body)
	}
}

// TestRenderSendsTheWholePage is the ordinary path, kept honest about the fact
// that buffering must not change what a working page looks like.
func TestRenderSendsTheWholePage(t *testing.T) {
	tpl := template.Must(template.New("ok.html").Parse(`<p>{{ .Name }}</p>`))
	h := &Handler{pages: map[string]*template.Template{"ok.html": tpl}}

	rec := httptest.NewRecorder()
	h.render(rec, httptest.NewRequest(http.MethodGet, "/", nil), "ok.html",
		map[string]string{"Name": "SW-CORE01"})

	if rec.Code != http.StatusOK { t.Errorf("status = %d, want 200", rec.Code) }
	if got := rec.Body.String(); got != "<p>SW-CORE01</p>" {
		t.Errorf("body = %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}
