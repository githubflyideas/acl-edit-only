package handler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/auth"
)

// handleDispatchSSE handles GET /dispatch/stream?cr_id=N&csrf_token=…
// Streams acl-agent terminal output via SSE so the browser shows it live.
func (h *Handler) handleDispatchSSE(w http.ResponseWriter, r *http.Request) {
	// Validate CSRF via query param (SSE uses GET, no form body).
	tok := r.URL.Query().Get("csrf_token")
	cookie, err := r.Cookie("session")
	if err != nil || tok == "" || tok != cookie.Value {
		http.Error(w, "CSRF check failed", http.StatusForbidden)
		return
	}

	actor := r.Context().Value(ctxUser).(*auth.User)
	crID, err := strconv.ParseInt(r.URL.Query().Get("cr_id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid cr_id", 400)
		return
	}
	if !canDispatchRole(actor.Role) {
		http.Error(w, "forbidden", 403)
		return
	}

	// SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	// Pipe: agent writes to pw, we read from pr and forward to SSE.
	pr, pw := io.Pipe()

	var dispatchErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pw.Close()

		h.dispatchMu.Lock()
		defer h.dispatchMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		dispatchErr = h.svc.DispatchStream(ctx, actor, crID, pw)
	}()

	// Forward pipe lines to SSE.
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "data: %s\n\n", sseEscape(line))
		flusher.Flush()
	}
	pr.Close()
	wg.Wait()

	if dispatchErr != nil {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseEscape(dispatchErr.Error()))
	} else {
		fmt.Fprintf(w, "event: done\ndata: ok\n\n")
	}
	flusher.Flush()
}

func sseEscape(s string) string {
	out := make([]byte, 0, len(s))
	for _, b := range []byte(s) {
		if b == '\n' || b == '\r' {
			out = append(out, ' ')
		} else {
			out = append(out, b)
		}
	}
	return string(out)
}
