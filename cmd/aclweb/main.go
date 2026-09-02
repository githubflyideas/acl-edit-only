// Command aclweb runs the HTTP server for the H3C ACL approval system.
// It has no device credentials; all device access is delegated to acl-agent
// called via sudo.
package main

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/githubflyideas/acl-edit-only/internal/aclweb/auth"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/core"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/db"
	"github.com/githubflyideas/acl-edit-only/internal/aclweb/handler"

	// Pure-Go SQLite (no CGo).
	_ "github.com/glebarez/sqlite"
)

//go:embed templates/*.html
var templateFS embed.FS

// Config is loaded from a JSON file (not the agent config — this is the web config).
type Config struct {
	Listen   string `json:"listen"`
	TLSCert  string `json:"tls_cert"`
	TLSKey   string `json:"tls_key"`
	DBPath   string `json:"db_path"`
	PlanDir  string `json:"plan_dir"`

	AgentBin         string `json:"agent_bin"`
	AgentCfg         string `json:"agent_cfg"`
	AgentTimeoutSecs int    `json:"agent_timeout_secs"`

	ACL      int `json:"acl"`
	RangeMin int `json:"range_min"`
	RangeMax int `json:"range_max"`
	AllocMax int `json:"alloc_max"`

	ReconcileIntervalMin int `json:"reconcile_interval_min"`
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	cfg := &Config{
		Listen:           ":8443",
		AgentTimeoutSecs: 60,
	}
	if err := json.Unmarshal(raw, cfg); err != nil { return nil, err }
	if cfg.ACL == 0 { return nil, fmt.Errorf("acl must be non-zero in config") }
	if cfg.AllocMax == 0 { cfg.AllocMax = cfg.RangeMax }
	if cfg.DBPath == "" { cfg.DBPath = "aclweb.db" }
	if cfg.AgentBin == "" { return nil, fmt.Errorf("agent_bin is required") }
	if cfg.AgentCfg == "" { return nil, fmt.Errorf("agent_cfg is required") }
	if cfg.PlanDir == "" { return nil, fmt.Errorf("plan_dir is required") }
	return cfg, nil
}

func main() {
	cfgPath := flag.String("config", "aclweb.json", "path to web config JSON")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil { log.Fatalf("config: %v", err) }

	// Open SQLite (WAL + foreign keys via db.Open).
	sqlDB, err := db.Open(cfg.DBPath)
	if err != nil { log.Fatalf("db open: %v", err) }
	defer sqlDB.Close()

	// Auth service.
	as := auth.NewService(sqlDB)
	initialPw, err := as.CreateInitialAdmin("admin")
	if err != nil { log.Fatalf("initial admin: %v", err) }
	if initialPw != "" {
		log.Printf("INITIAL ADMIN CREATED — username: admin  password: %s", initialPw)
		log.Printf("Change this password immediately after first login.")
	}

	// Core service.
	agentTimeout := time.Duration(cfg.AgentTimeoutSecs) * time.Second
	webCfg := &core.WebConfig{
		ACL: cfg.ACL, RangeMin: cfg.RangeMin, RangeMax: cfg.RangeMax, AllocMax: cfg.AllocMax,
		AgentBin: cfg.AgentBin, AgentCfg: cfg.AgentCfg,
		PlanDir: cfg.PlanDir, AgentTimeout: agentTimeout,
	}
	svc := core.NewService(sqlDB, webCfg, as)

	// Parse templates (embedded).
	subFS, err := fs.Sub(templateFS, "templates")
	if err != nil { log.Fatalf("template fs: %v", err) }
	// HTTP mux.
	h, err := handler.New(sqlDB, svc, as, subFS)
	if err != nil { log.Fatalf("templates: %v", err) }
	mux := http.NewServeMux()
	h.Register(mux)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}

	// Periodic reconciliation.
	if cfg.ReconcileIntervalMin > 0 {
		go func() {
			tick := time.NewTicker(time.Duration(cfg.ReconcileIntervalMin) * time.Minute)
			defer tick.Stop()
			for range tick.C {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				if err := svc.Reconcile(ctx); err != nil {
					log.Printf("reconcile error: %v", err)
				}
				cancel()
			}
		}()
	}

	// Periodic session cleanup.
	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		for range tick.C { as.PurgeExpiredSessions() }
	}()

	// Graceful shutdown.
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("aclweb listening on %s (TLS)", cfg.Listen)
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Printf("aclweb listening on %s (plain HTTP — add TLS cert/key in production)", cfg.Listen)
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
