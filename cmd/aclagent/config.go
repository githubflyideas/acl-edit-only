package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const defaultDailyLimit = 50

type AgentConfig struct {
	ACL            int    `json:"acl"`
	RangeMin       int    `json:"range_min"`
	RangeMax       int    `json:"range_max"`
	AllocMax       int    `json:"alloc_max"`
	CredentialFile string `json:"credential_file"`
	DeviceAddr     string `json:"device_addr"`
	ConnectTimeout int    `json:"connect_timeout_s"`
	ReadTimeout    int    `json:"read_timeout_s"`
	DailyLimit     int    `json:"daily_limit"`
	PlanDir        string `json:"plan_dir"`
	StateFile      string `json:"state_file"`

	configSHA256 string
	configPath   string
}

func LoadConfig(path string) (*AgentConfig, error) {
	absPath, err := filepath.Abs(path)
	if err != nil { return nil, fmt.Errorf("config path: %w", err) }
	f, err := os.Open(absPath)
	if err != nil { return nil, fmt.Errorf("open config: %w", err) }
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil { return nil, fmt.Errorf("read config: %w", err) }
	var cfg AgentConfig
	if err := json.Unmarshal(raw, &cfg); err != nil { return nil, fmt.Errorf("parse config: %w", err) }
	h := sha256.Sum256(raw)
	cfg.configSHA256 = fmt.Sprintf("%x", h)
	cfg.configPath = absPath
	if err := cfg.validate(); err != nil { return nil, fmt.Errorf("invalid config: %w", err) }
	return &cfg, nil
}

func (c *AgentConfig) validate() error {
	if c.ACL < 2000 || c.ACL > 4999 {
		return fmt.Errorf("acl %d is not a valid H3C advanced ACL (2000-4999)", c.ACL)
	}
	if c.RangeMin <= 0 || c.RangeMax <= 0 {
		return fmt.Errorf("range_min and range_max must be positive")
	}
	if c.RangeMin > c.RangeMax {
		return fmt.Errorf("range_min %d > range_max %d", c.RangeMin, c.RangeMax)
	}
	if c.AllocMax < c.RangeMin || c.AllocMax > c.RangeMax {
		return fmt.Errorf("alloc_max %d outside [%d,%d]", c.AllocMax, c.RangeMin, c.RangeMax)
	}
	if c.CredentialFile == "" { return fmt.Errorf("credential_file is required") }
	if c.DeviceAddr == ""    { return fmt.Errorf("device_addr is required") }
	if c.PlanDir == ""       { return fmt.Errorf("plan_dir is required") }
	if c.StateFile == ""     { return fmt.Errorf("state_file is required") }
	if c.ConnectTimeout <= 0 { c.ConnectTimeout = 10 }
	if c.ReadTimeout <= 0    { c.ReadTimeout = 30 }
	if c.DailyLimit <= 0     { c.DailyLimit = defaultDailyLimit }
	return nil
}

func (c *AgentConfig) SHA256() string     { return c.configSHA256 }
func (c *AgentConfig) ConfigPath() string { return c.configPath }
