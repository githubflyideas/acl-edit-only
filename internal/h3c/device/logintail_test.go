package device

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestNoLoginPromptReportsWhatArrived covers the diagnosis, not the login. When
// the prompt never comes the only evidence of why is what the device did send,
// and a bare "timeout waiting for prompt" throws that away — it took a
// byte-level capture on the deployed switch to find out the prompt was simply
// spelled differently. The bytes are safe to report here because this read
// happens before the password is sent.
func TestNoLoginPromptReportsWhatArrived(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatalf("listen: %v", err) }
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil { return }
		defer c.Close()
		c.Write([]byte("\r\n* Copyright (c) 2004-2024 New H3C Technologies Co., Ltd. *\r\nWho goes there?"))
		time.Sleep(3 * time.Second)
	}()

	s := NewSession(&TelnetTransport{}, DialConfig{Addr: ln.Addr().String(), ConnectTimeout: 5 * time.Second},
		&Auth{Username: "aclbot", Password: []byte("pw")}, 3977, 500*time.Millisecond)
	err = s.Open(context.Background())
	if err == nil { t.Fatal("open succeeded against a device that never prompted") }
	if !strings.Contains(err.Error(), "Who goes there?") {
		t.Errorf("error = %v, want it to quote what the device sent instead", err)
	}
}
