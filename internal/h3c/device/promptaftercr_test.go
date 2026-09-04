package device

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPromptDrawnAfterCarriageReturn is the deployed switch's third byte-level
// surprise in a row. It punctuates lines with CR NUL and, after the password is
// accepted, redraws the prompt following a bare carriage return with no line
// feed anywhere before it. The prompt pattern required a newline in front of the
// prompt, so nothing matched and the login timed out at "waiting for prompt"
// with the prompt sitting right there in the buffer.
func TestPromptDrawnAfterCarriageReturn(t *testing.T) {
	for _, tc := range []struct{ name, tail string }{
		{"cr nul", "\r\x00<JP-SW-1>"},
		{"cr", "\r<JP-SW-1>"},
		{"nul", "\x00<JP-SW-1>"},
		{"lf", "\r\n<JP-SW-1>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil { t.Fatalf("listen: %v", err) }
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err != nil { return }
				defer c.Close()
				c.Write([]byte("\r\n* Copyright (c) New H3C *\r\x00\r\nLogin:"))
				buf := make([]byte, 256)
				c.Read(buf) //nolint:errcheck
				c.Write([]byte("\r\x00\r\nPassword:"))
				c.Read(buf) //nolint:errcheck
				c.Write([]byte(tc.tail))
				time.Sleep(2 * time.Second)
			}()

			s := NewSession(&TelnetTransport{}, DialConfig{Addr: ln.Addr().String(), ConnectTimeout: 5 * time.Second},
				&Auth{Username: "aclbot", Password: []byte("aclbot-pw")}, 3767, 500*time.Millisecond)
			if err := s.Open(context.Background()); err != nil {
				t.Fatalf("open against a prompt drawn after %q: %v", tc.tail, err)
			}
		})
	}
}

// TestLoginFailureQuotesTheDeviceWithoutThePassword covers the other half: when
// the prompt really does not come, the message has to show what did arrive, and
// it must not carry the password even though this read is the one that follows
// sending it. Devices that echo what was typed exist.
func TestLoginFailureQuotesTheDeviceWithoutThePassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatalf("listen: %v", err) }
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil { return }
		defer c.Close()
		c.Write([]byte("\r\nLogin:"))
		buf := make([]byte, 256)
		c.Read(buf) //nolint:errcheck
		c.Write([]byte("\r\nPassword:"))
		c.Read(buf) //nolint:errcheck
		c.Write([]byte("\r\nyou typed s3cret-pw and I have nothing more to say"))
		time.Sleep(2 * time.Second)
	}()

	s := NewSession(&TelnetTransport{}, DialConfig{Addr: ln.Addr().String(), ConnectTimeout: 5 * time.Second},
		&Auth{Username: "aclbot", Password: []byte("s3cret-pw")}, 3767, 500*time.Millisecond)
	err = s.Open(context.Background())
	if err == nil { t.Fatal("open succeeded against a device that never prompted") }
	if !strings.Contains(err.Error(), "nothing more to say") {
		t.Errorf("error = %v, want it to quote what the device sent", err)
	}
	if strings.Contains(err.Error(), "s3cret-pw") {
		t.Errorf("error = %v, must not carry the password", err)
	}
}
