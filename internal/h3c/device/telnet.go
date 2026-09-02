package device

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	iacByte = 0xFF
	iacWill = 0xFB
	iacWont = 0xFC
	iacDo   = 0xFD
	iacDont = 0xFE
	iacSB   = 0xFA
	iacSE   = 0xF0
)

type TelnetTransport struct {
	conn     net.Conn
	iacState iacDecoder
}

func (t *TelnetTransport) Connect(ctx context.Context, cfg DialConfig) error {
	d := net.Dialer{Timeout: cfg.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("connect %s: %w", cfg.Addr, err)
	}
	t.conn = conn
	return nil
}

func (t *TelnetTransport) Send(_ context.Context, data []byte) error {
	_, err := t.conn.Write(escapeIAC(data))
	return err
}

func (t *TelnetTransport) ReadUntilRe(_ context.Context, res []*regexp.Regexp, deadline time.Time) (string, int, error) {
	return t.readUntil(deadline, func(out string) int {
		for i, re := range res {
			if re.MatchString(out) {
				return i
			}
		}
		return -1
	})
}

func (t *TelnetTransport) ReadUntil(_ context.Context, patterns []string, deadline time.Time) (string, int, error) {
	return t.readUntil(deadline, func(out string) int {
		for i, p := range patterns {
			if strings.Contains(out, p) {
				return i
			}
		}
		return -1
	})
}

func (t *TelnetTransport) readUntil(deadline time.Time, match func(string) int) (string, int, error) {
	if err := t.conn.SetReadDeadline(deadline); err != nil {
		return "", -1, fmt.Errorf("set deadline: %w", err)
	}
	defer t.conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	var buf strings.Builder
	raw := make([]byte, 4096)
	for {
		n, err := t.conn.Read(raw)
		if n > 0 {
			buf.Write(t.iacState.strip(raw[:n], t.conn))
			out := buf.String()
			if i := match(out); i >= 0 {
				return out, i, nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return buf.String(), -1, fmt.Errorf("timeout waiting for prompt")
			}
			return buf.String(), -1, err
		}
	}
}

func (t *TelnetTransport) Close() error {
	if t.conn != nil { return t.conn.Close() }
	return nil
}

type iacPhase int
const (
	phaseData   iacPhase = iota
	phaseIAC
	phaseOption
	phaseSB
	phaseSBIAC
)

type iacDecoder struct{ phase iacPhase; verb byte }

func (d *iacDecoder) strip(raw []byte, conn net.Conn) []byte {
	out := make([]byte, 0, len(raw))
	for _, b := range raw {
		switch d.phase {
		case phaseData:
			if b == iacByte { d.phase = phaseIAC } else { out = append(out, b) }
		case phaseIAC:
			switch b {
			case iacByte:
				out = append(out, iacByte); d.phase = phaseData
			case iacSB:
				d.phase = phaseSB
			case iacSE:
				d.phase = phaseData
			case iacWill, iacWont, iacDo, iacDont:
				d.verb = b; d.phase = phaseOption
			default:
				d.phase = phaseData
			}
		case phaseOption:
			var resp []byte
			switch d.verb {
			case iacWill: resp = []byte{iacByte, iacDont, b}
			case iacDo:   resp = []byte{iacByte, iacWont, b}
			}
			if len(resp) > 0 && conn != nil { conn.Write(resp) } //nolint:errcheck
			d.phase = phaseData
		case phaseSB:
			if b == iacByte { d.phase = phaseSBIAC }
		case phaseSBIAC:
			if b == iacSE { d.phase = phaseData } else { d.phase = phaseSB }
		}
	}
	return out
}

func escapeIAC(b []byte) []byte {
	out := make([]byte, 0, len(b)+4)
	for _, c := range b {
		if c == iacByte { out = append(out, iacByte, iacByte) } else { out = append(out, c) }
	}
	return out
}
