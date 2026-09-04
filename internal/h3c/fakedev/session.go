package fakedev

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

type conn struct {
	d    *Device
	c    net.Conn
	br   *bufio.Reader
	view string // "user", "system", "acl"
	// screenLen==0 means paging disabled
	screenLen int
}

func (d *Device) serve(c net.Conn) {
	defer c.Close()
	s := &conn{d: d, c: c, br: bufio.NewReader(c), view: "user", screenLen: d.PageLines}

	// Real devices negotiate before printing anything.
	s.raw([]byte{iac, will, 1})  // WILL ECHO
	s.raw([]byte{iac, do, 24})   // DO TERMINAL TYPE
	s.out("\r\n******************************************************************\r\n")
	s.out("* Copyright (c) 2004-2024 New H3C Technologies Co., Ltd.         *\r\n")
	s.out("******************************************************************\r\n\r\n")

	// A device with no local user account never prints "Username:". Modelling that
	// is the point: it is a supported switch configuration and the client has to
	// cope with either prompt arriving first.
	var user string
	if d.Username != "" {
		s.out("\r\n" + d.loginPrompt())
		u, err := s.readLine(true)
		if err != nil { return }
		user = u
	}
	s.out("\r\nPassword:")
	pass, err := s.readLine(false)
	if err != nil { return }
	if strings.TrimSpace(user) != d.Username || pass != d.Password {
		s.out("\r\n% Login failed.\r\n")
		s.out("\r\nPassword:")
		return
	}
	s.out("\r\n")
	s.prompt()

	for {
		line, err := s.readLine(true)
		if err != nil { return }
		cmd := strings.TrimSpace(line)
		if cmd == "" {
			s.prompt()
			continue
		}
		s.d.mu.Lock()
		s.d.CmdLog = append(s.d.CmdLog, s.view+": "+cmd)
		s.d.mu.Unlock()
		if s.handle(cmd) {
			return
		}
		s.prompt()
	}
}

// handle runs one command; returns true when the session should end.
func (s *conn) handle(cmd string) bool {
	d := s.d
	switch {
	case cmd == "quit":
		switch s.view {
		case "acl":
			s.view = "system"
		case "system":
			s.view = "user"
		default:
			s.out("\r\n")
			return true
		}
		return false

	case cmd == "screen-length disable":
		if d.NoScreenLength {
			s.errUnrecognized()
			return false
		}
		s.screenLen = 0
		return false

	case cmd == "system-view":
		if s.view != "user" {
			s.errUnrecognized()
			return false
		}
		s.out("\r\nSystem View: return to User View with Ctrl+Z.\r\n")
		s.view = "system"
		return false

	case strings.HasPrefix(cmd, "acl advanced "):
		if s.view != "system" {
			s.errUnrecognized()
			return false
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "acl advanced ")))
		if err != nil {
			s.errWrongParam()
			return false
		}
		if n != d.ACL {
			// A real device would happily create it; we refuse so a mis-bound
			// agent fails loudly in tests instead of silently editing ACL N.
			s.out("\r\n% Error: ACL " + strconv.Itoa(n) + " is not permitted in this test device.\r\n")
			return false
		}
		s.view = "acl"
		return false

	case cmd == "display this" || cmd == "dis this":
		if s.view != "acl" {
			s.errUnrecognized()
			return false
		}
		s.displayThis()
		return false

	case strings.HasPrefix(cmd, "display acl "):
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "display acl ")))
		if err != nil {
			s.errWrongParam()
			return false
		}
		s.displayACL(n)
		return false

	case strings.HasPrefix(cmd, "rule "):
		if s.view != "acl" {
			s.errUnrecognized()
			return false
		}
		s.ruleCmd(strings.TrimPrefix(cmd, "rule "))
		return false

	case strings.HasPrefix(cmd, "undo rule "):
		if s.view != "acl" {
			s.errUnrecognized()
			return false
		}
		id, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(cmd, "undo rule ")))
		if err != nil {
			s.errWrongParam()
			return false
		}
		d.mu.Lock()
		delete(d.rules, id)
		d.mu.Unlock()
		return false

	case cmd == "save" || cmd == "save force":
		if s.view != "user" && s.view != "system" {
			s.errUnrecognized()
			return false
		}
		if d.SaveFail {
			s.out("\r\n% Error: Failed to save the configuration.\r\n")
			return false
		}
		d.mu.Lock()
		d.Saved = true
		d.mu.Unlock()
		s.out("\r\nValidating file. Please wait.......\r\n")
		s.out("Configuration is saved to device successfully.\r\n")
		return false
	}
	s.errUnrecognized()
	return false
}

// displayThis prints the ACL view's own configuration, the way "display this"
// does. It is the only positive evidence of which view a session is in when the
// prompt does not carry the ACL number.
func (s *conn) displayThis() {
	d := s.d
	num := d.ACL
	if d.ACLViewDisplayThisACL != 0 { num = d.ACLViewDisplayThisACL }
	s.out("\r\n#\r\n")
	s.out(fmt.Sprintf("acl number %d\r\n", num))
	d.mu.Lock()
	ids := make([]int, 0, len(d.rules))
	for id := range d.rules { ids = append(ids, id) }
	sort.Ints(ids)
	for _, id := range ids {
		r := d.rules[id]
		s.out(fmt.Sprintf(" rule %d %s\r\n", id, r.Body))
		if r.Comment != "" { s.out(fmt.Sprintf(" rule %d comment %s\r\n", id, r.Comment)) }
	}
	d.mu.Unlock()
	s.out("#\r\nreturn\r\n")
}

func (s *conn) ruleCmd(rest string) {
	d := s.d
	sp := strings.SplitN(strings.TrimSpace(rest), " ", 2)
	if len(sp) != 2 {
		s.errIncomplete()
		return
	}
	id, err := strconv.Atoi(sp[0])
	if err != nil {
		s.errWrongParam()
		return
	}
	body := strings.TrimSpace(sp[1])
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.HasPrefix(body, "comment ") {
		r, ok := d.rules[id]
		if !ok {
			s.out("\r\n% Error: The rule does not exist.\r\n")
			return
		}
		r.Comment = strings.TrimPrefix(body, "comment ")
		return
	}
	if !strings.HasPrefix(body, "permit ") && !strings.HasPrefix(body, "deny ") {
		s.errWrongParam()
		return
	}
	if _, ok := d.rules[id]; ok {
		// H3C silently merges into an existing rule; that is exactly the
		// situation the in-session guard must prevent, so record it plainly.
		d.rules[id].Body = body
		return
	}
	d.rules[id] = &Rule{ID: id, Body: body}
	d.Saved = false
}

// displayACL renders output in H3C's format, paging if screen-length is on.
func (s *conn) displayACL(n int) {
	d := s.d
	if n != d.ACL {
		s.out("\r\n")
		return
	}
	rules := d.Rules()
	var lines []string
	if len(rules) == 0 && d.OmitEmptyCount {
		lines = append(lines, fmt.Sprintf("Advanced IPv4 ACL %d, named -,", d.ACL))
	} else {
		lines = append(lines, fmt.Sprintf("Advanced IPv4 ACL %d, named -, %d rule%s,",
			d.ACL, len(rules), plural(len(rules))))
	}
	lines = append(lines, "ACL's step is 5")
	for _, r := range rules {
		lines = append(lines, fmt.Sprintf(" rule %d %s", r.ID, r.Body))
		if r.Comment != "" {
			lines = append(lines, fmt.Sprintf(" rule %d comment %s", r.ID, r.Comment))
		}
	}
	s.out("\r\n")
	shown := 0
	for _, l := range lines {
		s.out(l + "\r\n")
		shown++
		if s.screenLen > 0 && shown%s.screenLen == 0 && shown < len(lines) {
			s.out("  ---- More ----")
			if !s.waitMore() {
				return
			}
			// The device erases the More marker with CR + spaces.
			s.out("\r              \r")
		}
	}
}

// waitMore blocks for the operator's key. Space = next page, q = abort.
func (s *conn) waitMore() bool {
	for {
		b, err := s.readByte()
		if err != nil { return false }
		switch b {
		case ' ':
			return true
		case 'q', 'Q', 0x03:
			s.out("\r\n")
			return false
		case '\r', '\n':
			return true // enter advances one line; close enough
		}
	}
}

func plural(n int) string { if n == 1 { return "" }; return "s" }

func (s *conn) prompt() {
	switch s.view {
	case "system":
		s.out(fmt.Sprintf("[%s]", s.d.Hostname))
	case "acl":
		if s.d.ACLViewPromptPlain {
			s.out(fmt.Sprintf("[%s]", s.d.Hostname))
			return
		}
		s.out(fmt.Sprintf("[%s-acl-ipv4-adv-%d]", s.d.Hostname, s.d.ACL))
	default:
		s.out(fmt.Sprintf("<%s>", s.d.Hostname))
	}
}

func (s *conn) errUnrecognized() {
	s.out("\r\n              ^\r\n% Unrecognized command found at '^' position.\r\n")
}
func (s *conn) errWrongParam() {
	s.out("\r\n              ^\r\n% Wrong parameter found at '^' position.\r\n")
}
func (s *conn) errIncomplete() {
	s.out("\r\n% Incomplete command found at '^' position.\r\n")
}

// ─── wire I/O ────────────────────────────────────────────────────

// out writes device text. A real H3C switch ends every line CR NUL LF — telnet's
// spelling of a carriage return that is not itself a line ending — so that is
// what this writes unless the test asked for plain CR LF.
func (s *conn) out(text string) {
	if !s.d.PlainLineEndings { text = strings.ReplaceAll(text, "\r\n", "\r\x00\n") }
	s.raw(escape([]byte(text)))
}

func (s *conn) raw(b []byte) { s.c.Write(b) } //nolint:errcheck

func escape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == iac { out = append(out, iac, iac) }
		out = append(out, c)
	}
	return out
}

// readByte returns the next data byte, consuming telnet option negotiation.
func (s *conn) readByte() (byte, error) {
	for {
		b, err := s.br.ReadByte()
		if err != nil { return 0, err }
		if b != iac { return b, nil }
		verb, err := s.br.ReadByte()
		if err != nil { return 0, err }
		switch verb {
		case iac:
			return iac, nil
		case will, wont, do, dont:
			if _, err := s.br.ReadByte(); err != nil { return 0, err }
		}
	}
}

// readLine reads until CR or LF. When echo is set the typed characters are
// echoed back, which is what a real H3C does after IAC WILL ECHO — and it is
// the only reason the operator watching the terminal sees the commands at all.
// The password is read with echo off, the way the device suppresses it.
func (s *conn) readLine(echo bool) (string, error) {
	var sb strings.Builder
	for {
		b, err := s.readByte()
		if err != nil { return "", err }
		switch b {
		case '\r':
			// Swallow a following LF or NUL if present.
			if nb, err := s.br.Peek(1); err == nil && len(nb) == 1 && (nb[0] == '\n' || nb[0] == 0) {
				s.br.ReadByte() //nolint:errcheck
			}
			if echo { s.raw([]byte("\r\n")) }
			return sb.String(), nil
		case '\n':
			if echo { s.raw([]byte("\r\n")) }
			return sb.String(), nil
		case 0x7f, 0x08:
			cur := sb.String()
			if cur != "" {
				sb.Reset()
				sb.WriteString(cur[:len(cur)-1])
				if echo { s.raw([]byte("\b \b")) }
			}
		default:
			sb.WriteByte(b)
			if echo { s.raw(escape([]byte{b})) }
		}
	}
}
