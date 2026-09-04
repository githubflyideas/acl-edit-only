// Package fakedev implements a fake H3C switch that speaks telnet, for tests.
//
// It is deliberately picky in the same ways a real device is: it negotiates
// telnet options, echoes commands, pages long output with "---- More ----"
// until screen-length is disabled, rejects unknown commands with the H3C
// error format, and changes its prompt with the view.
package fakedev

import (
	"net"
	"sort"
	"sync"
)

const (
	iac  = 0xFF
	will = 0xFB
	wont = 0xFC
	do   = 0xFD
	dont = 0xFE
)

// Rule is one ACL entry as the device stores it.
type Rule struct {
	ID      int
	Body    string // e.g. "permit tcp destination 10.1.1.1 0 destination-port eq 443"
	Comment string
}

// Device is a fake H3C switch.
type Device struct {
	mu       sync.Mutex
	Hostname string
	ACL      int
	Username string
	Password string
	rules    map[int]*Rule
	Saved    bool
	SaveFail bool // when true, "save" reports failure

	// OmitEmptyCount drops the "N rules," clause from the header when the ACL
	// holds nothing. Which form a given switch prints is not something this
	// project can settle from documentation, and the client has to read both, so
	// both are available to test against.
	OmitEmptyCount bool

	// PlainLineEndings makes the device end lines with CR LF instead of the CR
	// NUL LF a real switch sends. Only tests that want to read the transcript
	// byte for byte should set it.
	PlainLineEndings bool
	CmdLog   []string

	// PageLines is how many body lines fit on one screen before "---- More ----".
	PageLines int

	// NoScreenLength makes the device reject "screen-length disable", the way
	// some H3C models and restricted privilege levels do.
	NoScreenLength bool

	// ACLViewPromptPlain makes the prompt inside ACL view stay [hostname]
	// instead of naming the view. Whether a given Comware build renames the
	// prompt is not something this project can settle from documentation, and a
	// device that does not rename it must still be usable.
	ACLViewPromptPlain bool

	// ACLViewDisplayThisACL, when non-zero, is the ACL number "display this"
	// claims to be showing. It exists to model the case the prompt check is
	// there to catch: the session is in some other ACL's view.
	ACLViewDisplayThisACL int

	// LoginPromptText is the word the device uses to ask who is connecting.
	// Comware prints "Username:" on some versions and "login:" on others, and
	// which one you get also depends on how the vty is authenticated, so both
	// have to be reachable from a test. Empty means "Username:".
	LoginPromptText string

	ln net.Listener
}

// New returns a device preloaded with the given rules.
func New(hostname string, aclNum int, user, pass string, rules []Rule) *Device {
	d := &Device{
		Hostname:  hostname,
		ACL:       aclNum,
		Username:  user,
		Password:  pass,
		rules:     map[int]*Rule{},
		PageLines: 24,
	}
	for i := range rules {
		r := rules[i]
		d.rules[r.ID] = &r
	}
	return d
}

// Start listens on an arbitrary port on 127.0.0.1 and returns the address.
func (d *Device) Start() (string, error) { return d.ListenOn("127.0.0.1:0") }

// ListenOn is Start with the address chosen by the caller, for running the fake
// device as a standalone process.
func (d *Device) ListenOn(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	d.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c)
		}
	}()
	return ln.Addr().String(), nil
}

func (d *Device) Close() { if d.ln != nil { d.ln.Close() } }

// Rules returns a snapshot copy, sorted by ID.
func (d *Device) Rules() []Rule {
	d.mu.Lock()
	defer d.mu.Unlock()
	var ids []int
	for id := range d.rules { ids = append(ids, id) }
	sort.Ints(ids)
	out := make([]Rule, 0, len(ids))
	for _, id := range ids { out = append(out, *d.rules[id]) }
	return out
}

// Commands returns every command line the device received.
// SetRule adds or replaces a rule out of band, standing in for the engineer who
// edits the switch by hand between a submission and its execution.
func (d *Device) SetRule(r Rule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	copy := r
	d.rules[r.ID] = &copy
}

func (d *Device) Commands() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.CmdLog...)
}

// loginPrompt is the text the device asks for a username with.
func (d *Device) loginPrompt() string {
	if d.LoginPromptText != "" { return d.LoginPromptText }
	return "Username:"
}
