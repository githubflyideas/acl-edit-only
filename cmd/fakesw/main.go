// Command fakesw runs the simulated H3C switch that the test suite drives, as a
// standalone process. It exists so the whole system can be tried out — submit,
// diff, execute, watch the terminal — on one machine with no switch anywhere
// near it, and so a deployment can be checked before it is pointed at real
// hardware.
//
// It is a telnet server: real IAC negotiation, real paging, real command echo.
// Nothing about it is a mock of this program's own code.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/githubflyideas/acl-edit-only/internal/h3c/fakedev"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:2300", "address to listen on")
	name := flag.String("name", "SW-CORE01", "device prompt name")
	acl := flag.Int("acl", 3977, "ACL number to serve")
	user := flag.String("user", "aclbot", "username to accept")
	pass := flag.String("pass", "aclbot-pw", "password to accept")
	rules := flag.Int("rules", 5, "number of pre-existing rules, starting at range_min")
	first := flag.Int("first-rule", 2000, "ID of the first pre-existing rule")
	flag.Parse()

	seed := make([]fakedev.Rule, 0, *rules)
	for i := 0; i < *rules; i++ {
		seed = append(seed, fakedev.Rule{
			ID:   *first + i*5,
			Body: fmt.Sprintf("permit tcp destination 10.20.%d.%d 0 destination-port eq 443", i/256, i%256),
		})
	}

	dev := fakedev.New(*name, *acl, *user, *pass, seed)
	addr, err := dev.ListenOn(*listen)
	if err != nil { log.Fatalf("fakesw: %v", err) }
	defer dev.Close()

	log.Printf("fake H3C switch on %s — acl %d, %d rules, login %s/%s",
		addr, *acl, *rules, *user, *pass)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
