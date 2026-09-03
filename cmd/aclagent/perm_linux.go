//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// checkSecretFile is the one permission rule that protects anything: the file
// holding the device password must belong to whoever is running this process and
// must not be readable by anybody else. Both 0400 and 0600 satisfy that; there
// is no reason to insist on one of them.
//
// The config file used to be held to the same rule. It holds no secret, so all
// that check ever did was fail a deployment for a harmless reason.
func checkSecretFile(path string) error {
	info, err := os.Stat(path)
	if err != nil { return fmt.Errorf("stat %s: %w", path, err) }
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok { return fmt.Errorf("cannot read syscall stat for %s", path) }
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s: mode %04o is readable by others, run: chmod 600 %s", path, mode, path)
	}
	if uid := selfUID(); sys.Uid != uid {
		return fmt.Errorf("%s: owned by uid %d but this process runs as uid %d, run: chown %d %s",
			path, sys.Uid, uid, uid, path)
	}
	return nil
}

func selfUID() uint32 { return uint32(os.Getuid()) }
