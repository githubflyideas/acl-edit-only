//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

func checkFilePerms(path string, wantMode os.FileMode, wantUID uint32) error {
	info, err := os.Stat(path)
	if err != nil { return fmt.Errorf("stat %s: %w", path, err) }
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok { return fmt.Errorf("cannot read syscall stat for %s", path) }
	if got := info.Mode().Perm(); got != wantMode {
		return fmt.Errorf("%s: mode %04o, want %04o", path, got, wantMode)
	}
	if sys.Uid != wantUID {
		return fmt.Errorf("%s: uid %d, want %d", path, sys.Uid, wantUID)
	}
	return nil
}

func checkDirPerms(path string, wantMode os.FileMode, wantUID uint32) error {
	info, err := os.Stat(path)
	if err != nil { return fmt.Errorf("stat dir %s: %w", path, err) }
	if !info.IsDir() { return fmt.Errorf("%s is not a directory", path) }
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok { return fmt.Errorf("cannot read syscall stat for %s", path) }
	if got := info.Mode().Perm(); got != wantMode {
		return fmt.Errorf("dir %s: mode %04o, want %04o", path, got, wantMode)
	}
	if sys.Uid != wantUID {
		return fmt.Errorf("dir %s: uid %d, want %d", path, sys.Uid, wantUID)
	}
	return nil
}

func selfUID() uint32 { return uint32(os.Getuid()) }
