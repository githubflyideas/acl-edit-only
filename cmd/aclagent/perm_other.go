//go:build !linux

package main

import (
	"fmt"
	"os"
)

func checkFilePerms(_ string, _ os.FileMode, _ uint32) error { return fmt.Errorf("acl-agent only runs on Linux") }
func checkDirPerms(_ string, _ os.FileMode, _ uint32) error  { return fmt.Errorf("acl-agent only runs on Linux") }
func selfUID() uint32                                          { return 0 }
