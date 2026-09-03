//go:build !linux

package main

import "fmt"

func checkSecretFile(_ string) error { return fmt.Errorf("acl-agent only runs on Linux") }
func selfUID() uint32                { return 0 }
