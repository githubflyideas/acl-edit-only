// Package cfgpath resolves the paths named inside a configuration file, so that
// a whole deployment can be unpacked into any single directory and moved around
// later without editing anything.
package cfgpath

import (
	"os"
	"path/filepath"
)

// Resolve makes p absolute. A relative p is taken as relative to baseDir — the
// directory holding the config file that named it — and not to whatever working
// directory the process happened to be started from. That distinction is the
// whole point: it lets a config say "plans" and mean the plans directory sitting
// beside it, whether the service was launched from a shell, from systemd, or
// from a double-click.
func Resolve(baseDir, p string) string {
	if p == "" { return "" }
	if filepath.IsAbs(p) { return p }
	return filepath.Join(baseDir, p)
}

// Sibling returns the path of a file sitting next to the running executable,
// which is where the other half of this pair of binaries is expected to be.
func Sibling(name string) string {
	exe, err := os.Executable()
	if err != nil { return name }
	return filepath.Join(filepath.Dir(exe), name)
}
