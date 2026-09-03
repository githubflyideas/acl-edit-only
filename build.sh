#!/bin/sh
# Builds the three binaries into dist/ and writes SHA256SUMS.
#
# CGO_ENABLED=0 is the whole point of this script. The SQLite driver is pure Go,
# so nothing needs a C toolchain, and a binary built with cgo enabled links
# against the glibc of whatever machine built it — a release built that way
# refused to start on the deployment host with "GLIBC_2.34 not found". Static
# binaries run on any Linux of the same architecture.
set -e
cd "$(dirname "$0")"
mkdir -p dist
for cmd in aclweb aclagent fakesw; do
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "dist/$cmd" "./cmd/$cmd"
	if ldd "dist/$cmd" >/dev/null 2>&1; then
		echo "dist/$cmd is dynamically linked; it will not run on an older glibc" >&2
		exit 1
	fi
done
cd dist && sha256sum aclweb aclagent fakesw > SHA256SUMS
cat SHA256SUMS
