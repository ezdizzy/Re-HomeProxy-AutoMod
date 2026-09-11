#!/bin/bash
# Build the native automation helpers (probe_pool, sni_sniffer) for every
# OpenWrt architecture install.sh can deploy, and upload-ready zips.
# Go source trees live in .github/go/<tool> so they are never packaged into
# the apk/ipk itself (the app package is arch-independent: binaries are
# downloaded from the release assets by install.sh on the router).
set -e

BASE_DIR="$(cd "$(dirname "$0")"; pwd)"
GO_DIR="$BASE_DIR/go"
OUT_DIR="$BASE_DIR/binaries"

command -v go >/dev/null 2>&1 || { echo "build-go.sh: go toolchain not found" >&2; exit 1; }

# Unit tests run natively on the runner (linux/amd64) — the SNI parser and the
# request/verdict plumbing are covered there.
echo "== go test (host) =="
for d in "$GO_DIR"/*/; do
	pushd "$d" >/dev/null
	go vet ./...
	go test -count=1 ./... || { echo "tests FAILED in $d" >&2; exit 1; }
	popd >/dev/null
done

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for d in "$GO_DIR"/*/; do
	tool="$(basename "$d")"
	echo "== build $tool =="
	pushd "$d" >/dev/null
	# build.sh writes bin/<tool>-linux-<arch>[.zip]; copy into the shared out dir
	bash build.sh
	cp -f bin/* "$OUT_DIR/"
	popd >/dev/null
done

echo "== built artifacts =="
ls -l "$OUT_DIR"
