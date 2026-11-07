#!/bin/bash
# Build utls_probe for the OpenWrt architectures install.sh knows how to deploy.
# ONE third-party dependency: refraction-networking/utls (browser ClientHello
# fingerprints — the whole point of this probe; crypto/tls cannot impersonate
# a browser). go.sum is committed; CI/runner needs network for the module cache.
set -e

cd "$(dirname "$0")"

# tuples: GOARCH GOARM GOMIPS asset-suffix
TARGETS=(
	"arm64 - - arm64"
	"amd64 - - amd64"
	"mipsle - softfloat mipsle-softfloat"
	"mips - softfloat mips-softfloat"
	"arm 7 - armv7"
	"arm 6 - armv6"
	"riscv64 - - riscv64"
)

mkdir -p bin
rm -f bin/utls_probe-linux-*

for t in "${TARGETS[@]}"; do
	set -- $t
	GOARCH_T="$1"; GOARM_T="$2"; GOMIPS_T="$3"; NAME="$4"

# "-" means "not set" (same bug as probe_pool build.sh, CI runs #95/#96).
GOARM_ENV=""; [ "$GOARM_T" != "-" ] && GOARM_ENV="GOARM=$GOARM_T"
GOMIPS_ENV=""; [ "$GOMIPS_T" != "-" ] && GOMIPS_ENV="GOMIPS=$GOMIPS_T"
CACHE_ENV=""; [ -n "$GOCACHE" ] && CACHE_ENV="GOCACHE=$GOCACHE"

echo "== utls_probe: GOARCH=${GOARCH_T} GOARM=${GOARM_T} GOMIPS=${GOMIPS_T} -> bin/utls_probe-linux-${NAME}"
env -i PATH="$PATH" HOME="$HOME" $CACHE_ENV \
	CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_T}" $GOARM_ENV $GOMIPS_ENV \
	go build -trimpath -ldflags="-s -w" -o "bin/utls_probe-linux-${NAME}" .
	( cd bin && zip -q -j "utls_probe-linux-${NAME}.zip" "utls_probe-linux-${NAME}" )
	ls -l "bin/utls_probe-linux-${NAME}"
done

echo "utls_probe build complete:"
ls -l bin/
