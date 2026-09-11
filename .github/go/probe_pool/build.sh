#!/bin/bash
# Build probe_pool for the OpenWrt architectures install.sh knows how to deploy.
# stdlib-only: no module downloads, no CGO, fully static binaries.
set -e

cd "$(dirname "$0")"

# tuples: GOARCH GOARM GOMIPS asset-suffix
TARGETS=(
	"arm64 - - arm64"
	"amd64 - - amd64"
	"mipsle - softfloat mipsle-softfloat"
	"arm 7 - armv7"
	"arm 6 - armv6"
)

mkdir -p bin
rm -f bin/probe_pool-linux-*

for t in "${TARGETS[@]}"; do
	set -- $t
	GOARCH_T="$1"; GOARM_T="$2"; GOMIPS_T="$3"; NAME="$4"

# "-" means "not set": ${VAR:+…} alone would still emit GOARM=- / GOMIPS=-
# because the placeholder is a non-empty string (broke CI runs #95/#96).
GOARM_ENV=""; [ "$GOARM_T" != "-" ] && GOARM_ENV="GOARM=$GOARM_T"
GOMIPS_ENV=""; [ "$GOMIPS_T" != "-" ] && GOMIPS_ENV="GOMIPS=$GOMIPS_T"
# keep an explicit GOCACHE alive through env -i (linux runners get the
# HOME default anyway; Windows contributors need it passed explicitly)
CACHE_ENV=""; [ -n "$GOCACHE" ] && CACHE_ENV="GOCACHE=$GOCACHE"

echo "== probe_pool: GOARCH=${GOARCH_T} GOARM=${GOARM_T} GOMIPS=${GOMIPS_T} -> bin/probe_pool-linux-${NAME}"
env -i PATH="$PATH" HOME="$HOME" $CACHE_ENV \
	CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_T}" $GOARM_ENV $GOMIPS_ENV \
	go build -trimpath -ldflags="-s -w" -o "bin/probe_pool-linux-${NAME}" .
	( cd bin && zip -q -j "probe_pool-linux-${NAME}.zip" "probe_pool-linux-${NAME}" )
	ls -l "bin/probe_pool-linux-${NAME}"
done

echo "probe_pool build complete:"
ls -l bin/
