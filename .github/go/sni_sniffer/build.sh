#!/bin/bash
# Build sni_sniffer for the OpenWrt architectures install.sh knows how to deploy.
# stdlib-only: no module downloads, no CGO, fully static binaries.
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
rm -f bin/sni_sniffer-linux-*

for t in "${TARGETS[@]}"; do
	set -- $t
	GOARCH_T="$1"; GOARM_T="$2"; GOMIPS_T="$3"; NAME="$4"

	# "-" means "not set": ${VAR:+…} alone would still emit GOARM=- / GOMIPS=-
	# because the placeholder is a non-empty string (same bug as probe_pool).
	GOARM_ENV=""; [ "$GOARM_T" != "-" ] && GOARM_ENV="GOARM=$GOARM_T"
	GOMIPS_ENV=""; [ "$GOMIPS_T" != "-" ] && GOMIPS_ENV="GOMIPS=$GOMIPS_T"
	# keep an explicit GOCACHE alive through env -i (see probe_pool/build.sh)
	CACHE_ENV=""; [ -n "$GOCACHE" ] && CACHE_ENV="GOCACHE=$GOCACHE"

	echo "== sni_sniffer: GOARCH=${GOARCH_T} GOARM=${GOARM_T} GOMIPS=${GOMIPS_T} -> bin/sni_sniffer-linux-${NAME}"
	env -i PATH="$PATH" HOME="$HOME" $CACHE_ENV \
		CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_T}" $GOARM_ENV $GOMIPS_ENV \
		go build -trimpath -ldflags="-s -w" -o "bin/sni_sniffer-linux-${NAME}" .
	( cd bin && zip -q -j "sni_sniffer-linux-${NAME}.zip" "sni_sniffer-linux-${NAME}" )
	ls -l "bin/sni_sniffer-linux-${NAME}"
done

echo "sni_sniffer build complete:"
ls -l bin/
