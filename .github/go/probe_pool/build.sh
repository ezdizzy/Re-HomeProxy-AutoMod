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

	echo "== probe_pool: GOARCH=${GOARCH_T} GOARM=${GOARM_T} GOMIPS=${GOMIPS_T} -> bin/probe_pool-linux-${NAME}"
	env -i PATH="$PATH" HOME="$HOME" \
		CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH_T}" \
		${GOARM_T:+GOARM=$GOARM_T} ${GOMIPS_T:+GOMIPS=$GOMIPS_T} \
		go build -trimpath -ldflags="-s -w" -o "bin/probe_pool-linux-${NAME}" .
	( cd bin && zip -q -j "probe_pool-linux-${NAME}.zip" "probe_pool-linux-${NAME}" )
	ls -l "bin/probe_pool-linux-${NAME}"
done

echo "probe_pool build complete:"
ls -l bin/
