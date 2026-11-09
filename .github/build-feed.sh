#!/usr/bin/env bash
# build-feed.sh — build the Ravnex package feed (§1.7 "own package repository", Ф11 V2).
#
# Produces a tree of signed apk v3 packages + ipk packages + a client manifest
# per OpenWrt arch label, hosted on the feed branch (raw.githubusercontent):
#
#   <out>/ravnex-feed.pub                        # public key (client: /etc/apk/keys/)
#   <out>/versions.txt                           # pkg<TAB>version<TAB>arch — change-guard
#   <out>/releases/<series>/<arch>/packages.adb  # signed index (apk tooling/humans)
#   <out>/releases/<series>/<arch>/manifest.json # CLIENT CONTRACT (Ф11 V2)
#   <out>/releases/<series>/<arch>/<pkg>.apk     # signed apk v3 packages
#   <out>/releases/<series>/<arch>/<pkg>.ipk     # ipk packages (opkg systems)
#
# ── V2 CONTRACT (session 150, decisions D-F11.150) ──────────────────────────
# The client NEVER resolves through repositories: it does NOT write a
# repositories.d line (a foreign feed could then out-version our components
# via `apk upgrade`). It downloads the exact file named by manifest.json and
# installs it explicitly (`apk add ./x.apk` — signature checked against our
# key; `opkg install ./x.ipk` — sha256 checked against the manifest).
# packages.adb is still built for apk tooling and humans; the client reads
# manifest.json only.
#
# Components (ч.265 «ВСЁ ИЗ ОРИГИНАЛЬНЫХ РЕПОЗИТОРИЕВ» — де-форк/де-фид ядер):
#   OUR BUILDS (upstream raw binaries, packaged by us, $VER-$REV):
#     mosdns                                      IrineSistiana/mosdns zip
#     probe_pool, sni_sniffer                     our Go helpers from release zips
#   OUR PACKAGING OF ORIGINAL BINARIES (decision 5: engines with no upstream
#   OpenWrt packages are packaged by US from the ORIGINAL static binaries):
#     byedpi        hufrea/byedpi static tarball  → our apk+ipk
#     zapret2       bol-van/zapret2 openwrt-embedded tar.gz → our apk+ipk
#
# The PROXY CORES left the feed completely: hiddify/hiddify-core publishes
# OpenWrt apk+ipk itself (v5.4.0+), sing-box-extended = shtorm-7 apk+ipk,
# lite = MANCrimSon tarballs — the app installs them straight from the
# originals (SHA256 API-digest gate), so building/mirroring them here would
# be a second uncontrolled source. feed-first for cores is REMOVED from the
# client as well (core_mgmt.uc, seance 177).
#
# arch→asset tables mirror the app exactly (core_mgmt.uc GOARCH maps,
# luci.ravnex byedpi/zapret2 maps) so a feed package exists wherever the
# app knows how to run the component. Labels with no upstream asset simply
# omit that component from the arch's manifest.
#
# Requirements: apk (apk-tools v3 with mkpkg/mkndx, host build), jq,
# curl, tar, unzip, openssl. The signing key comes from APK_SIGN_KEY (path);
# when empty an unsigned feed is built (client needs --allow-untrusted then —
# the app's feed_status reports the honest state).

set -euo pipefail

OUT=${1:?usage: build-feed.sh <out-dir>}
mkdir -p "$OUT"
SERIES=${FEED_SERIES:-25.12}
REV=${FEED_REV:-r1}
ARCHS=${FEED_ARCHS:-aarch64_generic,aarch64_cortex-a53,aarch64_cortex-a72,aarch64_cortex-a76,x86_64,arm_cortex-a7_neon-vfpv4,arm_cortex-a9_neon,mipsel_24kc,mips_24kc}
GHAPI='https://api.github.com'
GHDL='https://github.com'
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── arch → upstream asset tables (mirrors of the app's own maps) ─────────────
mosdns_asset() {
	case "$1" in
	aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72|aarch64_cortex-a76) echo 'mosdns-linux-arm64.zip';;
	arm_cortex-a7_neon-vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a9_neon|arm_cortex-a7_vfpv4|arm_cortex-a8_vfpv3|arm_cortex-a15_neon-vfpv4) echo 'mosdns-linux-arm-7.zip';;
	arm_cortex-a5_vfpv4|arm_arm926ej-s) echo 'mosdns-linux-arm-6.zip';;
	x86_64) echo 'mosdns-linux-amd64.zip';;
	mipsel_24kc|mipsel_74kc) echo 'mosdns-linux-mipsle-softfloat.zip';;
	*) return 1;;
	esac
}
helper_asset() {
	case "$1" in
	aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72|aarch64_cortex-a76) echo 'arm64';;
	arm_cortex-a7_neon-vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a9_neon|arm_cortex-a7_vfpv4|arm_cortex-a15_neon-vfpv4) echo 'armv7';;
	arm_cortex-a5_vfpv4|arm_arm926ej-s|arm_fa526) echo 'armv6';;
	x86_64) echo 'amd64';;
	mipsel_24kc|mipsel_74kc) echo 'mipsle-softfloat';;
	mips_24kc|mips_74kc|mips_mips32) echo 'mips-softfloat';;
	riscv64_generic) echo 'riscv64';;
	*) return 1;;
	esac
}
# hufrea/byedpi static tarballs use Go arch names with the leading "0."
# dropped from the version (0.17.3 → 17.3). Mirror of rpcd BD_MAP.
byedpi_goarch() {
	case "$1" in
	aarch64*) echo 'aarch64';;
	arm_arm1176jzf-s_vfp) echo 'armv6';;
	arm_cortex-a*) echo 'armv7l';;
	x86_64) echo 'x86_64';;
	i386_pentium4) echo 'i686';;
	mipsel*) echo 'mipsel';;
	mips*) echo 'mips';;
	powerpc*) echo 'powerpc';;
	*) return 1;;
	esac
}
# bol-van/zapret2 openwrt-embedded carries binaries/linux-<dir>/. Mirror of
# rpcd Z2_MAP.
zapret2_dir() {
	case "$1" in
	aarch64*) echo 'linux-arm64';;
	arm_cortex-a*) echo 'linux-arm';;
	x86_64) echo 'linux-x86_64';;
	i386_pentium4) echo 'linux-x86';;
	mipsel_24kc_24kf) echo 'linux-mipsel';;
	mipsel*) echo 'linux-mipsel';;
	mips64*) echo 'linux-mips64';;
	mips*) echo 'linux-mips';;
	riscv64*) echo 'linux-riscv64';;
	powerpc*) echo 'linux-ppc';;
	*) return 1;;
	esac
}

IFS=',' read -r -a ARCH_LIST <<< "$ARCHS"

# Session 161: upstream edge flakes (503/504 Unicorn) killed whole runs with
# exit 9 (unzip "cannot find") after one asset exhausted curl's built-in
# --retry (4 quick attempts, ch.244). Shell-level retry ladder with a real
# backoff on top of curl's own retries.
fetch() {
	local url=$1 out=$2 attempt
	for attempt in 1 2 3; do
		if curl -fsSL --retry 3 --retry-delay 3 -o "$out" "$url"; then
			return 0
		fi
		echo "fetch: attempt $attempt/3 failed for $url" >&2
		sleep $((attempt * 8))
	done
	return 1
}

tag_of() {
	local repo=$1 body tag attempt
	for attempt in 1 2 3; do
		# capture first: a piped `curl | jq` hides curl's exit status and an
		# empty body would silently yield an empty tag -> broken pkg versions
		if body=$(curl -fsSL --retry 3 --retry-delay 3 "$GHAPI/repos/$repo/releases/latest" 2>/dev/null); then
			tag=$(printf '%s' "$body" | jq -r '.tag_name')
			[ -n "$tag" ] && [ "$tag" != "null" ] && { printf '%s' "$tag"; return 0; }
		fi
		echo "tag_of: attempt $attempt/3 failed for $repo" >&2
		sleep $((attempt * 8))
	done
	return 1
}

echo "── versions ──────────────────────────────────────────────"
MOS_TAG=$(tag_of IrineSistiana/mosdns);                 MOS_VER=${MOS_TAG#v}
HELP_TAG=$(tag_of ezdizzy/ravnex);                HELP_VER=${HELP_TAG#v}
BYD_TAG=$(tag_of hufrea/byedpi);                        BYD_VER=${BYD_TAG#v}
Z2_TAG=$(tag_of bol-van/zapret2);                       Z2_VER=${Z2_TAG#v}
echo "mosdns=$MOS_VER helpers=$HELP_VER byedpi=$BYD_VER zapret2=$Z2_VER rev=$REV series=$SERIES"
# Session 161: an exhausted ladder must abort, not package empty versions.
for v in "$MOS_VER" "$HELP_VER" "$BYD_VER" "$Z2_VER"; do
	[ -n "$v" ] || { echo "ERROR: an upstream tag resolve failed (see above) - aborting"; exit 1; }
done

# ── download unique source payloads once (cache per asset) ───────────────────
mkdir -p "$WORK/src"
fetch_bin() { # <url> <cachefile>
	local f="$WORK/src/$(basename "$2")"
	[ -s "$f" ] || fetch "$1" "$f"
	echo "$f"
}

# ── packaging primitives ─────────────────────────────────────────────────────
PUB_DIR="$WORK/pub"; mkdir -p "$PUB_DIR"
if [ -n "${APK_SIGN_KEY:-}" ] && [ -s "$APK_SIGN_KEY" ]; then
	openssl rsa -in "$APK_SIGN_KEY" -pubout -out "$OUT/ravnex-feed.pub" 2>/dev/null || \
	openssl ec  -in "$APK_SIGN_KEY" -pubout -out "$OUT/ravnex-feed.pub" 2>/dev/null || {
		echo "ERROR: APK_SIGN_KEY is set but openssl cannot read it (tried rsa and ec) - refusing to build a silently unsigned feed"; exit 1;
	}
	SIGN_ARGS=(--sign-key "$APK_SIGN_KEY")
else
	echo "WARNING: APK_SIGN_KEY empty — building an UNSIGNED feed"
	SIGN_ARGS=()
fi
[ -s "$OUT/ravnex-feed.pub" ] && cp "$OUT/ravnex-feed.pub" "$PUB_DIR/ravnex-feed.pub" || true

pkg() { # <stageroot> <name> <version> <arch> <descr> <out.apk>
	local root=$1 name=$2 ver=$3 arch=$4 descr=$5 o=$6
	mkdir -p "$WORK/idroot/etc"
	printf 'root:x:0:0:root:/root:/bin/sh\n' > "$WORK/idroot/etc/passwd"
	printf 'root:x:0:\n' > "$WORK/idroot/etc/group"
	apk --root "$WORK/idroot" mkpkg --no-xattrs \
		--info "name:$name" --info "version:$ver" --info "arch:$arch" \
		--info "description:$descr" \
		--info "url:https://github.com/ezdizzy/ravnex" \
		--info "maintainer:Ravnex feed <https://github.com/ezdizzy/ravnex>" \
		--info "depends:libc" \
		--info "origin:ravnex-feed" \
		${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} \
		--files "$root" --output "$o"
}

ipk_build() { # <control-file> <dataroot> <out.ipk> — OpenWrt ipk (tar.gz of 3 members)
	local ctl=$1 root=$2 o=$3
	local M="$WORK/ipkbuild"; rm -rf "$M"; mkdir -p "$M"
	printf '2.0\n' > "$M/debian-binary"
	cp "$ctl" "$M/control"
	tar -czf "$M/control.tar.gz" -C "$M" control
	tar -czf "$M/data.tar.gz" -C "$root" .
	tar -czf "$o" -C "$M" debian-binary control.tar.gz data.tar.gz
}

# unpack a foreign OpenWrt ipk: control + data staging (deterministic format)
unpack_ipk() { # <file.ipk> <ctrldir> <datadir>
	local f=$1 c=$2 d=$3
	rm -rf "$c" "$d" "$WORK/ipkx"; mkdir -p "$c" "$d" "$WORK/ipkx"
	tar -xzf "$f" -C "$WORK/ipkx" || return 1
	local ctgz dtgz
	ctgz=$(find "$WORK/ipkx" -name 'control.tar.gz' | head -1)
	dtgz=$(find "$WORK/ipkx" -name 'data.tar.gz' | head -1)
	[ -n "$ctgz" ] && [ -n "$dtgz" ] || return 1
	tar -xzf "$ctgz" -C "$c" || return 1
	tar -xzf "$dtgz" -C "$d" || return 1
}

MANIFESTS="$WORK/manifests"; mkdir -p "$MANIFESTS"
VERSIONS="$OUT/versions.txt"; : > "$VERSIONS"

manifest_add() { # <arch> <json-line>
	echo "$2" >> "$MANIFESTS/$1.jsonl"
}
versions_add() { # <pkg> <ver> <arch>
	printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$VERSIONS"
}

# repack a foreign ipk into OUR apk+ipk (name/version/depends preserved)
san_ver() { # <ver> <pkgname> -> apk-valid version (apk-tools grammar: digit{.digit}...{letter}{_suf#}...{~hex}{-r#})
	local v=$1 pkg=$2
	if printf '%s' "$v" | grep -qE '^[0-9]+(\.[0-9]+)*[a-z]?(_(alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*(~[0-9a-fA-F]+)?(-r[0-9]+)?$'; then
		printf '%s' "$v"; return
	fi
	local core tail digits
	core=$(printf '%s' "$v" | grep -oE '^[0-9]+(\.[0-9]+)*' | head -1)
	tail=${v#"$core"}
	digits=$(printf '%s' "$tail" | tr -dc '0-9')
	[ -n "$digits" ] || digits=1
	echo "NOTE $pkg $v: version is not valid for the apk v3 grammar (mkpkg rejects it) - mapped to ${core}-r${digits}, the upstream verbatim goes to the description" >&2
	printf '%s' "${core}-r${digits}"
}

repack_ipk() { # <src.ipk> <arch> <descr>
	local src=$1 arch=$2 descr=$3
	local c="$WORK/rc" d="$WORK/rd"
	unpack_ipk "$src" "$c" "$d" || { echo "SKIP repack $(basename "$src") $arch (not an ipk?)"; return 1; }
	[ -s "$c/control" ] || { echo "SKIP repack $(basename "$src") $arch (no control)"; return 1; }
	local name ver orig
	name=$(sed -n 's/^Package:[[:space:]]*//p' "$c/control" | head -1 | tr -d ' \r')
	orig=$(sed -n 's/^Version:[[:space:]]*//p'  "$c/control" | head -1 | tr -d ' \r')
	[ -n "$name" ] && [ -n "$orig" ] || { echo "SKIP repack $(basename "$src") $arch (no Package/Version)"; return 1; }
	ver=$(san_ver "$orig" "$name")
	sed -i "s/^Version:.*/Version: $ver/" "$c/control"
	[ "$ver" = "$orig" ] || descr="$descr (upstream version $orig)"
	local scripts=""
	grep -qE '^(pre|post)inst' <(find "$c" -maxdepth 1 -type f -printf '%f\n') && \
		scripts=" (foreign maintainer scripts NOT carried — review: $(find "$c" -maxdepth 1 -type f -not -name control -printf '%f ' ))"
	[ -n "$scripts" ] && echo "NOTE $name $orig: foreign control scripts present:$scripts"
	local D="$OUT/releases/$SERIES/$arch"; mkdir -p "$D"
	pkg  "$d" "$name" "$ver" "$arch" "$descr" "$D/$name-$ver.apk" || { echo "SKIP repack $name $arch (mkpkg failed)"; return 1; }
	ipk_build "$c/control" "$d" "$D/$name-$ver.ipk" || { echo "SKIP repack $name $arch (ipk_build failed)"; return 1; }
	local sha_a sha_i
	sha_a=$(sha256sum "$D/$name-$ver.apk" | cut -d' ' -f1)
	sha_i=$(sha256sum "$D/$name-$ver.ipk" | cut -d' ' -f1)
	manifest_add "$arch" "\"$name\":{\"version\":\"$ver\",\"upstream\":\"$orig\",\"apk\":\"$name-$ver.apk\",\"apk_sha256\":\"$sha_a\",\"ipk\":\"$name-$ver.ipk\",\"ipk_sha256\":\"$sha_i\"}"
	versions_add "$name" "$ver" "$arch"
	echo "REPACKED $name $ver ($arch) ← $(basename "$src")"
}

# package OUR OWN binary payload into apk+ipk (+manifest)
own_pkg() { # <stageroot> <name> <ver> <arch> <descr>
	local root=$1 name=$2 ver=$3 arch=$4 descr=$5
	ver=$(san_ver "$ver" "$name")
	local D="$OUT/releases/$SERIES/$arch"; mkdir -p "$D"
	pkg "$root" "$name" "$ver" "$arch" "$descr" "$D/$name-$ver.apk" || { echo "SKIP $name $arch (mkpkg failed)"; return 1; }
	local M="$WORK/ownctl"; rm -rf "$M"; mkdir -p "$M"
	printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Ravnex feed <https://github.com/ezdizzy/ravnex>\nDepends: libc\nDescription: %s\n' "$name" "$ver" "$arch" "$descr" > "$M/control"
	ipk_build "$M/control" "$root" "$D/$name-$ver.ipk"
	local sha_a sha_i
	sha_a=$(sha256sum "$D/$name-$ver.apk" | cut -d' ' -f1)
	sha_i=$(sha256sum "$D/$name-$ver.ipk" | cut -d' ' -f1)
	manifest_add "$arch" "\"$name\":{\"version\":\"$ver\",\"apk\":\"$name-$ver.apk\",\"apk_sha256\":\"$sha_a\",\"ipk\":\"$name-$ver.ipk\",\"ipk_sha256\":\"$sha_i\"}"
	versions_add "$name" "$ver" "$arch"
}

for A in "${ARCH_LIST[@]}"; do
	echo "── arch $A ────────────────────────────────────────────────"
	D="$OUT/releases/$SERIES/$A"; mkdir -p "$D"
	MA=$(mosdns_asset "$A" || true)
	GA=$(helper_asset "$A" || true)
	BG=$(byedpi_goarch "$A" || true)
	ZD=$(zapret2_dir "$A" || true)

	if [ -n "${MA:-}" ]; then
		SRC=$(fetch_bin "$GHDL/IrineSistiana/mosdns/releases/latest/download/$MA" "$MA" || true)
		if [ -n "${SRC:-}" ]; then
			rm -rf "$WORK/x" "$WORK/root"; mkdir -p "$WORK/x" "$WORK/root/usr/bin"; unzip -qo "$SRC" -d "$WORK/x"
			BIN=$(find "$WORK/x" -type f -name 'mosdns' | head -1)
			if [ -n "${BIN:-}" ]; then
				mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/mosdns"; chmod 755 "$WORK/root/usr/bin/mosdns"
				own_pkg "$WORK/root" mosdns "$MOS_VER-$REV" "$A" "Ravnex mosdns (MultiDNS racing resolver)"
			fi
		fi
	fi
	if [ -n "${GA:-}" ]; then
		for T in probe_pool sni_sniffer; do
			SRC=$(fetch_bin "$GHDL/ezdizzy/ravnex/releases/latest/download/$T-linux-$GA.zip" "$T-$GA.zip" || true)
			if [ -n "${SRC:-}" ]; then
				rm -rf "$WORK/x" "$WORK/root"; mkdir -p "$WORK/x" "$WORK/root/usr/bin"; unzip -qo "$SRC" -d "$WORK/x"
				# release zips carry the binary named with the platform suffix
				# (probe_pool-linux-arm64), not bare "$T" - runs 6-8 skipped the
				# helpers silently when -name "$T" matched nothing
				BIN=$(find "$WORK/x" -type f \( -name "$T" -o -name "$T-linux-*" \) | head -1)
				if [ -n "${BIN:-}" ]; then
					mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/$T"; chmod 755 "$WORK/root/usr/bin/$T"
					own_pkg "$WORK/root" "$T" "$HELP_VER-$REV" "$A" "Ravnex $T (native automation helper)" || echo "SKIP $T $A (packaging failed)"
				else
					echo "SKIP $T $GA (no $T binary in the release zip)"
				fi
			fi
		done
	fi

	# ── engines: OUR packages built from the ORIGINAL upstream binaries ──────
	# (decision 5, seance 177: byedpi/zapret2 have no upstream OpenWrt packages
	# — we package the original static binaries ourselves; no more 1andrevich
	# mirrors. The proxies' own cores left the feed entirely.)
	if [ -n "${BG:-}" ]; then
		BV2=${BYD_VER#0.}   # hufrea drops the leading "0." in asset names
		SRC=$(fetch_bin "$GHDL/hufrea/byedpi/releases/download/$BYD_TAG/byedpi-$BV2-$BG.tar.gz" "byedpi-$BG.tar.gz" || true)
		if [ -n "${SRC:-}" ]; then
			rm -rf "$WORK/x" "$WORK/root"; mkdir -p "$WORK/x" "$WORK/root/usr/bin"; tar -xzf "$SRC" -C "$WORK/x"
			BIN=$(find "$WORK/x" -type f -name 'ciadpi*' | head -1)
			if [ -n "${BIN:-}" ]; then
				cp "$BIN" "$WORK/root/usr/bin/ciadpi"; chmod 755 "$WORK/root/usr/bin/ciadpi"
				own_pkg "$WORK/root" byedpi "$BYD_VER-$REV" "$A" "Ravnex byedpi (upstream hufrea static build $BYD_VER)"
			else
				echo "SKIP byedpi $A (no ciadpi binary in tarball)"
			fi
		fi
	fi
	if [ -n "${ZD:-}" ]; then
		SRC=$(fetch_bin "$GHDL/bol-van/zapret2/releases/download/$Z2_TAG/zapret2-$Z2_TAG-openwrt-embedded.tar.gz" "zapret2-embedded.tar.gz" || true)
		if [ -n "${SRC:-}" ]; then
			rm -rf "$WORK/x" "$WORK/root"
			mkdir -p "$WORK/x" "$WORK/root/opt/zapret2/nfq2" "$WORK/root/opt/zapret2/lua" "$WORK/root/opt/zapret2/files/fake"
			tar -xzf "$SRC" -C "$WORK/x"
			R2=$(find "$WORK/x" -maxdepth 1 -type d -name 'zapret2-v*' | head -1)
			if [ -n "$R2" ] && [ -s "$R2/binaries/$ZD/nfqws2" ]; then
				cp "$R2/binaries/$ZD/nfqws2" "$WORK/root/opt/zapret2/nfq2/nfqws2"; chmod 755 "$WORK/root/opt/zapret2/nfq2/nfqws2"
				cp "$R2/binaries/$ZD/mdig" "$R2/binaries/$ZD/ip2net" "$WORK/root/opt/zapret2/" 2>/dev/null || true
				chmod 755 "$WORK/root/opt/zapret2/mdig" "$WORK/root/opt/zapret2/ip2net" 2>/dev/null || true
				cp "$R2"/lua/*.gz "$WORK/root/opt/zapret2/lua/" || true
				cp "$R2"/files/fake/*.bin "$WORK/root/opt/zapret2/files/fake/" || true
				own_pkg "$WORK/root" zapret2 "$Z2_VER-$REV" "$A" "Ravnex zapret2 nfqws2 (upstream bol-van openwrt-embedded $Z2_VER)"
			else
				echo "SKIP zapret2 $A (no binaries/$ZD/nfqws2 in the embedded tarball)"
			fi
		fi
	fi

	# Index AFTER the packages are signed (mkpkg --sign-key already signed them;
	# adbsign would change file sizes and break the index file_size entries).
	if ls "$D"/*.apk >/dev/null 2>&1; then
		( cd "$D" && apk --keys-dir "$PUB_DIR" --allow-untrusted \
			mkndx ${SIGN_ARGS[@]+"--sign-key" "$APK_SIGN_KEY"} --output packages.adb *.apk )
		# manifest.json = the client contract (merge this arch's jsonl lines)
		if [ -s "$MANIFESTS/$A.jsonl" ]; then
			{
				printf '{"series":"%s","arch":"%s","pkgs":{' "$SERIES" "$A"
				sep=''
				while IFS= read -r line; do printf '%s%s' "$sep" "$line"; sep=','; done < "$MANIFESTS/$A.jsonl"
				printf '}}\n'
			} > "$D/manifest.json"
		fi
		echo "arch $A: $(ls "$D"/*.apk | wc -l) apk, $(ls "$D"/*.ipk 2>/dev/null | wc -l) ipk, manifest: $([ -s "$D/manifest.json" ] && echo yes || echo NO)"
	else
		rmdir "$D" 2>/dev/null || true
		rm -f "$MANIFESTS/$A.jsonl"
		echo "arch $A: no packages — skipped"
	fi
done

echo "── feed tree ─────────────────────────────────────────────"
find "$OUT" -type f | sort
[ -s "$OUT/ravnex-feed.pub" ] || echo "NOTE: no public key written (unsigned build)"
echo "DONE: feed in $OUT (series $SERIES)"
