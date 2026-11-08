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
# Components:
#   OUR BUILDS (upstream raw binaries, packaged by us, $VER-$REV):
#     hiddify-core (+ hiddify-core-compact UPX)   hiddify/hiddify-core tar.gz
#     mosdns                                      IrineSistiana/mosdns zip
#     probe_pool, sni_sniffer                     our Go helpers from release zips
#   MIRRORS (foreign payloads REBUILT with our key, NAME+VERSION preserved
#   verbatim so the client's vercmp against the installed binary stays true):
#     sing-box-extended                shtorm-7 ipk → repack
#     sing-box-extended-lite           MANCrimSon normal tarball (compressed
#                                      stays on the proven installer path)
#     byedpi                           1andrevich ipk → repack
#     zapret2                          1andrevich ipk → repack
#
# arch→asset tables mirror the app exactly (core_mgmt.uc HIDDIFY_UPSTREAM_ASSET,
# luci.homeproxy byedpi/zapret2 maps) so a feed package exists wherever the
# app knows how to run the component. Labels with no upstream asset simply
# omit that component from the arch's manifest (the client falls back to the
# asset path / installer).
#
# Requirements: apk (apk-tools v3 with mkpkg/mkndx, host build), upx-ucl, jq,
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
hid_asset() {
	case "$1" in
	aarch64_cortex-a53|aarch64_cortex-a72|aarch64_cortex-a76|aarch64_generic) echo 'hiddify-core-linux-arm64-musl.tar.gz';;
	arm_cortex-a5_vfpv4|arm_cortex-a7_neon-vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a8_vfpv3|arm_cortex-a9_neon|arm_cortex-a9_vfpv3-d16|arm_cortex-a15_neon-vfpv4) echo 'hiddify-core-linux-armv7-musl.tar.gz';;
	arm_arm926ej-s) echo 'hiddify-core-linux-armv5.tar.gz';;
	arm_arm1176jzf-s_vfp) echo 'hiddify-core-linux-armv6.tar.gz';;
	mipsel_24kc|mipsel_74kc|mipsel_mips32) echo 'hiddify-core-linux-mipsle-softfloat.tar.gz';;
	mipsel_24kc_24kf) echo 'hiddify-core-linux-mipsle.tar.gz';;
	mips_24kc|mips_4kec|mips_mips32) echo 'hiddify-core-linux-mips-softfloat.tar.gz';;
	mips64_mips64r2|mips64_octeonplus) echo 'hiddify-core-linux-mips64-softfloat.tar.gz';;
	x86_64) echo 'hiddify-core-linux-amd64-musl.tar.gz';;
	i386_pentium4) echo 'hiddify-core-linux-386-musl.tar.gz';;
	i386_pentium-mmx) echo 'hiddify-core-linux-386-softfloat.tar.gz';;
	riscv64_generic) echo 'hiddify-core-linux-riscv64.tar.gz';;
	*) return 1;;
	esac
}
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
# MANCrimSon lite tarballs use Go arch names; variant = normal only (the
# compressed build stays on the project installer path — it ships a sh
# wrapper + UPX binary whose layout the feed does not replicate).
lite_goarch() {
	case "$1" in
	aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72|aarch64_cortex-a76) echo 'arm64';;
	arm_cortex-a5_vfpv4|arm_cortex-a7_neon-vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a8_vfpv3|arm_cortex-a9_neon|arm_cortex-a9_vfpv3-d16|arm_cortex-a15_neon-vfpv4|arm_fa526) echo 'armv7';;
	x86_64) echo 'amd64';;
	mips_24kc|mips_74kc|mips_mips32) echo 'mips-softfloat';;
	mipsel_24kc|mipsel_74kc) echo 'mipsle-softfloat';;
	*) return 1;;
	esac
}
# shtorm-7 / 1andrevich publish OpenWrt packages under the OpenWrt arch label
# directly (verified 2026-11-08: sing-box-extended_<ver>_openwrt_<arch>.ipk,
# byedpi_<ver>_<arch>.ipk, zapret2_<arch>.ipk); exact-name attempt, honest skip.
sbx_ipk_url() { # <ver> <arch>
	echo "$GHDL/shtorm-7/sing-box-extended/releases/download/v$1/sing-box-extended_${1}_openwrt_${2}.ipk"
}
byedpi_ipk_url() { # <ver> <arch>
	echo "$GHDL/1andrevich/ByeDPI-OpenWrt/releases/download/v$1/byedpi_${1}_${2}.ipk"
}
zapret2_ipk_url() { # <ver> <arch>
	echo "$GHDL/1andrevich/zapret2-openwrt/releases/download/v$1/zapret2_${2}.ipk"
}
# UPX compact: same classes the app refuses (MIPS soft-float SIGILL) + formats
# upx cannot pack (riscv64). armv5/v6 pack fine but stay full — small fleet.
upx_ok() { case "$1" in mips*|riscv64*) return 1;; *) return 0;; esac; }

IFS=',' read -r -a ARCH_LIST <<< "$ARCHS"

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
tag_of() { curl -fsSL --retry 3 "$GHAPI/repos/$1/releases/latest" | jq -r '.tag_name'; }

echo "── versions ──────────────────────────────────────────────"
HID_TAG=$(tag_of hiddify/hiddify-core);                 HID_VER=${HID_TAG#v}
MOS_TAG=$(tag_of IrineSistiana/mosdns);                 MOS_VER=${MOS_TAG#v}
HELP_TAG=$(tag_of ezdizzy/re-homeproxy);                HELP_VER=${HELP_TAG#v}
SBX_TAG=$(tag_of shtorm-7/sing-box-extended);           SBX_VER=${SBX_TAG#v}
LITE_TAG=$(tag_of MANCrimSon/sing-box-extended-lite);   LITE_VER=${LITE_TAG#v}
BYD_TAG=$(tag_of 1andrevich/ByeDPI-OpenWrt);            BYD_VER=${BYD_TAG#v}
Z2_TAG=$(tag_of 1andrevich/zapret2-openwrt);            Z2_VER=${Z2_TAG#v}
echo "hiddify-core=$HID_VER mosdns=$MOS_VER helpers=$HELP_VER rev=$REV series=$SERIES"
echo "sing-box-extended=$SBX_VER lite=$LITE_VER byedpi=$BYD_VER zapret2=$Z2_VER"

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
		--info "url:https://github.com/ezdizzy/re-homeproxy" \
		--info "maintainer:Ravnex feed <https://github.com/ezdizzy/re-homeproxy>" \
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
	manifest_add "$arch" "{\"$name\":{\"version\":\"$ver\",\"upstream\":\"$orig\",\"apk\":\"$name-$ver.apk\",\"apk_sha256\":\"$sha_a\",\"ipk\":\"$name-$ver.ipk\",\"ipk_sha256\":\"$sha_i\"}}"
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
	printf 'Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Ravnex feed <https://github.com/ezdizzy/re-homeproxy>\nDepends: libc\nDescription: %s\n' "$name" "$ver" "$arch" "$descr" > "$M/control"
	ipk_build "$M/control" "$root" "$D/$name-$ver.ipk"
	local sha_a sha_i
	sha_a=$(sha256sum "$D/$name-$ver.apk" | cut -d' ' -f1)
	sha_i=$(sha256sum "$D/$name-$ver.ipk" | cut -d' ' -f1)
	manifest_add "$arch" "{\"$name\":{\"version\":\"$ver\",\"apk\":\"$name-$ver.apk\",\"apk_sha256\":\"$sha_a\",\"ipk\":\"$name-$ver.ipk\",\"ipk_sha256\":\"$sha_i\"}}"
	versions_add "$name" "$ver" "$arch"
}

for A in "${ARCH_LIST[@]}"; do
	echo "── arch $A ────────────────────────────────────────────────"
	D="$OUT/releases/$SERIES/$A"; mkdir -p "$D"
	HA=$(hid_asset "$A" || true)
	MA=$(mosdns_asset "$A" || true)
	GA=$(helper_asset "$A" || true)
	LG=$(lite_goarch "$A" || true)

	if [ -n "${HA:-}" ]; then
		SRC=$(fetch_bin "$GHDL/hiddify/hiddify-core/releases/latest/download/$HA" "$HA" || true)
		if [ -n "${SRC:-}" ]; then
			rm -rf "$WORK/x" "$WORK/root"; mkdir -p "$WORK/x" "$WORK/root/usr/bin"; tar -xzf "$SRC" -C "$WORK/x"
			BIN=$(find "$WORK/x" -type f -name 'hiddify-core' | head -1)
			[ -n "$BIN" ] || echo "SKIP hiddify-core $A (no binary in tarball)"
			if [ -n "${BIN:-}" ]; then
				mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/hiddify-core"; chmod 755 "$WORK/root/usr/bin/hiddify-core"
				own_pkg "$WORK/root" hiddify-core "$HID_VER-$REV" "$A" "Ravnex hiddify-core (full upstream build)"
				if upx_ok "$A"; then
					cp "$BIN" "$WORK/root/usr/bin/hiddify-core"
					upx -q -9 "$WORK/root/usr/bin/hiddify-core" >/dev/null
					own_pkg "$WORK/root" hiddify-core-compact "$HID_VER-$REV" "$A" "Ravnex hiddify-core (UPX compact)"
				fi
			fi
		fi
	fi
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
			SRC=$(fetch_bin "$GHDL/ezdizzy/re-homeproxy/releases/latest/download/$T-linux-$GA.zip" "$T-$GA.zip" || true)
			if [ -n "${SRC:-}" ]; then
				rm -rf "$WORK/x" "$WORK/root"; mkdir -p "$WORK/x" "$WORK/root/usr/bin"; unzip -qo "$SRC" -d "$WORK/x"
				BIN=$(find "$WORK/x" -type f -name "$T" | head -1)
				if [ -n "${BIN:-}" ]; then
					mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/$T"; chmod 755 "$WORK/root/usr/bin/$T"
					own_pkg "$WORK/root" "$T" "$HELP_VER-$REV" "$A" "Ravnex $T (native automation helper)"
				fi
			fi
		done
	fi

	# ── mirrors: name/version preserved, our signatures ─────────────────────
	if [ -n "${SBX_VER:-}" ]; then
		SRC=$(fetch_bin "$(sbx_ipk_url "$SBX_VER" "$A")" "sbx-$A.ipk" || true)
		[ -n "${SRC:-}" ] && repack_ipk "$SRC" "$A" "sing-box-extended (mirror of shtorm-7, Ravnex-signed)" || echo "SKIP sing-box-extended $A (no upstream ipk)"
	fi
	if [ -n "${BYD_VER:-}" ]; then
		SRC=$(fetch_bin "$(byedpi_ipk_url "$BYD_VER" "$A")" "byedpi-$A.ipk" || true)
		[ -n "${SRC:-}" ] && repack_ipk "$SRC" "$A" "byedpi (mirror of 1andrevich/ByeDPI-OpenWrt, Ravnex-signed)" || echo "SKIP byedpi $A (no upstream ipk)"
	fi
	if [ -n "${Z2_VER:-}" ]; then
		SRC=$(fetch_bin "$(zapret2_ipk_url "$Z2_VER" "$A")" "zapret2-$A.ipk" || true)
		[ -n "${SRC:-}" ] && repack_ipk "$SRC" "$A" "zapret2 nfqws2 (mirror of 1andrevich/zapret2-openwrt, Ravnex-signed)" || echo "SKIP zapret2 $A (no upstream ipk)"
	fi
	if [ -n "${LG:-}" ] && [ -n "${LITE_VER:-}" ]; then
		SRC=$(fetch_bin "$GHDL/MANCrimSon/sing-box-extended-lite/releases/download/$LITE_TAG/sing-box-extended-lite-$LITE_VER-linux-$LG.tar.gz" "lite-$A.tar.gz" || true)
		if [ -n "${SRC:-}" ]; then
			rm -rf "$WORK/x" "$WORK/root"; mkdir -p "$WORK/x" "$WORK/root/usr/bin"
			tar -xzf "$SRC" -C "$WORK/x"
			BIN=$(find "$WORK/x" -maxdepth 2 -type f -name 'sing-box' | head -1)
			if [ -n "${BIN:-}" ]; then
				cp "$BIN" "$WORK/root/usr/bin/sing-box"; chmod 755 "$WORK/root/usr/bin/sing-box"
				own_pkg "$WORK/root" sing-box-extended-lite "$LITE_VER" "$A" "sing-box-extended-lite (mirror of MANCrimSon normal build $LITE_VER, Ravnex-signed)"
			else
				echo "SKIP sing-box-extended-lite $A (no sing-box binary in tarball)"
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
