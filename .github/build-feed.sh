#!/usr/bin/env bash
# build-feed.sh — build the Ravnex apk feed (§1.7 "own package repository").
#
# Produces a tree of signed apk v3 packages + a signed index (packages.adb) per
# OpenWrt arch label, ready for raw.githubusercontent / GitHub Pages hosting:
#
#   <out>/ravnex-feed.pub                       # public key (client: /etc/apk/keys/)
#   <out>/releases/<series>/<arch>/packages.adb # signed index (client feed URL)
#   <out>/releases/<series>/<arch>/<pkg>.apk    # packages, FLAT beside the index
#
# Covers the components that today install "by archive/manually" (KB §1.7):
#   hiddify-core          (upstream tar.gz — no upstream package at all)
#   hiddify-core-compact  (same binary, UPX-compressed — fork frozen at v4.1.0)
#   mosdns                (upstream zip — no OpenWrt package)
#   probe_pool, sni_sniffer (own Go helpers from release zips)
# byedpi/zapret2/sing-box-extended already ship as release-asset .apk files and
# keep their existing asset-install path (NOT mirrored here, v1).
#
# arch→asset tables mirror the app exactly (core_mgmt.uc HIDDIFY_UPSTREAM_ASSET,
# luci.homeproxy mosdns/helpers maps) so a feed package exists wherever the app
# knows how to run the component. Labels with no source for a component simply
# omit it from that arch's index (the client falls back to the asset path).
#
# Requirements: apk (apk-tools v3 with mkpkg/mkndx, host build), upx-ucl, jq,
# curl, tar, unzip, openssl. The signing key comes from APK_SIGN_KEY (path);
# when empty an unsigned feed is built (client needs --allow-untrusted then —
# the app's feed_setup still works, reporting the honest state).

set -euo pipefail

OUT=${1:?usage: build-feed.sh <out-dir>}
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
	arm_cortex-a7_neon-vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a9_neon|arm_cortex-a8_vfpv3|arm_cortex-a15_neon-vfpv4) echo 'mosdns-linux-arm-7.zip';;
	arm_cortex-a5_vfpv4|arm_arm926ej-s) echo 'mosdns-linux-arm-6.zip';;
	x86_64) echo 'mosdns-linux-amd64.zip';;
	mipsel_24kc|mipsel_74kc) echo 'mosdns-linux-mipsle-softfloat.zip';;
	*) return 1;;
	esac
}
helper_asset() {
	case "$1" in
	aarch64_generic|aarch64_cortex-a53|aarch64_cortex-a72|aarch64_cortex-a76) echo 'arm64';;
	arm_cortex-a7_neon-vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a9_neon|arm_cortex-a8_vfpv3|arm_cortex-a15_neon-vfpv4) echo 'armv7';;
	arm_cortex-a5_vfpv4|arm_arm926ej-s|arm_fa526) echo 'armv6';;
	x86_64) echo 'amd64';;
	mipsel_24kc|mipsel_74kc) echo 'mipsle-softfloat';;
	mips_24kc|mips_74kc|mips_mips32) echo 'mips-softfloat';;
	riscv64_generic) echo 'riscv64';;
	*) return 1;;
	esac
}
# UPX compact: same classes the app refuses (MIPS soft-float SIGILL) + formats
# upx cannot pack (riscv64). armv5/v6 pack fine but stay full — small fleet.
upx_ok() { case "$1" in mips*|riscv64*) return 1;; *) return 0;; esac; }

IFS=',' read -r -a ARCH_LIST <<< "$ARCHS"

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
tag_of() { curl -fsSL --retry 3 "$GHAPI/repos/$1/releases/latest" | jq -r '.tag_name'; }

echo "── versions ──────────────────────────────────────────────"
HID_TAG=$(tag_of hiddify/hiddify-core);          HID_VER=${HID_TAG#v}
MOS_TAG=$(tag_of IrineSistiana/mosdns);          MOS_VER=${MOS_TAG#v}
HELP_TAG=$(tag_of ezdizzy/re-homeproxy);         HELP_VER=${HELP_TAG#v}
echo "hiddify-core=$HID_VER mosdns=$MOS_VER helpers=$HELP_VER rev=$REV series=$SERIES"

# ── download unique source binaries once (cache per asset) ───────────────────
mkdir -p "$WORK/src"
fetch_bin() { # <url> <cachefile>
	local f="$WORK/src/$(basename "$2")"
	[ -s "$f" ] || fetch "$1" "$f"
	echo "$f"
}
for A in "${ARCH_LIST[@]}"; do
	HA=$(hid_asset "$A" || true)
	[ -n "${HA:-}" ] && fetch_bin "$GHDL/hiddify/hiddify-core/releases/latest/download/$HA" "$HA" >/dev/null || true
	MA=$(mosdns_asset "$A" || true)
	[ -n "${MA:-}" ] && fetch_bin "$GHDL/IrineSistiana/mosdns/releases/latest/download/$MA" "$MA" >/dev/null || true
done

echo "── build packages ────────────────────────────────────────"
PUB_DIR="$WORK/pub"; mkdir -p "$PUB_DIR"
if [ -n "${APK_SIGN_KEY:-}" ] && [ -s "$APK_SIGN_KEY" ]; then
	openssl rsa -in "$APK_SIGN_KEY" -pubout -out "$OUT/ravnex-feed.pub" 2>/dev/null || \
	openssl ec  -in "$APK_SIGN_KEY" -pubout -out "$OUT/ravnex-feed.pub" 2>/dev/null
	SIGN_ARGS=(--sign-key "$APK_SIGN_KEY")
else
	echo "WARNING: APK_SIGN_KEY empty — building an UNSIGNED feed"
	SIGN_ARGS=()
fi
mkdir -p "$PUB_DIR"
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
		--info "maintainer:1andrevich <1andrevich.recede274@passmail.net>" \
		--info "depends:libc" \
		--info "origin:ravnex-feed" \
		${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} \
		--files "$root" --output "$o"
}

for A in "${ARCH_LIST[@]}"; do
	D="$OUT/releases/$SERIES/$A"; mkdir -p "$D"
	HA=$(hid_asset "$A" || true)
	MA=$(mosdns_asset "$A" || true)
	GA=$(helper_asset "$A" || true)

	if [ -n "${HA:-}" ]; then
		SRC=$(fetch_bin "$GHDL/hiddify/hiddify-core/releases/latest/download/$HA" "$HA")
		rm -rf "$WORK/x"; mkdir -p "$WORK/x"; tar -xzf "$SRC" -C "$WORK/x"
		BIN=$(find "$WORK/x" -type f -name 'hiddify-core' | head -1)
		[ -n "$BIN" ] || { echo "SKIP hiddify-core $A (no binary in tarball)"; }
		if [ -n "${BIN:-}" ]; then
			mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/hiddify-core"; chmod 755 "$WORK/root/usr/bin/hiddify-core"
			pkg "$WORK/root" hiddify-core "$HID_VER-$REV" "$A" "Ravnex hiddify-core (full upstream build)" "$D/hiddify-core-$HID_VER-$REV.apk"
			if upx_ok "$A"; then
				cp "$BIN" "$WORK/root/usr/bin/hiddify-core"
				upx -q -9 "$WORK/root/usr/bin/hiddify-core" >/dev/null
				pkg "$WORK/root" hiddify-core-compact "$HID_VER-$REV" "$A" "Ravnex hiddify-core (UPX compact)" "$D/hiddify-core-compact-$HID_VER-$REV.apk"
			fi
		fi
	fi
	if [ -n "${MA:-}" ]; then
		SRC=$(fetch_bin "$GHDL/IrineSistiana/mosdns/releases/latest/download/$MA" "$MA")
		rm -rf "$WORK/x"; mkdir -p "$WORK/x"; unzip -qo "$SRC" -d "$WORK/x"
		BIN=$(find "$WORK/x" -type f -name 'mosdns' | head -1)
		if [ -n "${BIN:-}" ]; then
			mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/mosdns"; chmod 755 "$WORK/root/usr/bin/mosdns"
			pkg "$WORK/root" mosdns "$MOS_VER-$REV" "$A" "Ravnex mosdns (MultiDNS racing resolver)" "$D/mosdns-$MOS_VER-$REV.apk"
		fi
	fi
	if [ -n "${GA:-}" ]; then
		for T in probe_pool sni_sniffer; do
			SRC=$(fetch_bin "$GHDL/ezdizzy/re-homeproxy/releases/latest/download/$T-linux-$GA.zip" "$T-$GA.zip")
			rm -rf "$WORK/x"; mkdir -p "$WORK/x"; unzip -qo "$SRC" -d "$WORK/x"
			BIN=$(find "$WORK/x" -type f -name "$T" | head -1)
			if [ -n "${BIN:-}" ]; then
				mkdir -p "$WORK/root/usr/bin"; cp "$BIN" "$WORK/root/usr/bin/$T"; chmod 755 "$WORK/root/usr/bin/$T"
				pkg "$WORK/root" "$T" "$HELP_VER-$REV" "$A" "Ravnex $T (native automation helper)" "$D/$T-$HELP_VER-$REV.apk"
			fi
		done
	fi

	# Index AFTER the packages are signed (mkpkg --sign-key already signed them;
	# adbsign would change file sizes and break the index file_size entries).
	if ls "$D"/*.apk >/dev/null 2>&1; then
		( cd "$D" && apk --keys-dir "$PUB_DIR" --allow-untrusted \
			mkndx ${SIGN_ARGS[@]+"--sign-key" "$APK_SIGN_KEY"} --output packages.adb *.apk )
		echo "arch $A: $(ls "$D"/*.apk | wc -l) package(s) + packages.adb"
	else
		rmdir "$D" 2>/dev/null || true
		echo "arch $A: no packages — skipped"
	fi
done

echo "── feed tree ─────────────────────────────────────────────"
find "$OUT" -type f | sort
[ -s "$OUT/ravnex-feed.pub" ] || echo "NOTE: no public key written (unsigned build)"
echo "DONE: feed in $OUT (series $SERIES)"
