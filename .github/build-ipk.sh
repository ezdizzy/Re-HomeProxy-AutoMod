#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 Tianling Shen <cnsztl@immortalwrt.org>

set -o errexit
set -o pipefail

PKG_MGR="${1:-apk}"
RELEASE_TYPE="${2:-snapshot}"
# Optional 4th arg: explicit package version (the workflow_dispatch `version` input,
# or the pushed `v*` tag). When set on a release build it overrides the Makefile's
# PKG_VERSION so the package files (e.g. luci-app-ravnex_4.0.0_all.apk) match
# the GitHub release tag (v4.0.0). Without it we fall back to the Makefile value.
PKG_VERSION_OVERRIDE="${4:-}"

export PKG_SOURCE_DATE_EPOCH="$(date "+%s")"
export SOURCE_DATE_EPOCH="$PKG_SOURCE_DATE_EPOCH"

BASE_DIR="$(cd "$(dirname $0)"; pwd)"
PKG_DIR="$BASE_DIR/.."

function get_mk_value() {
	awk -F "$1:=" '{print $2}' "$PKG_DIR/Makefile" | xargs
}

PKG_NAME="$(get_mk_value "PKG_NAME")"
if [ "$RELEASE_TYPE" == "release" ]; then
	if [ -n "$PKG_VERSION_OVERRIDE" ]; then
		PKG_VERSION="$PKG_VERSION_OVERRIDE"
	else
		PKG_VERSION="$(get_mk_value "PKG_VERSION")"
	fi
else
	# NOTE: the CI checks out a shallow clone, so `git rev-list --count HEAD` is always 1.
	# Use a timestamp-based version so every build gets a UNIQUE package version —
	# otherwise reinstalling from a newer release with the same version string makes the
	# package manager skip the file overwrite and the device keeps stale code.
	# IMPORTANT: Alpine `apk` rejects hyphens in versions (only digits/dots/_suffix allowed),
	# so we use a dotted numeric timestamp (date + seconds) which is valid for both apk and ipk.
	PKG_VERSION="$(date -u +%Y.%m.%d.%H%M%S)"
fi

TEMP_DIR="$(mktemp -d -p $BASE_DIR)"
TEMP_PKG_DIR="$TEMP_DIR/$PKG_NAME"
mkdir -p "$TEMP_PKG_DIR/lib/upgrade/keep.d/"
mkdir -p "$TEMP_PKG_DIR/usr/lib/lua/luci/i18n/"
mkdir -p "$TEMP_PKG_DIR/www/"
if [ "$PKG_MGR" == "apk" ]; then
	mkdir -p "$TEMP_PKG_DIR/lib/apk/packages/"
else
	mkdir -p "$TEMP_PKG_DIR/CONTROL/"
fi

cp -fpR "$PKG_DIR/htdocs"/* "$TEMP_PKG_DIR/www/"
cp -fpR "$PKG_DIR/root"/* "$TEMP_PKG_DIR/"

cat > "$TEMP_PKG_DIR/lib/upgrade/keep.d/$PKG_NAME" <<-EOF
/etc/ravnex/certs/
/etc/ravnex/ruleset/
/etc/ravnex/resources/direct_list.txt
/etc/ravnex/resources/proxy_list.txt
/etc/ravnex/resources/auto_proxy_list.txt
/etc/ravnex/resources/auto_proxy_ip.txt
EOF

if [ "$PKG_MGR" == "apk" ]; then
	find "$TEMP_PKG_DIR" -type f,l -printf '/%P\n' | sort > "$TEMP_PKG_DIR/lib/apk/packages/$PKG_NAME.list"
	echo "/etc/config/ravnex" >> "$TEMP_PKG_DIR/lib/apk/packages/$PKG_NAME.conffiles"
	echo "/etc/config/ravcontrol" >> "$TEMP_PKG_DIR/lib/apk/packages/$PKG_NAME.conffiles"
	cat "$TEMP_PKG_DIR/lib/apk/packages/$PKG_NAME.conffiles" | while IFS= read -r file; do
		[ -f "$TEMP_PKG_DIR/$file" ] || continue
		sha256sum "$TEMP_PKG_DIR/$file" | sed "s,$TEMP_PKG_DIR/,," >> "$TEMP_PKG_DIR/lib/apk/packages/$PKG_NAME.conffiles_static"
	done

	echo -e '#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
add_group_and_user
# Deliberately NOT default_postinst: its init.d loop runs "/etc/init.d/ravnex
# start" synchronously, and the service start is slow (mosdns bootstrap +
# rule-set downloads + fw4) — slow enough to blow the 120s ubus timeout and
# kill apk mid-transaction (observed: update failed, i18n updated, app stayed
# old). The app update flow restarts the service in the background instead.
[ -n "${IPKG_INSTROOT}" ] || { if [ -d /tmp/.uci ] || mkdir -p /tmp/.uci; then
	for i in /etc/uci-defaults/luci-ravnex /etc/uci-defaults/luci-ravnex-migration /etc/uci-defaults/luci-ravnex-theme /etc/uci-defaults/luci-homeproxy /etc/uci-defaults/luci-homeproxy-migration /etc/uci-defaults/luci-homeproxy-theme; do
		[ -f "$i" ] && ( . "$i" ) && rm -f "$i"
	done
	uci commit
fi
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	# ch.253 Р9: the RPC object name changed (luci.homeproxy -> luci.ravnex);
	# SIGHUP does NOT reload the ucode method set (Makefile postinst lesson),
	# a full restart is required. Delayed+setsid: survives apk teardown and
	# does not block when the install runs THROUGH rpcd.
	if command -v setsid >/dev/null 2>&1; then
		setsid sh -c "sleep 3; /etc/init.d/rpcd restart" >/dev/null 2>&1 &
	fi
	# Menu hardening (ch.252): the ucode menu tree lives inside the uhttpd
	# process and never un-bakes a poisoned satisfied=false (menu dies for
	# all sessions, incl. fresh logins, until uhttpd restarts). Restart it
	# so every installer/updater ends with a clean tree.
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	# ch.255 Р9 (package rename bridge): sweep the LAST pre-rename leftovers.
	# /usr/share/homeproxy is superseded by /usr/share/ravnex in this package
	# (never copy the old dir over the new one - lesson 389, package wins);
	# the legacy RU catalog is retired only when the renamed one is present
	# (an app-only update must not lose translations).
	rm -rf /usr/share/homeproxy 2>/dev/null
	if [ -f /usr/lib/lua/luci/i18n/ravnex.ru.lmo ]; then
		rm -f /usr/lib/lua/luci/i18n/homeproxy.ru.lmo /usr/lib/lua/luci/i18n/homeproxy.ru.lmo.* 2>/dev/null
	fi
	exit 0
}' > "$TEMP_DIR/post-install"

	echo -e '#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
add_group_and_user
[ -n "${IPKG_INSTROOT}" ] || { if [ -d /tmp/.uci ] || mkdir -p /tmp/.uci; then
	# Upgrade path (ch.253 Р9): apk upgrades run post-upgrade, not
	# post-install - this hook now runs the FULL uci-defaults loop, because
	# the UCI/directory migrator lives in luci-ravnex-migration (it runs
	# BEFORE migrate_config.uc; see the stub). Legacy luci-homeproxy* names
	# are consumed too (boxes that carry them unconsumed). Idempotent and
	# gated: on a fresh box (no /etc/config/homeproxy) the migrator exits
	# immediately.
	for i in /etc/uci-defaults/luci-ravnex /etc/uci-defaults/luci-ravnex-migration /etc/uci-defaults/luci-ravnex-theme /etc/uci-defaults/luci-homeproxy /etc/uci-defaults/luci-homeproxy-migration /etc/uci-defaults/luci-homeproxy-theme; do
		[ -f "$i" ] && ( . "$i" ) && rm -f "$i"
	done
	uci commit
fi
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	# ch.253 Р9: renamed RPC object - full rpcd restart, not SIGHUP
	# (SIGHUP only reloads ACLs/session; the ucode method set stays stale).
	if command -v setsid >/dev/null 2>&1; then
		setsid sh -c "sleep 3; /etc/init.d/rpcd restart" >/dev/null 2>&1 &
	fi
	# ch.252 menu hardening: clean menu tree for every updater.
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	# ch.255 Р9 rename bridge: retire the pre-rename /usr/share/homeproxy and
	# legacy RU catalog (same conditions as post-install, see above).
	rm -rf /usr/share/homeproxy 2>/dev/null
	if [ -f /usr/lib/lua/luci/i18n/ravnex.ru.lmo ]; then
		rm -f /usr/lib/lua/luci/i18n/homeproxy.ru.lmo /usr/lib/lua/luci/i18n/homeproxy.ru.lmo.* 2>/dev/null
	fi
	exit 0
}' > "$TEMP_DIR/post-upgrade"

	# ch.253 Р9: snapshot the ENTIRE old tree BEFORE apk unpacks (old
	# non-conffile files vanish with the old package - lesson 389; modified
	# conffiles survive, unmodified ones are replaced). The migrator overlays
	# user state FROM this snapshot, so nothing user-owned is lost. Also
	# stops the OLD service cleanly before the file swap (the new service is
	# started by the update flow / hooks afterwards).
	cat > "$TEMP_DIR/pre-upgrade" <<-'PREEOF'
	#!/bin/sh
	[ -n "${IPKG_INSTROOT}" ] && exit 0
	TS=$(date +%s)
	SD="/root/ravnex-premigrate-$TS"
	mkdir -p "$SD"
	[ -d /etc/homeproxy ] && cp -a /etc/homeproxy "$SD/homeproxy" 2>/dev/null
	cp -p /etc/config/homeproxy /etc/config/homecontrol /etc/config/firewall "$SD/" 2>/dev/null
	/etc/init.d/homeproxy stop 2>/dev/null
	exit 0
	PREEOF
	chmod 0755 "$TEMP_DIR/pre-upgrade"

	echo -e '#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
add_group_and_user
[ -n "${IPKG_INSTROOT}" ] || { rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	exit 0
}' > "$TEMP_DIR/pre-deinstall"

	apk mkpkg \
		--info "name:$PKG_NAME" \
		--info "version:$PKG_VERSION" \
		--info "description:Ravnex - modern multi-core proxy platform. Fork of ImmortalWrt HomeProxy" \
		--info "arch:noarch" \
		--info "origin:$PKG_NAME" \
		--info "url:https://github.com/ezdizzy/ravnex" \
		--info "maintainer:1andrevich <1andrevich.recede274@passmail.net>" \
		--script "pre-upgrade:$TEMP_DIR/pre-upgrade" \
		--script "post-install:$TEMP_DIR/post-install" \
		--script "post-upgrade:$TEMP_DIR/post-upgrade" \
		--script "pre-deinstall:$TEMP_DIR/pre-deinstall" \
		--info "depends:libc firewall4" \
		--info "provides:luci-app-homeproxy" \
		--info "provides:luci-app-homeproxy-hiddify" \
		--info "replaces:luci-app-homeproxy" \
		--info "replaces:luci-app-homeproxy-hiddify" \
		--info "provides:luci-app-re-homeproxy=$PKG_VERSION" \
		--info "replaces:luci-app-re-homeproxy" \
		${APK_SIGN_KEY:+--sign-key "$APK_SIGN_KEY"} \
		--files "$TEMP_PKG_DIR" \
		--output "$TEMP_DIR/${PKG_NAME}_${PKG_VERSION}.apk"

	mv "$TEMP_DIR/${PKG_NAME}_${PKG_VERSION}.apk" "$BASE_DIR/${PKG_NAME}_${PKG_VERSION}_all.apk"
else
	mkdir -p "$TEMP_PKG_DIR/CONTROL/"

	# No ucode-mod-digest dependency: the app code deliberately avoids it
	# (dependency-free FNV-1a hashing in import_conf.uc / update_subscriptions.uc /
	# import_link.uc), so the package installs on every ucode-capable OpenWrt.
	IPK_DEPS="libc, firewall4, kmod-nft-tproxy"

	# Rename handling (ipk): do NOT Provides the old names. opkg treats an installed
	# package that is also Provided as *satisfying* the dependency and then never
	# fires Conflicts — so old + new would coexist. Dropping Provides and keeping
	# Conflicts+Replaces makes opkg cleanly replace the old pkg. (Nothing depends on
	# the old names: the i18n packages depend on $PKG_NAME.) The apk path uses the
	# Alpine rename idiom instead: provides + replaces (see the apk mkpkg call above).
	# R9 ШАГ 4 (ch.255): the OWN legacy name luci-app-re-homeproxy joins
	# Conflicts+Replaces — opkg (24.10) must retire it when installing
	# luci-app-ravnex (proven live in an offline opkg sandbox before release).
	cat > "$TEMP_PKG_DIR/CONTROL/control" <<-EOF
		Package: $PKG_NAME
		Version: $PKG_VERSION
		Depends: $IPK_DEPS
		Conflicts: luci-app-homeproxy luci-app-homeproxy-hiddify luci-app-re-homeproxy
		Replaces: luci-app-homeproxy luci-app-homeproxy-hiddify luci-app-re-homeproxy
		Source: https://github.com/ezdizzy/ravnex
		SourceName: $PKG_NAME
		Section: luci
		SourceDateEpoch: $PKG_SOURCE_DATE_EPOCH
		Maintainer: 1andrevich <1andrevich.recede274@passmail.net>
		Architecture: all
		Installed-Size: TO-BE-FILLED-BY-IPKG-BUILD
		Description:  Ravnex - modern multi-core proxy platform. Fork of ImmortalWrt HomeProxy
	EOF
	chmod 0644 "$TEMP_PKG_DIR/CONTROL/control"

	# ch.255 Р9 fix: this line previously used a POWERSHELL newline escape
	# (`n) inside a bash double-quoted string - the backtick opened a command
	# substitution that swallowed ~50 following lines at parse time (and the
	# generated CONTROL/conffiles was garbage on ipk builds). Proper bash:
	echo -e '/etc/config/ravnex\n/etc/config/ravcontrol' > "$TEMP_PKG_DIR/CONTROL/conffiles"

	# R9 ШАГ 4 (ch.255): opkg (24.10) honours Conflicts+Replaces only as a
	# file-takeover hint - it does NOT retire the replaced package from its
	# db (proven live in an offline opkg root). Retire the OWN legacy package
	# explicitly BEFORE the new files land (a postinst removal would race the
	# new package's shared /www files; preinst gives a clean swap). Modified
	# conffiles survive `opkg remove` (proven live) - the migrator overlays
	# their content into /etc/config/ravnex afterwards.
	echo -e '#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
if opkg status luci-app-re-homeproxy 2>/dev/null | grep -q "^Status: install"; then
	opkg remove luci-app-re-homeproxy 2>/dev/null
fi
exit 0' > "$TEMP_PKG_DIR/CONTROL/preinst"
	chmod 0755 "$TEMP_PKG_DIR/CONTROL/preinst"

	echo -e '#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
add_group_and_user
# Not default_postinst: its init.d loop would start /etc/init.d/ravnex
# synchronously (slow: bootstrap + rule-set downloads + fw4) and can blow the
# update timeout. The app update flow restarts the service in the background.
[ -n "${IPKG_INSTROOT}" ] || { if [ -d /tmp/.uci ] || mkdir -p /tmp/.uci; then
	for i in /etc/uci-defaults/luci-ravnex /etc/uci-defaults/luci-ravnex-migration /etc/uci-defaults/luci-ravnex-theme /etc/uci-defaults/luci-homeproxy /etc/uci-defaults/luci-homeproxy-migration /etc/uci-defaults/luci-homeproxy-theme; do
		[ -f "$i" ] && ( . "$i" ) && rm -f "$i"
	done
	uci commit
fi
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	rm -rf /usr/share/homeproxy 2>/dev/null
	if [ -f /usr/lib/lua/luci/i18n/ravnex.ru.lmo ]; then
		rm -f /usr/lib/lua/luci/i18n/homeproxy.ru.lmo /usr/lib/lua/luci/i18n/homeproxy.ru.lmo.* 2>/dev/null
	fi
	exit 0
}' > "$TEMP_PKG_DIR/CONTROL/postinst"
	chmod 0755 "$TEMP_PKG_DIR/CONTROL/postinst"

	echo -e "[ -n \"\${IPKG_INSTROOT}\" ] || {
	(. /etc/uci-defaults/$PKG_NAME) && rm -f /etc/uci-defaults/$PKG_NAME
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/uhttpd restart >/dev/null 2>&1
	exit 0
}" > "$TEMP_PKG_DIR/CONTROL/postinst-pkg"
	chmod 0755 "$TEMP_PKG_DIR/CONTROL/postinst-pkg"

	echo -e '#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_prerm $0 $@' > "$TEMP_PKG_DIR/CONTROL/prerm"
	chmod 0755 "$TEMP_PKG_DIR/CONTROL/prerm"

	ipkg-build -m "" "$TEMP_PKG_DIR" "$TEMP_DIR"

	mv "$TEMP_DIR/${PKG_NAME}_${PKG_VERSION}_all.ipk" "$BASE_DIR/${PKG_NAME}_${PKG_VERSION}_all.ipk"
fi

rm -rf "$TEMP_DIR"

# Native automation helpers (probe_pool, sni_sniffer) are NOT built here and
# NOT part of the package: they are arch-specific while the package is
# arch-independent ("all"). The workflow builds them via build-go.sh and
# publishes per-arch zips as release assets; install.sh downloads the right
# one on the router (graceful fallback to shell workers when absent).
# Go sources live in .github/go/ precisely so `cp -fpR root/*` can never leak
# them into the package tree.

# Build i18n package for Russian. R9 ШАГ 4 (ch.255): renamed to
# luci-i18n-ravnex-ru together with the app package; the po source is
# po/ru/ravnex.po, the installed catalog stays /usr/lib/lua/luci/i18n/
# ravnex.ru.lmo (the catalog file name IS the translation domain; ucode
# dispatcher merges every catalog in /usr/lib/lua/luci/i18n). The package
# declares replaces for its own legacy name (luci-i18n-homeproxy-ru) and
# ships a post-install hook that retires the legacy catalog file - a box
# that upgrades app+i18n together must not keep a stale merged catalog.
I18N_PKG_NAME="luci-i18n-ravnex-ru"
I18N_TEMP_DIR="$(mktemp -d -p $BASE_DIR)"
I18N_TEMP_PKG_DIR="$I18N_TEMP_DIR/$I18N_PKG_NAME"
mkdir -p "$I18N_TEMP_PKG_DIR/usr/lib/lua/luci/i18n/"
if [ "$PKG_MGR" == "apk" ]; then
	mkdir -p "$I18N_TEMP_PKG_DIR/lib/apk/packages/"
else
	mkdir -p "$I18N_TEMP_PKG_DIR/CONTROL/"
fi

po2lmo "$PKG_DIR/po/ru/ravnex.po" "$I18N_TEMP_PKG_DIR/usr/lib/lua/luci/i18n/ravnex.ru.lmo"

if [ "$PKG_MGR" == "apk" ]; then
	find "$I18N_TEMP_PKG_DIR" -type f,l -printf '/%P\n' | sort > "$I18N_TEMP_PKG_DIR/lib/apk/packages/$I18N_PKG_NAME.list"

	echo -e '#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /usr/lib/lua/luci/i18n/homeproxy.ru.lmo /usr/lib/lua/luci/i18n/homeproxy.ru.lmo.* 2>/dev/null
rm -f /tmp/luci-indexcache.* 2>/dev/null
rm -rf /tmp/luci-modulecache/ 2>/dev/null
exit 0' > "$I18N_TEMP_DIR/post-install"
	chmod 0755 "$I18N_TEMP_DIR/post-install"
	# apk runs post-UPGRADE (not post-install) when the package replaces an
	# installed one - the legacy-catalog sweep must fire on BOTH paths.
	cp -p "$I18N_TEMP_DIR/post-install" "$I18N_TEMP_DIR/post-upgrade"

	apk mkpkg \
		--info "name:$I18N_PKG_NAME" \
		--info "version:$PKG_VERSION" \
		--info "description:Russian translation for luci-app-ravnex" \
		--info "arch:noarch" \
		--info "origin:$I18N_PKG_NAME" \
		--info "url:https://github.com/ezdizzy/ravnex" \
		--info "maintainer:1andrevich <1andrevich.recede274@passmail.net>" \
		--info "depends:$PKG_NAME" \
		--info "replaces:luci-i18n-homeproxy-ru" \
		--script "post-install:$I18N_TEMP_DIR/post-install" \
		--script "post-upgrade:$I18N_TEMP_DIR/post-upgrade" \
		${APK_SIGN_KEY:+--sign-key "$APK_SIGN_KEY"} \
		--files "$I18N_TEMP_PKG_DIR" \
		--output "$I18N_TEMP_DIR/${I18N_PKG_NAME}_${PKG_VERSION}.apk"

	mv "$I18N_TEMP_DIR/${I18N_PKG_NAME}_${PKG_VERSION}.apk" "$BASE_DIR/${I18N_PKG_NAME}_${PKG_VERSION}_all.apk"
else
	echo -e '#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /usr/lib/lua/luci/i18n/homeproxy.ru.lmo /usr/lib/lua/luci/i18n/homeproxy.ru.lmo.* 2>/dev/null
rm -f /tmp/luci-indexcache.* 2>/dev/null
rm -rf /tmp/luci-modulecache/ 2>/dev/null
exit 0' > "$I18N_TEMP_PKG_DIR/CONTROL/postinst"
	chmod 0755 "$I18N_TEMP_PKG_DIR/CONTROL/postinst"

	cat > "$I18N_TEMP_PKG_DIR/CONTROL/control" <<-EOF
		Package: $I18N_PKG_NAME
		Version: $PKG_VERSION
		Depends: $PKG_NAME
		Replaces: luci-i18n-homeproxy-ru
		Source: https://github.com/ezdizzy/ravnex
		SourceName: $I18N_PKG_NAME
		Section: luci
		SourceDateEpoch: $PKG_SOURCE_DATE_EPOCH
		Maintainer: 1andrevich <1andrevich.recede274@passmail.net>
		Architecture: all
		Installed-Size: TO-BE-FILLED-BY-IPKG-BUILD
		Description:  Russian translation for luci-app-ravnex
	EOF
	chmod 0644 "$I18N_TEMP_PKG_DIR/CONTROL/control"

	ipkg-build -m "" "$I18N_TEMP_PKG_DIR" "$I18N_TEMP_DIR"

	mv "$I18N_TEMP_DIR/${I18N_PKG_NAME}_${PKG_VERSION}_all.ipk" "$BASE_DIR/${I18N_PKG_NAME}_${PKG_VERSION}_all.ipk"
fi

rm -rf "$I18N_TEMP_DIR"