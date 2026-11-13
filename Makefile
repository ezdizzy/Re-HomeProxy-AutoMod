# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org
# Copyright (C) 2024-2026 1andrevich <1andrevich.recede274@passmail.net>

include $(TOPDIR)/rules.mk

LUCI_TITLE:=Ravnex - multi-core proxy platform (DPI bypass, automation; successor of Re:HomeProxy AutoMod)
LUCI_PKGARCH:=all
# NOTE: MultiDNS uses mosdns (not smartdns) as its per-query DNS racing engine.
# mosdns is NOT shipped in the standard OpenWrt feed, so it is fetched at runtime
# from the mosdns GitHub releases by install.sh (binary в†’ /usr/bin/mosdns) instead
# of being declared as a hard package dependency (which would break install on
# feeds that lack it). The app degrades gracefully when mosdns is absent.
LUCI_DEPENDS:= \
	+firewall4 \
	+ucode-mod-digest

PKG_NAME:=luci-app-ravnex
# Р9 ШАГ 4 (план 22): the package itself is renamed luci-app-re-homeproxy ->
# luci-app-ravnex. The rename path is carried by build-ipk.sh (apk mkpkg
# provides/replaces, ipk Conflicts/Replaces for the OWN old name) and the
# migrator (migrate_ravnex.uc) - NOT by the buildroot path below, which is
# only used for feed builds of a fresh tree.
# Semantic version (X.Y.Z). This value IS the public version of Ravnex:
# the GitHub release tag is "v${PKG_VERSION}" and the in-app self-update compares the
# locally installed version against the latest release tag. Bump it ONLY when cutting a
# release (see LOCAL_DOCS/LOCAL_CHANGELOG.md / README "Releases" section). Do NOT use a date/timestamp.
PKG_VERSION:=3.2.0
PKG_RELEASE:=1
PKG_MAINTAINER:=1andrevich <1andrevich.recede274@passmail.net>
PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE

define Package/luci-app-ravnex/conffiles
/etc/config/ravnex
/etc/config/ravcontrol
/etc/ravnex/certs/
/etc/ravnex/ruleset/
/etc/ravnex/resources/direct_list.txt
/etc/ravnex/resources/proxy_list.txt
/etc/ravnex/resources/auto_proxy_list.txt
/etc/ravnex/resources/auto_proxy_ip.txt
endef

define Package/luci-app-ravnex/postinst
#!/bin/sh
# Full restart, NOT kill -HUP: SIGHUP only reloads ACLs/session, so rpcd keeps the
# OLD ucode method set from /usr/share/rpcd/ucode/ until restarted. On every update
# that shipped a new/changed method (e.g. zapret_resolve_hosts) the method would be
# missing/stale until a manual `rpcd restart` вЂ” surfacing as "DNS not ready",
# yellow "?" in diagnostics, "Unknown method", etc. A restart reloads methods + ACLs.
# Detached + redirected and after a short delay so it (a) lets the install finish
# first, and (b) doesn't block when the upgrade is driven THROUGH rpcd (LuCI Software
# page): rpcd's popen() would otherwise wait on a child holding stdout open.
#
# MUST use setsid, not a bare `( вЂ¦ ) &`: a plain background subshell stays in the
# postinst's process group, so when opkg/apk tears the install down it reaps the
# still-sleeping child and the restart NEVER fires (methods stay stale в†’ "DNS not
# ready" / "Method not found" until a manual `rpcd restart`). setsid puts the
# restarter in its own session, reparented to init, so it survives both the install
# teardown AND rpcd's own stop. Fall back to the plain form only where setsid is
# absent (rare; util-linux setsid ships on stock OpenWrt).
[ -n "$$IPKG_INSTROOT" ] && exit 0
# Session 161 heal: release 3.0.1 shipped scripts/*.sh with git file modes
# (oom_adj.sh = 100644) while multidns.uc/automation.uc call it via DIRECT
# exec -> "setsid: can't execute ... Permission denied" -> crash-guard stops
# the auto-spawn and writes mosdns.broken. Content-identical files get the
# (now-fixed 100755) package mode back on clean replacement, but files kept
# as .apk-new (content differs) keep the OLD mode (apk lesson 389) - the
# blanket chmod heals every already-broken 3.0.1 box on upgrade to 3.0.2.
# Removing the crash-guard flag lets multidns respawn mosdns within its
# next tick (~60 s) without any manual SSH step.
chmod 755 /etc/ravnex/scripts/*.sh 2>/dev/null
rm -f /var/run/ravnex/multidns/mosdns.broken 2>/dev/null
if command -v setsid >/dev/null 2>&1; then
	setsid sh -c 'sleep 3; /etc/init.d/rpcd restart' >/dev/null 2>&1 &
	setsid sh -c 'sleep 4; /etc/init.d/uhttpd restart' >/dev/null 2>&1 &
else
	( sleep 3; /etc/init.d/rpcd restart ) >/dev/null 2>&1 &
	( sleep 4; /etc/init.d/uhttpd restart ) >/dev/null 2>&1 &
fi
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
