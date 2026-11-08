#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';

import { access, popen, readfile, writefile, rename, stat, mkdir, unlink, opendir } from 'fs';
import { find_daemons as pm_find } from '/etc/ravnex/scripts/pmgr.uc';

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

/* Optional GitHub mirror (set by a provisioning tool or the user as
 * uci ravnex.config.github_mirror). Used ONLY as a FALLBACK: every fetch tries
 * GitHub first and only swaps to the mirror if GitHub fails — so a healthy GitHub is
 * never bypassed, but a blocked/failed one still gets the file via the mirror. */
function gh_mirror_base() {
	let base = null;
	const fd = popen('uci -q get ravnex.config.github_mirror 2>/dev/null');
	if (fd) { base = trim(fd.read('all')); fd.close(); }
	return (base && length(base)) ? replace(base, /\/+$/, '') : null;
}

function gh_mirror_of(url, base) {
	const m = match(url, /^https:\/\/github\.com(\/[^\/]+\/[^\/]+\/releases\/.+)$/);
	return m ? `${base}${m[1]}` : null;
}

/* Session 161: curl first when present — its TLS ClientHello passes the
 * TSPU selective hole that kills wget's fingerprint (session 159/161: wget
 * to api.github.com times out while curl succeeds from the same box).
 * wget stays as the fallback (stock boxes may lack curl), then the mirror.
 * 2-arg system() is fine here (lesson 167 refuted for this context, ch.246:
 * the B6 rc=1 roots were the dead /etc path and the rcfile-vs-exit bug).
 * ч.249b: return the PATH, not a boolean — the caller interpolates it into
 * the command; the boolean "true" turned every fetch into the shell builtin
 * `true -fsL …` (rc=0 instantly, NO file — the 3.0.2→3.0.3 self-update
 * download fake-success, live-proven by the DBG CMD print). */
function gh_has_curl() {
	return access('/usr/bin/curl') ? '/usr/bin/curl' : (access('/bin/curl') ? '/bin/curl' : null);
}

function curl_fetch(curl, dest, url, timeout_ms) {
	return system(`${curl} -fsL --retry 2 --retry-delay 2 -o ${shellquote(dest)} --connect-timeout 10 ${shellquote(url)} 2>/dev/null`, timeout_ms);
}

/* GitHub-first, mirror-FALLBACK download. Returns exit code (0 = success). */
function gh_fetch(url, dest, timeout_ms) {
	const curl = gh_has_curl();
	let rc = curl ? curl_fetch(curl, dest, url, timeout_ms)
		: system(`wget -qO ${shellquote(dest)} --timeout=15 ${shellquote(url)} 2>/dev/null`, timeout_ms);
	if (rc !== 0)
		rc = system(`wget -qO ${shellquote(dest)} --timeout=15 ${shellquote(url)} 2>/dev/null`, timeout_ms);
	if (rc !== 0) {
		const base = gh_mirror_base();
		const mu = base ? gh_mirror_of(url, base) : null;
		if (mu) {
			if (curl)
				rc = curl_fetch(curl, dest, mu, timeout_ms);
			if (rc !== 0)
				rc = system(`wget -qO ${shellquote(dest)} --timeout=15 ${shellquote(mu)} 2>/dev/null`, timeout_ms);
		}
	}
	return rc;
}

function detect_pkg_manager() {
	for (let p in ['/usr/bin/apk', '/sbin/apk', '/usr/sbin/apk'])
		if (access(p)) return 'apk';
	for (let p in ['/bin/opkg', '/usr/bin/opkg'])
		if (access(p)) return 'opkg';
	return null;
}

function detect_arch() {
	const os_rel = readfile('/etc/os-release') || '';
	const m = match(os_rel, /OPENWRT_ARCH="([^"]+)"/) ||
	          match(os_rel, /OPENWRT_ARCH=([^\n]+)/);
	return m ? trim(m[1]) : '';
}

function free_kb(path) {
	const fd = popen(`df -k ${path} 2>/dev/null | awk 'NR==2{print $4}'`);
	if (!fd) return 0;
	const v = int(trim(fd.read('all'))); fd.close();
	return v || 0;
}

function free_ram_kb() {
	const m = match(readfile('/proc/meminfo') || '', /MemAvailable:\s+([0-9]+)/);
	return m ? int(m[1]) : 0;
}

/* Does the overlay filesystem transparently compress? jffs2/ubifs do (~3x on a Go binary),
 * ext4/f2fs do not. This decides how much flash the FULL binary actually occupies. */
function overlay_compresses() {
	const fd = popen("mount 2>/dev/null | awk '$3==\"/overlay\"{print $5; exit}'");
	let t = '';
	if (fd) { t = trim(fd.read('all')); fd.close(); }
	return (t in ['jffs2', 'ubifs']);
}

/* Footprint thresholds (KB). The UPX/compact build is already compressed (~20 MB on ANY fs)
 * but decompresses the whole binary into RAM at every launch (trades flash for RAM). The full
 * Go binary is ~76 MB raw → ~76 MB on ext4/f2fs, but only ~26 MB on a compressing overlay. */
const FULL_OVERLAY_RAW_KB  = 81920;   /* ~80 MB free for the full binary on an uncompressed overlay */
const FULL_OVERLAY_COMP_KB = 32768;   /* ~32 MB on a compressing overlay (binary stores ~3x smaller) */
const COMPACT_OVERLAY_KB   = 25600;   /* ~25 MB for the compact (UPX) build — fs-independent */
const COMPACT_RAM_KB       = 98304;   /* ~96 MB free RAM to decompress + run the compact build */

/* sing-box-extended-lite (MANCrimSon, GitHub issue #4) footprint thresholds —
 * they mirror the project's own install.sh guards so prepare_install fails
 * BEFORE the download instead of mid-install: --normal needs ~50 MB effective
 * flash (free + the size of the binary being replaced), --compressed needs
 * ~16 MB overlay + ~96 MB RAM (UPX decompresses into RAM at every launch). */
const LITE_NORMAL_MIN_KB      = 51200;
const LITE_COMPRESSED_MIN_KB  = 16384;
const LITE_COMPRESSED_RAM_KB  = 98304;
const LITE_TMP_MIN_KB         = 20480;   /* installer work dir (+tar.gz) in /tmp */
const LITE_WRAPPER_MAX_BYTES  = 10000;   /* the compressed build ships a sh wrapper here */
const LITE_REPO               = 'https://api.github.com/repos/MANCrimSon/sing-box-extended-lite/releases/latest';
const LITE_INSTALLER_URL      = 'https://raw.githubusercontent.com/MANCrimSon/sing-box-extended-lite/main/install.sh';

/* hiddify-core upstream (hiddify/hiddify-core) — ОРИГИНАЛЬНЫЙ репозиторий
 * проекта (ч.129, ан-146). Releases публикуют сырые tar.gz-сборки per Go
 * target; musl CGO-сборки несут NaïveProxy, статические MIPS-сборки — нет
 * (cronet без MIPS — у форка то же самое). Пакеты apk/ipk оригинал НЕ
 * публикует (собирает их CI, но в релиз не выкладывает) — это и было
 * единственной функцией форка 1andrevich: публикация OpenWrt-пакетов при
 * НУЛЕВЫХ изменениях Go-кода (13 коммитов форка — только CI). С июня 2026
 * авто-чекер форка встал (драфт-релизы затеняют новые апстрим-теги), форк
 * заморожен на v4.1.0 при апстриме v5.x → форк стал РЕЗЕРВНЫМ источником
 * (компактная UPX-сборка есть только у него). Апстрим-тарбол: ядро
 * hiddify-core-linux-<target>[-musl]/hiddify-core (+ LICENSE.md). */
const HIDDIFY_UPSTREAM_DL   = 'https://github.com/hiddify/hiddify-core/releases/latest/download/';
const HIDDIFY_UPSTREAM_API  = 'https://api.github.com/repos/hiddify/hiddify-core/releases/latest';
const HIDDIFY_FORK_API      = 'https://api.github.com/repos/1andrevich/hiddify-core/releases/latest';
/* OpenWrt OPENWRT_ARCH → апстрим-ассет (musl CGO, где cronet существует;
 * статические для MIPS/старых ARM — они и у форка без NaïveProxy).
 * Неизвестная архитектура = форк (как раньше). */
const HIDDIFY_UPSTREAM_ASSET = {
	'aarch64_cortex-a53':   'hiddify-core-linux-arm64-musl.tar.gz',
	'aarch64_cortex-a72':   'hiddify-core-linux-arm64-musl.tar.gz',
	'aarch64_cortex-a76':   'hiddify-core-linux-arm64-musl.tar.gz',
	'aarch64_generic':      'hiddify-core-linux-arm64-musl.tar.gz',
	'arm_cortex-a5_vfpv4':  'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_cortex-a7_neon-vfpv4': 'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_cortex-a7_vfpv4':  'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_cortex-a8_vfpv3':  'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_cortex-a9_neon':   'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_cortex-a9_vfpv3-d16': 'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_cortex-a15_neon-vfpv4': 'hiddify-core-linux-armv7-musl.tar.gz',
	'arm_arm926ej-s':       'hiddify-core-linux-armv5.tar.gz',
	'arm_arm1176jzf-s_vfp': 'hiddify-core-linux-armv6.tar.gz',
	'mipsel_24kc':          'hiddify-core-linux-mipsle-softfloat.tar.gz',
	'mipsel_74kc':          'hiddify-core-linux-mipsle-softfloat.tar.gz',
	'mipsel_mips32':        'hiddify-core-linux-mipsle-softfloat.tar.gz',
	'mipsel_24kc_24kf':     'hiddify-core-linux-mipsle.tar.gz',
	'mips_24kc':            'hiddify-core-linux-mips-softfloat.tar.gz',
	'mips_4kec':            'hiddify-core-linux-mips-softfloat.tar.gz',
	'mips_mips32':          'hiddify-core-linux-mips-softfloat.tar.gz',
	'mips64_mips64r2':      'hiddify-core-linux-mips64-softfloat.tar.gz',
	'mips64_octeonplus':    'hiddify-core-linux-mips64-softfloat.tar.gz',
	'x86_64':               'hiddify-core-linux-amd64-musl.tar.gz',
	'i386_pentium4':        'hiddify-core-linux-386-musl.tar.gz',
	'i386_pentium-mmx':     'hiddify-core-linux-386-softfloat.tar.gz',
	'riscv64_generic':      'hiddify-core-linux-riscv64.tar.gz'
};
/* Пороги полной апстрим-сборки v5.x (arm64-musl: бинарник ≈101 МиБ, тарбол
 * ≈35.4 МиБ) — крупнее форковой (Go 1.27 + cronet). Тарбол кладётся в /tmp,
 * бинарник распаковывается прямо в оверлей (staging) → swap. */
const UP_FULL_OVERLAY_RAW_KB  = 112640;   /* ~110 MB на несжимающем оверлее */
const UP_FULL_OVERLAY_COMP_KB = 40960;    /* ~40 MB на сжимающем (jffs2/ubifs) */
const UP_FULL_TMP_KB          = 46080;    /* тарбол + запас в /tmp */

function bin_bytes(path) {
	/* 2>/dev/null FIRST: a missing file's "can't open" must stay silent. */
	const fd = popen(`wc -c 2>/dev/null < ${shellquote(path)}`);
	if (!fd) return 0;
	const v = int(trim(fd.read('all'))); fd.close();
	return v || 0;
}

/* Version-probe cache (tmpfs). Probing a core's `version` costs 1.5–3 s for
 * a UPX/packed binary (hiddify-core) and runs on EVERY page of the app
 * (rpcd singbox_get_features) and in every core_mgmt 'info' — the cache
 * turns those into instant reads. Entries are validated against the
 * binary's mtime+size: replacing the core invalidates its entry. The same
 * file/schema is used by rpcd's singbox_get_features (lesson 44: fs.stat
 * fields carry NO st_ prefix). */
const VERSION_CACHE = '/var/run/ravnex/core_versions.json';

function read_version_cache() {
	if (!access(VERSION_CACHE))
		return {};
	let cache;
	try { cache = json(readfile(VERSION_CACHE) || ''); } catch (e) { cache = null; }
	return (cache && type(cache) == 'object') ? cache : {};
}

function write_version_cache(cache) {
	mkdir('/var/run/ravnex');
	const tmp = VERSION_CACHE + '.tmp';
	writefile(tmp, sprintf('%.J', cache) + '\n');
	rename(tmp, VERSION_CACHE);
}

/* Wrapper size via stat(2), not `wc -c` — a popen failure must not make the
 * lite build invisible in the UI (issue #11/#13 reports from routers where
 * popen probing flaked). Same LITE_WRAPPER_MAX_BYTES threshold. */
function bin_size(path) {
	const st = access(path) ? stat(path) : null;
	return (st && st.size) ? st.size : 0;
}

/* Parse a core's version output into display + capability info. Tags are
 * the only reliable capability source: e.g. sing-box-extended ships
 * WITHOUT with_naive_outbound (NaïveProxy dropped), while hiddify-core
 * has it. Wrapper-aware: the lite COMPRESSED build puts a tiny sh wrapper
 * at /usr/bin/sing-box that answers `version` from a first-line cache
 * (no Tags line) and execs the real binary — probe /usr/libexec/sing-box-core
 * for the REAL tags, else the generator would think quic/wireguard are
 * missing and skip every fast node. */
function core_features(bin) {
	let info = {};
	let probe = bin;
	const bsize = bin_size(bin);
	if (bsize > 0 && bsize < LITE_WRAPPER_MAX_BYTES && access('/usr/libexec/sing-box-core'))
		probe = '/usr/libexec/sing-box-core';
	const fd = popen(probe + ' version 2>/dev/null');
	if (!fd) return info;
	const out = fd.read('all'); fd.close();
	const m = match(out, /version v?(\S+)/);
	if (m) info.version = m[1];
	const tm = match(out, /\nTags: ([^\n]+)/);
	let tags = {};
	if (tm)
		for (let t in split(tm[1], ','))
			tags[trim(t)] = true;
	/* tags stored in the cached info as well: rpcd's singbox_get_features
	 * shares this cache and needs the tag map (hp_core_info consumers). */
	info.tags = tags;
	info.naive = ('with_naive_outbound' in tags);
	info.quic = ('with_quic' in tags);
	info.wireguard = ('with_wireguard' in tags);
	info.extended = !!match(out, /-extended-/);
	info.wrapper = (probe !== bin);
	/* lite = extended build without the two heavy optional tags (the full
	 * shtorm-7 build carries BOTH with_gvisor and with_tailscale; the lite
	 * build strips them — verified against both repos' build tags). A
	 * first-line-only wrapper output has no Tags at all: extended version
	 * + wrapper presence still identifies lite (its version carries
	 * -extended- too), tags fall back to the real-binary probe above. */
	info.lite = info.extended && info.wrapper
		? true
		: (info.extended && !('with_gvisor' in tags) && !('with_tailscale' in tags));
	return info;
}

/* Cached wrapper: stat the binary, return the cached probe result when the
 * file is unchanged, probe+store otherwise. A probe that yields no version
 * is NOT cached (a transient failure must not stick). */
function core_features_cached(bin) {
	const st = stat(bin);
	if (!st)
		return {};
	const cache = read_version_cache();
	const e = cache[bin];
	if (e && e.mtime == st.mtime && e.size == st.size && e.info && e.info.version)
		return e.info;
	const info = core_features(bin);
	if (info && info.version) {
		cache[bin] = { mtime: st.mtime, size: st.size, info: info };
		write_version_cache(cache);
	}
	return info;
}

/* ── §1.7 Own package feed — V2, EXPLICIT FILES ONLY (session 150) ──────
 * Client contract = manifest.json (pkg → version → apk/ipk file + sha256);
 * NO repositories.d line is ever written (a foreign feed could then
 * out-version our components via `apk upgrade`). Mirrors the luci.ravnex
 * feed block verbatim (ч.223 «mirrors verbatim» principle): same ladder
 * (raw → jsDelivr → UCI gh-proxy mirror), same cache/TTL, same explicit-
 * file install with the sha256 gate, same bounded sibling families.
 * Declared BEFORE the action dispatch (ucode has no hoisting — a helper
 * below the dispatch block is invisible to the branches that run at module
 * level, lesson 93/126). */
const FEED_KEY_FILE = '/etc/apk/keys/ravnex-feed.pub';
const FEED_LIST_LEGACY = '/etc/apk/repositories.d/ravnex-feed.list';
const FEED_MANIFEST_FILE = '/var/run/ravnex/feed_manifest.json';
const FEED_MANIFEST_TTL = 1800;
const FEED_BRANCH = 'refs/heads/feed';
const FEED_REPOS = ['ezdizzy/ravnex', 'ezdizzy/ravnex'];
const FEED_BIN_PATH = {
	'hiddify-core': '/usr/bin/hiddify-core',
	'hiddify-core-compact': '/usr/bin/hiddify-core',
	'mosdns': '/usr/bin/mosdns',
	'probe_pool': '/usr/bin/probe_pool',
	'sni_sniffer': '/usr/bin/sni_sniffer',
	'sing-box-extended': '/usr/bin/sing-box',
	'sing-box-extended-lite': '/usr/bin/sing-box',
	'byedpi': '/usr/bin/ciadpi',
	'zapret2': '/opt/zapret2/nfq2/nfqws2'
};
/* Sibling families share a binary path — removed best-effort when the
 * counterpart installs. ONLY these two own families (lesson ch.223). */
const FEED_SIBLING = {
	'hiddify-core': 'hiddify-core-compact',
	'hiddify-core-compact': 'hiddify-core',
	'sing-box-extended': 'sing-box-extended-lite',
	'sing-box-extended-lite': 'sing-box-extended'
};

function feed_series() {
	const fd = popen("awk -F\\' '/DISTRIB_RELEASE/ {print $2}' /etc/openwrt_release 2>/dev/null");
	if (!fd) return '25.12';
	const r = trim(fd.read('all'));
	fd.close();
	const m = match(r, /^([0-9]+\.[0-9]+)/);
	return m ? m[1] : '25.12';
}

function feed_rel(path) {
	return 'releases/' + feed_series() + '/' + detect_arch() + '/' + path;
}

function feed_urls(rel) {
	const urls = [];
	const base = gh_mirror_base();
	for (let r in FEED_REPOS) {
		push(urls, { url: `https://raw.githubusercontent.com/${r}/${FEED_BRANCH}/${rel}`, rung: 'raw', repo: r });
		push(urls, { url: `https://cdn.jsdelivr.net/gh/${r}@feed/${rel}`, rung: 'jsdelivr', repo: r });
		if (base)
			push(urls, { url: `${base}/${r}/raw/${FEED_BRANCH}/${rel}`, rung: 'mirror', repo: r });
	}
	return urls;
}

function feed_fetch(rel, dest, timeout_ms) {
	const urls = feed_urls(rel);
	for (let r in FEED_REPOS) {
		for (let u in urls) {
			if (u.repo != r) continue;
			system(`rm -f ${shellquote(dest)}`);
			const rc = system(`wget -qO ${shellquote(dest)} --timeout=15 ${shellquote(u.url)} 2>/dev/null; RC=$?; exit $RC`, timeout_ms || 60000);
			if (rc === 0 && access(dest)) {
				const st = stat(dest);
				if (st && st.size > 0)
					return { ok: true, url: u.url, rung: u.rung, repo: r };
			}
			system(`rm -f ${shellquote(dest)}`);
		}
	}
	return { ok: false, url: (length(urls) ? urls[0].url : null), rung: null, repo: null };
}

function feed_manifest(force) {
	let cache = null;
	if (access(FEED_MANIFEST_FILE)) {
		try { cache = json(readfile(FEED_MANIFEST_FILE) || ''); } catch (e) { cache = null; }
	}
	const now = time();
	if (!force && cache && type(cache) == 'object' && cache.ts &&
	    (now - cache.ts) < FEED_MANIFEST_TTL && cache.manifest)
		return cache.manifest;
	const arch = detect_arch();
	const got = feed_fetch(feed_rel('manifest.json'), FEED_MANIFEST_FILE + '.dl', 30000);
	if (!got.ok)
		return (cache && cache.manifest) ? cache.manifest : null;
	let man = null;
	try { man = json(readfile(FEED_MANIFEST_FILE + '.dl') || ''); } catch (e) { man = null; }
	system(`rm -f ${shellquote(FEED_MANIFEST_FILE + '.dl')}`);
	if (!man || type(man) != 'object' || !man.pkgs || man.arch != arch)
		return (cache && cache.manifest) ? cache.manifest : null;
	const entry = { ts: now, manifest: man };
	mkdir('/var/run/ravnex');
	writefile(FEED_MANIFEST_FILE + '.tmp', sprintf('%.J', entry) + '\n');
	rename(FEED_MANIFEST_FILE + '.tmp', FEED_MANIFEST_FILE);
	return man;
}

function feed_candidate(pkg) {
	/* cache-first manifest read; the caller applies its own version gate */
	const man = feed_manifest(false);
	if (!man || !man.pkgs) return null;
	const e = man.pkgs[pkg];
	if (!e || !e.version) return null;
	return { version: '' + e.version,
		apk: e.apk || null, apk_sha256: e.apk_sha256 || null,
		ipk: e.ipk || null, ipk_sha256: e.ipk_sha256 || null };
}

function feed_configured() {
	/* apk: the key marks the feed enabled. opkg: the manifest is fetched on
	 * demand and sha256 is the verification — always usable. */
	const pm = detect_pkg_manager();
	if (pm == null) return false;
	if (pm === 'opkg') return true;
	return !!access(FEED_KEY_FILE);
}

function feed_strip_rev(v) {
	const m = match(v || '', /^[0-9]+(\.[0-9]+)*/);
	return m ? m[0] : '';
}

function feed_vercmp_base(a, b) {
	const pa = split(a, '.'), pb = split(b, '.');
	const n = (length(pa) > length(pb)) ? length(pa) : length(pb);
	for (let i = 0; i < n; i++) {
		const xa = int((pa[i] != null) ? pa[i] : '0') || 0;
		const xb = int((pb[i] != null) ? pb[i] : '0') || 0;
		if (xa != xb) return (xa > xb) ? 1 : -1;
	}
	return 0;
}

/* Installed version of a feed package — the same honest contract as the
 * rpcd copy: the PM record when the package was installed through apk/opkg,
 * else null (a binary probe lies here: the OLD binary is exactly what a
 * failed install leaves behind). */
function feed_installed_version(pkg) {
	const pm = detect_pkg_manager();
	if (pm === 'apk') {
		const fd = popen(`apk info ${shellquote(pkg)} 2>/dev/null`);
		if (fd) {
			const out = fd.read('all');
			fd.close();
			/* scan every line for "<pkg>-<version>" (apk v3 info output) */
			const prefix = pkg + '-';
			for (let line in split(out, '\n')) {
				if (substr(line, 0, length(prefix)) != prefix) continue;
				const rest = trim(substr(line, length(prefix)));
				const ver = (length(rest) > 0) ? split(rest, ' ')[0] : '';
				if (length(ver))
					return split(ver, ':')[0];
			}
		}
	} else if (pm === 'opkg') {
		const fd = popen(`opkg status ${shellquote(pkg)} 2>/dev/null`);
		if (fd) {
			const out = fd.read('all');
			fd.close();
			const m = match(out, /Version: (\S+)/);
			if (m) return m[1];
		}
	}
	return null;
}

/* V2 explicit-file install of one feed package (mirror of rpcd's
 * feed_install_pkg): manifest → exact file → ladder → sha256 gate →
 * `apk add ./x.apk` (signature checked by apk) | `opkg install ./x.ipk`
 * (sha256 WAS the gate) → post-check access(). */
function feed_install_pkg(pkg) {
	const pkg_manager = detect_pkg_manager();
	if (!pkg_manager)
		return { result: false, error: 'no supported package manager (apk/opkg)' };
	if (pkg_manager === 'apk' && !access(FEED_KEY_FILE))
		return { result: false, error: 'feed key is not installed — run the feed setup first' };
	const man = feed_manifest(true);
	if (!man)
		return { result: false, error: 'feed manifest unavailable (raw/jsDelivr/mirror did not answer)' };
	const entry = (man.pkgs || {})[pkg];
	if (!entry || !entry.version)
		return { result: false, error: `the feed manifest (${man.arch}) has no package ${pkg}` };
	const file = (pkg_manager === 'apk') ? entry.apk : entry.ipk;
	const sha = (pkg_manager === 'apk') ? entry.apk_sha256 : entry.ipk_sha256;
	if (!file || !sha)
		return { result: false, error: `the manifest has no ${pkg_manager} file for ${pkg}` };
	if (!match(file, /^[a-z0-9][a-zA-Z0-9._-]*$/) || !match(sha, /^[0-9a-f]{64}$/))
		return { result: false, error: 'invalid manifest record (file name/sha256)' };
	const tmp = `/tmp/feed_${pkg}.${pkg_manager}`;
	const got = feed_fetch(feed_rel(file), tmp, 300000);
	if (!got.ok)
		return { result: false, error: `download failed: ${file}` };
	let sum = '';
	const hfd = popen(`sha256sum ${shellquote(tmp)} 2>/dev/null`);
	if (hfd) { sum = trim(hfd.read('all')); hfd.close(); }
	const hm = match(sum, /^([0-9a-f]{64})/);
	if (!hm || hm[1] != sha) {
		system(`rm -f ${shellquote(tmp)}`);
		return { result: false, error: `sha256 mismatch for ${file} — install refused` };
	}
	const sib = FEED_SIBLING[pkg];
	if (sib)
		system(`${(pkg_manager === 'apk') ? 'apk del' : 'opkg remove'} ${shellquote(sib)} >/dev/null 2>&1; true`);
	let rc;
	if (pkg_manager === 'apk') {
		/* ч.248: `apk upgrade ./file` is NOT a file-target form on apk 3.x
		 * (the path parses as a world constraint — a silent no-op), while
		 * `apk add ./file` both installs AND upgrades from a file (proven
		 * live 1.0.5.2→1.0.7). The rpcd copy was fixed then, but this copy
		 * DRIFTED and a registered core got a false «успешно» with the old
		 * binary still on disk (field report 2026-11-08: hiddify-core
		 * 5.1.0→5.5.5 «updated» without changing a byte). ALWAYS add. */
		rc = system(`apk add ${shellquote(tmp)} >/dev/null 2>&1; RC=$?; rm -f ${shellquote(tmp)}; exit $RC`, 300000);
	} else {
		rc = system(`opkg install --force-reinstall ${shellquote(tmp)} >/dev/null 2>&1; RC=$?; rm -f ${shellquote(tmp)}; exit $RC`, 300000);
	}
	const bin = FEED_BIN_PATH[pkg];
	/* apk 3.0.5 exit codes are unreliable on success (file-target installs
	 * that landed fine still exit 1/2 on NOTE-level messages, proven live
	 * by the loopback acceptance) — the same contract as install_pkg:
	 * trust the installed binary, report the rc only when it is absent. */
	if (!(bin && access(bin)))
		return { result: false, error: `feed install of ${pkg} failed (${pkg_manager} rc=${rc}, post-check failed)` };
	/* Version honesty (mirror of the rpcd copy): a silent no-op must not
	 * pass as an upgrade — the installed PM version has to match the
	 * manifest entry. NULL is tolerated (binary-only installs). */
	const got_ver = feed_installed_version(pkg);
	if (got_ver != null && feed_vercmp_base(feed_strip_rev('' + got_ver), feed_strip_rev('' + entry.version)) !== 0)
		return { result: false, error: `${pkg}: после установки версия ${got_ver} не совпала с фидом ${entry.version} — установка не прижилась` };
	return { result: true, version: '' + entry.version, pkg_manager,
		note: `installed from the update source: ${pkg} ${entry.version}` };
}


const action = ARGV[0];
let result;

	if (action === 'info') {
		const pkg_manager = detect_pkg_manager();
		const arch = detect_arch();

		const tmp_free_kb = free_kb('/tmp');
		let overlay_free_kb = free_kb('/overlay');
		if (!overlay_free_kb) overlay_free_kb = free_kb('/');
		const ram_free_kb = free_ram_kb();

		/* Parse a core's version output into display + capability info —
		 * core_features_cached() (top of file) is wrapper-aware for lite
		 * builds and reuses the shared version cache. */
		const hiddify_installed = !!access('/usr/bin/hiddify-core');
		const singbox_installed = !!access('/usr/bin/sing-box');
		const hid_f = hiddify_installed ? core_features_cached('/usr/bin/hiddify-core') : {};
		const sb_f  = singbox_installed ? core_features_cached('/usr/bin/sing-box') : {};

		result = {
			pkg_manager, arch, tmp_free_kb, overlay_free_kb, ram_free_kb,
			hiddify: {
				installed: hiddify_installed,
				version: hid_f.version ?? null,
				naive: hid_f.naive ?? false,
				quic: hid_f.quic ?? false,
				wireguard: hid_f.wireguard ?? false,
				extended: hid_f.extended ?? false
			},
			singbox: {
				installed: singbox_installed,
				version: sb_f.version ?? null,
				naive: sb_f.naive ?? false,
				quic: sb_f.quic ?? false,
				wireguard: sb_f.wireguard ?? false,
				extended: sb_f.extended ?? false,
				lite: sb_f.lite ?? false,
				wrapper: sb_f.wrapper ?? false,
				/* variant of the on-disk binary: normal ELF vs the tiny sh
				 * wrapper of the compressed (UPX) lite build. stat(2) size —
				 * see bin_size() (popen must not gate the lite detection). */
				variant: singbox_installed
					? (bin_size('/usr/bin/sing-box') < LITE_WRAPPER_MAX_BYTES ? 'compressed' : 'normal')
					: null
			}
		};

} else if (action === 'check_remote') {
	const core = ARGV[1];
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { error: 'illegal core' };
	} else if (core === 'hiddify') {
		/* ч.129 (ан-146): первичный источник — ОРИГИНАЛЬНЫЙ hiddify/hiddify-core
		 * (форк заморожен на v4.1.0 с июня 2026), форк — резерв. Если на этой
		 * архитектуре апстрим-тарбол пригоден (ассет смаплен) И оверлей его
		 * вместит — сообщаем апстрим; иначе форк (то, что реально поставится). */
		const gh_latest = (api_url) => {
			const fd = popen('wget -qO- --timeout=10 ' + shellquote(api_url) + ' 2>/dev/null');
			if (!fd) return null;
			const raw = trim(fd.read('all')); fd.close();
			let data;
			try { data = json(raw); } catch(e) { data = null; }
			return (data && data.tag_name) ? { tag: data.tag_name } : null;
		};
		const arch = detect_arch();
		const up_asset = arch ? HIDDIFY_UPSTREAM_ASSET[arch] : null;
		let overlay_free_kb = free_kb('/overlay');
		if (!overlay_free_kb) overlay_free_kb = free_kb('/');
		const up_need = overlay_compresses() ? UP_FULL_OVERLAY_COMP_KB : UP_FULL_OVERLAY_RAW_KB;
		let data = up_asset && overlay_free_kb >= up_need ? gh_latest(HIDDIFY_UPSTREAM_API) : null;
		if (data) {
			result = { tag: data.tag, version: replace(data.tag, /^v/, ''), source: 'upstream' };
		} else {
			data = gh_latest(HIDDIFY_FORK_API);
			if (data)
				result = { tag: data.tag, version: replace(data.tag, /^v/, ''), source: up_asset ? 'fork' : 'fork' };
			else
				result = { error: 'no response from GitHub API' };
		}
	} else {
		const api_url = core === 'singbox'
			? 'https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest'
			: LITE_REPO;

		const fd = popen('wget -qO- --timeout=10 ' + shellquote(api_url) + ' 2>/dev/null');
		if (!fd) {
			result = { error: 'wget failed' };
		} else {
			const raw = trim(fd.read('all')); fd.close();
			if (!length(raw)) {
				result = { error: 'no response from GitHub API' };
			} else {
				let data;
				try { data = json(raw); } catch(e) { data = null; }
				if (!data)
					result = { error: 'invalid JSON from GitHub API' };
				else if (!data?.tag_name)
					result = { error: 'could not read tag_name from response' };
				else
					result = { tag: data.tag_name, version: replace(data.tag_name, /^v/, '') };
			}
		}
	}

} else if (action === 'prepare_install') {
	const core = ARGV[1];
	const variant = ARGV[2] || '';   /* 'upx' = the compressed hiddify-core build (small flash, decompresses into RAM at launch); lite: 'normal' | 'compressed' */
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { error: 'illegal core' };
	} else {
		const pkg_manager = detect_pkg_manager();
		if (!pkg_manager) {
			result = { error: 'no supported package manager found (apk or opkg)' };
		} else if (core === 'singbox-lite') {
			/* The lite project ships an install.sh (no apk/ipk): it downloads
			 * the right tar.gz for the arch, validates the binary, swaps it
			 * and restarts the services it stopped. Pre-validate the same
			 * thresholds here so the UI gets a clean error before any
			 * download (the installer hard-fails mid-way otherwise). */
			const arch = detect_arch();
			if (!arch || !match(arch, /^[a-zA-Z0-9_-]+$/)) {
				result = { error: 'could not detect device architecture' };
			} else {
				const tmp_free_kb = free_kb('/tmp');
				if (tmp_free_kb < LITE_TMP_MIN_KB) {
					result = { error: `not enough /tmp space for the lite installer: ${tmp_free_kb} KB free, need ~20 MB` };
				} else {
					let overlay_free_kb = free_kb('/overlay');
					if (!overlay_free_kb) overlay_free_kb = free_kb('/');
					/* "Effective" flash = free space + the size of the binary
					 * this install replaces (same accounting as install.sh). */
					const cur_kb = int(bin_bytes('/usr/bin/sing-box') / 1024);
					const effective_kb = overlay_free_kb + cur_kb;
					const ram_free_kb = free_ram_kb();
					let chosen = variant;
					if (chosen !== 'normal' && chosen !== 'compressed')
						chosen = (effective_kb >= LITE_NORMAL_MIN_KB) ? 'normal' : 'compressed';
					/* §1.7 V2 feed-first — NORMAL build only: the feed mirrors
					 * the MANCrimSon normal tarball as a signed package; the
					 * COMPRESSED (UPX wrapper) build stays on the proven
					 * installer path (its layout is not replicated in the
					 * feed, decision session 150). */
					if (chosen === 'normal' && effective_kb >= LITE_NORMAL_MIN_KB && feed_configured()) {
						const lite_cur = core_features_cached('/usr/bin/sing-box');
						const cur = (lite_cur && lite_cur.version) ? lite_cur.version : '';
						const cand = feed_candidate('sing-box-extended-lite');
						if (cand &&
						    (!length(cur) || feed_vercmp_base(feed_strip_rev(cand.version), cur) >= 0))
							result = { pkg_manager, arch, variant: 'normal',
								source: 'feed', feed_pkg: 'sing-box-extended-lite',
								note: `own feed: sing-box-extended-lite ${cand.version}` };
					}
					if (result == null && chosen === 'normal' && effective_kb < LITE_NORMAL_MIN_KB) {
						result = { error: `Not enough effective flash for the lite --normal build: ${effective_kb} KB free (need ~50 MB). Try the compressed (UPX) build — it needs ~96 MB free RAM.` };
					} else if (result == null && chosen === 'compressed' && overlay_free_kb < LITE_COMPRESSED_MIN_KB) {
						result = { error: `Not enough overlay for the lite compressed build: ${overlay_free_kb} KB free (need ~16 MB).` };
					} else if (result == null && chosen === 'compressed' && ram_free_kb < LITE_COMPRESSED_RAM_KB) {
						result = { error: `Not enough RAM for the lite compressed build: ${ram_free_kb} KB free (need ~96 MB — the UPX binary decompresses into RAM at launch).` };
					} else if (result == null) {
						result = {
							pkg_manager, arch, variant: chosen,
							installer_url: LITE_INSTALLER_URL,
							tmp_path: `/tmp/sing-box-extended-lite-installer-${chosen}.sh`
						};
					}
				}
			}
		} else {
			const arch = detect_arch();
			if (!arch || !match(arch, /^[a-zA-Z0-9_-]+$/)) {
				result = { error: 'could not detect device architecture' };
			} else {
				const tmp_free_kb = free_kb('/tmp');
				if (tmp_free_kb < 30720) {
					result = { error: `not enough /tmp space: ${tmp_free_kb} KB free, need 30 MB` };
				} else {
					let overlay_free_kb = free_kb('/overlay');
					if (!overlay_free_kb) overlay_free_kb = free_kb('/');
					const ram_free_kb = free_ram_kb();
					const ext = pkg_manager === 'apk' ? '.apk' : '.ipk';
					/* full-binary footprint depends on whether the overlay compresses */
					const full_need = overlay_compresses() ? FULL_OVERLAY_COMP_KB : FULL_OVERLAY_RAW_KB;

					/* §1.7 V2 feed-first for sing-box-extended: a manifest
					 * candidate not older than the installed binary short-
					 * circuits the GitHub API + asset download (the runner
					 * installs via install_feed_pkg). Space gate = the same
					 * full_need the asset path enforces below. */
					let sb_feed_hit = null;
					if (core !== 'hiddify' && feed_configured()) {
						const sb_cur = core_features_cached('/usr/bin/sing-box');
						const cur = (sb_cur && sb_cur.version) ? sb_cur.version : '';
						const cand = feed_candidate('sing-box-extended');
						if (cand && overlay_free_kb >= full_need &&
						    (!length(cur) || feed_vercmp_base(feed_strip_rev(cand.version), cur) >= 0))
							sb_feed_hit = { pkg_manager, arch, source: 'feed',
								feed_pkg: 'sing-box-extended',
								note: `own feed: sing-box-extended ${cand.version}` };
					}

				if (core === 'hiddify') {
					/* ч.129 (ан-146): ПЕРВИЧНЫЙ источник — оригинальный репозиторий
					 * hiddify/hiddify-core (raw tar.gz per Go target). Форк 1andrevich
					 * — только резерв: он заморожен на v4.1.0 (июнь 2026) и существует
					 * лишь ради OpenWrt-пакетов (apk/ipk) и компактной UPX-сборки.
					 * Апстрим-ветка: musl CGO-тарбол (= NaïveProxy на борту), путь
					 * download → tar -xzf в staging на оверлее → атомарный swap.
					 * Форк-ветка (пакет apk/ipk, ниже) остаётся как была: явный
					 * variant='upx', немапленные архитектуры и устройства, которым
					 * не хватает места под крупный апстрим-бинарник (~101 МиБ). */
					const up_asset = HIDDIFY_UPSTREAM_ASSET[arch] || null;
					const up_need = overlay_compresses() ? UP_FULL_OVERLAY_COMP_KB : UP_FULL_OVERLAY_RAW_KB;
					const up_fits = up_asset && overlay_free_kb >= up_need && tmp_free_kb >= UP_FULL_TMP_KB;
					/* §1.7 V2: the own feed — when its manifest candidate is not
					 * older than the installed binary, take the package from
					 * the feed (explicit file + sha256 + signature, no tarball
					 * download at all). Everything that misses (not
					 * configured, older candidate, no space, manifest blind)
					 * falls through to the original upstream/fork paths below
					 * — the fallback IS the old code. The compact build rides
					 * the same feed as hiddify-core-compact (replaces the
					 * frozen v4.1.0 fork apk; space-checked with the same
					 * COMPACT_OVERLAY_KB). The install itself is the
					 * generalized install_feed_pkg action below (runner calls
					 * it with prep.feed_pkg). */
					let feed_hit = null;
					if (feed_configured()) {
						const fpkg = (variant === 'upx') ? 'hiddify-core-compact' : 'hiddify-core';
						const cur_info = core_features_cached('/usr/bin/hiddify-core');
						const cur = cur_info.version || '';
						const cand = feed_candidate(fpkg);
						const fits = overlay_free_kb >= ((variant === 'upx') ? COMPACT_OVERLAY_KB : full_need);
						if (cand && fits &&
						    (!length(cur) || feed_vercmp_base(feed_strip_rev(cand.version), cur) >= 0))
							feed_hit = { pkg_manager, arch,
								variant: (variant === 'upx') ? 'upx' : 'standard',
								source: 'feed', feed_pkg: fpkg,
								note: `own apk feed: ${fpkg} ${cand.version}` };
					}
					if (feed_hit) {
						result = feed_hit;
					} else if (variant !== 'upx' && up_fits) {
						result = {
							pkg_manager, arch, variant: 'standard', source: 'upstream',
							note: 'upstream build (hiddify/hiddify-core tar.gz)',
							dl_url: HIDDIFY_UPSTREAM_DL + up_asset,
							tmp_path: '/tmp/hiddify-core.tar.gz'
						};
					} else {
					/* Auto-pick the build from free overlay (+ free RAM for the compact one).
					 * ARGV[2] ('standard'|'upx') is an advanced override; size-checked either way.
					 * This is the guardrail for the "full binary truncates on a small overlay →
					 * SIGBUS" trap: never offer a build the device can't actually hold/run. */
					let chosen = variant;
					let note = variant === 'upx'
						? 'compact (UPX) build - fork-only: the original repository publishes no compact builds'
						: null;
					/* UPX-compressed binaries are crash-prone (SIGILL on startup) on these
					 * soft-float MIPS targets, so never AUTO-pick the compact build there —
					 * fall back to standard, or error cleanly. An explicit variant='upx'
					 * override is still honored (advanced users). Non-MIPS arches (incl.
					 * aarch64 like MT7622) are unaffected. */
					const mips_no_auto_upx = (arch === 'mipsel_24kc' || arch === 'mips_24kc');
					if (chosen !== 'standard' && chosen !== 'upx') {
						if (overlay_free_kb >= full_need)
							chosen = 'standard';
						else if (mips_no_auto_upx)
							chosen = null;   /* don't squeeze a crash-prone compact build onto tight-flash MIPS */
						else if (overlay_free_kb >= COMPACT_OVERLAY_KB && ram_free_kb >= COMPACT_RAM_KB) {
							chosen = 'upx';
							note = 'Limited storage — installing the compact build (decompresses into RAM at launch).';
						} else
							chosen = null;
					}

					if (!chosen) {
						result = mips_no_auto_upx
							? { error: `Not enough overlay for the full build: ${overlay_free_kb} KB free, need ~${full_need} KB. The compact build is not offered on MIPS (UPX is unreliable there). Free up space, or bake the core into a custom firmware image.` }
							: (overlay_free_kb >= COMPACT_OVERLAY_KB)
							? { error: `Device too constrained: ${overlay_free_kb} KB free overlay (full build needs ~${full_need}) and only ${ram_free_kb} KB free RAM (compact build needs ~${COMPACT_RAM_KB}). Use sing-box-extended instead.` }
							: { error: `Not enough storage: ${overlay_free_kb} KB free overlay, need at least ~${COMPACT_OVERLAY_KB} KB (~25 MB).` };
					} else {
						const need = (chosen === 'upx') ? COMPACT_OVERLAY_KB : full_need;
						if (overlay_free_kb < need) {
							result = { error: `Not enough overlay space for the ${chosen === 'upx' ? 'compact' : 'full'} build: ${overlay_free_kb} KB free, need ~${need} KB.` };
						} else {
							const hp_path = (chosen === 'upx') ? 'download/upx' : 'latest/download';
							result = {
								pkg_manager, arch, variant: chosen, note,
								source: 'fork',
								dl_url: `https://github.com/1andrevich/hiddify-core/releases/${hp_path}/hiddify-core_${arch}${ext}`,
								tmp_path: `/tmp/hiddify-core${ext}`
							};
						}
					}
					}
				} else if (sb_feed_hit) {
					result = sb_feed_hit;
				} else if (overlay_free_kb < full_need) {
						result = { error: `Not enough overlay space: ${overlay_free_kb} KB free, sing-box-extended needs ~${full_need} KB.` };
					} else {
						const api_fd = popen('wget -qO- --timeout=10 https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest 2>/dev/null');
						if (!api_fd) {
							result = { error: 'failed to contact GitHub API' };
						} else {
							const api_raw = trim(api_fd.read('all')); api_fd.close();
							let api_data;
							try { api_data = json(api_raw); } catch(e) { api_data = null; }
							if (!api_data?.tag_name) {
								result = { error: 'could not determine latest version from GitHub' };
							} else {
								let dl_url = null;
								for (let asset in (api_data?.assets || [])) {
									const n = asset?.name || '';
									if (!match(n, /openwrt/)) continue;
									if (length(split(n, arch)) < 2) continue;
									if (ext === '.apk' && !match(n, /\.apk$/)) continue;
									if (ext === '.ipk' && !match(n, /\.ipk$/)) continue;
									dl_url = asset?.browser_download_url;
									break;
								}
								if (!dl_url)
									result = { error: `no package found for arch ${arch} in latest release` };
								else
									result = { pkg_manager, arch, dl_url, tmp_path: `/tmp/sing-box-extended${ext}` };
							}
						}
					}
				}
			}
		}
	}

} else if (action === 'download_pkg') {
	/* UI calls (url, tmp_path). Also tolerate an optional leading core arg
	 * (download_pkg <core> <url> <tmp_path>) so callers that mirror the
	 * prepare_install/install_pkg core-first signature don't silently fail. */
	let url      = ARGV[1];
	let tmp_path = ARGV[2];
	if (ARGV[3] && (ARGV[1] in ['hiddify', 'singbox', 'singbox-lite'])) {
		url      = ARGV[2];
		tmp_path = ARGV[3];
	}
	if (!url || !tmp_path) {
		result = { result: false, error: 'missing arguments' };
	} else {
		const exit_code = gh_fetch(url, tmp_path, 300000);   /* GitHub first, mirror fallback */
		result = exit_code === 0 ? { result: true } : { result: false, error: 'download failed' };
	}

} else if (action === 'install_pkg') {
	const core        = ARGV[1];
	const tmp_path    = ARGV[2];
	const pkg_manager = ARGV[3];
	if (!(core in ['hiddify', 'singbox', 'singbox-lite']) || !tmp_path || !pkg_manager) {
		result = { result: false, error: 'invalid arguments' };
	} else if (core === 'singbox-lite') {
		/* The lite project ships install.sh only (no apk/ipk): it downloads the
		 * right tar.gz for the arch, validates the binary, swaps it and
		 * restarts the services it stopped (with an automatic rollback to the
		 * previous binary if the new core does not come up). Run it with the
		 * variant flag prepare_install already chose; keep the log for
		 * diagnostics and confirm the core is actually running afterwards. */
		if (!match(tmp_path, /^\/tmp\/[a-zA-Z0-9._-]+\.sh$/)) {
			result = { result: false, error: 'unexpected installer path' };
		} else {
			const vm = match(tmp_path, /-(normal|compressed)\.sh$/);
			const lflag = (vm && vm[1] === 'compressed') ? '--compressed' : '--normal';
			const logf = '/tmp/sing-box-lite-install.log';
			/* 900 s: the installer downloads its own tarball INSIDE this call
			 * (~46 MB for --normal — minutes on a throttled uplink), then
			 * swaps, restarts the service and runs its health-check. The
			 * detached runner already caps this stage at 900 s; the inner cap
			 * matched (300 s before ch.125) and defeated that headroom. */
			const exit_code = system(
				`{ sh ${shellquote(tmp_path)} ${lflag}; } >${shellquote(logf)} 2>&1` +
				`; RC=$?; rm -f ${shellquote(tmp_path)}; exit $RC`,
				900000
			);
			/* The installer's own post-start health check polls `pidof sing-box`
			 * — but the service runs whichever core Preferred core names. On a
			 * router whose active core is hiddify (or any non-sing-box core) the
			 * poll can never succeed, the installer "fails" AFTER swapping the
			 * binary and leaves the service STOPPED. Detect that state: the
			 * on-disk binary is a valid lite build → recover the service and
			 * report success with an honest note. */
			if (exit_code !== 0) {
				const vfd = popen('/usr/bin/sing-box version 2>/dev/null');
				const vout = vfd ? vfd.read('all') : '';
				if (vfd) vfd.close();
				const lite_now = !!match(vout, /-extended-/) &&
					!match(vout, /with_gvisor/) && !match(vout, /with_tailscale/);
				if (lite_now) {
					system('/etc/init.d/ravnex start >/dev/null 2>&1');
					result = { result: true,
						note: 'installed; the installer health-check only watches sing-box and returned an error (the active core is not sing-box) — the service was restarted' };
				} else {
					result = { result: false, error: `lite installer failed — see ${logf}` };
				}
		} else {
			/* Ф1.4b: identity liveness (exact /proc scan) — the lite build
			 * runs as sing-box-core, both runtime names checked. */
			const alive = length(pm_find({ exe: 'sing-box' })) > 0 ||
				length(pm_find({ exe: 'sing-box-core' })) > 0;
			result = alive
				? { result: true }
				: { result: true, warning: `installer finished but sing-box is not running — see ${logf}` };
		}
		}
	} else if (core === 'hiddify' && match(tmp_path, /\.tar\.gz$/)) {
		/* ч.129 (ан-146): апстрим-тарбол hiddify/hiddify-core. Структура:
		 * hiddify-core-linux-<target>[-musl]/hiddify-core (+ LICENSE.md).
		 * Распаковка прямо в staging НА ОВЕРЛЕЕ (не в /tmp — бинарник ~101 МиБ,
		 * tmpfs его не удержит на малых роутерах), валидный запуск, атомарный
		 * mv на /usr/bin/hiddify-core, уборка staging+тарбола. mv внутри одного
		 * оверлея = rename(2) без копирования. */
		const stage = '/usr/libexec/.hiddify-up';
		const cmd =
			`{ rm -rf ${shellquote(stage)}; mkdir -p ${shellquote(stage)}; }` +
			` && tar -xzf ${shellquote(tmp_path)} -C ${shellquote(stage)}` +
			` && BIN=$(find ${shellquote(stage)} -type f -name hiddify-core | head -n1)` +
			` && [ -n "$BIN" ] && [ -s "$BIN" ]` +
			` && "$BIN" version >/dev/null 2>&1` +
			` && mv -f "$BIN" /usr/bin/hiddify-core` +
			` && rm -rf ${shellquote(stage)} ${shellquote(tmp_path)}`;
		const exit_code = system(cmd, 300000);
		result = exit_code === 0
			? { result: true, note: 'upstream tar.gz build installed' }
			: { result: false, error: 'upstream tarball extraction/validation failed' };
	} else {
		let exit_code;
		if (core === 'hiddify' && pkg_manager === 'apk') {
			/* Signing key: skip the fetch if already present (a provisioning tool may pre-place
			 * it); else GitHub-first, mirror-FALLBACK via gh_fetch, best-effort (a
			 * throttled/blocked GitHub must NOT fail the install — the package already
			 * arrived over HTTPS). Install trusted if the key is there, else untrusted. */
			if (!access('/etc/apk/keys/homeproxy-hiddify.pub')) {
				if (gh_fetch('https://github.com/1andrevich/homeproxy-hiddify/releases/latest/download/homeproxy-hiddify.pub', '/tmp/homeproxy-hiddify.pub', 20000) === 0)
					system('[ -s /tmp/homeproxy-hiddify.pub ] && cp /tmp/homeproxy-hiddify.pub /etc/apk/keys/ 2>/dev/null; rm -f /tmp/homeproxy-hiddify.pub');
			}
			if (access('/etc/apk/keys/homeproxy-hiddify.pub'))
				exit_code = system(`apk add ${shellquote(tmp_path)} >/dev/null 2>&1; RC=$?; rm -f ${shellquote(tmp_path)}; exit $RC`, 120000);
			else
				exit_code = system(`apk add --allow-untrusted ${shellquote(tmp_path)} >/dev/null 2>&1; RC=$?; rm -f ${shellquote(tmp_path)}; exit $RC`, 120000);
		} else if (pkg_manager === 'apk') {
			/* sing-box-extended has no signing key — allow-untrusted is unavoidable */
			exit_code = system(
				`{ apk add --allow-untrusted ${shellquote(tmp_path)}; } >/dev/null 2>&1` +
				`; RC=$?; rm -f ${shellquote(tmp_path)}; exit $RC`,
				120000
			);
		} else {
			exit_code = system(
				`{ opkg install --force-reinstall ${shellquote(tmp_path)}; } >/dev/null 2>&1` +
				`; RC=$?; rm -f ${shellquote(tmp_path)}; exit $RC`,
				120000
			);
		}
		result = exit_code === 0 ? { result: true } : { result: false, error: 'package installation failed' };
	}

} else if (action === 'install_feed_pkg') {
	/* §1.7 V2: install a feed package by EXPLICIT FILE (the runner passes
	 * prep.feed_pkg from a feed-hit prepare_install). The generalized
	 * feed_install_pkg handles every feed package: manifest → exact file →
	 * ladder download → sha256 gate → apk add ./file (signature checked by
	 * apk against our key) | opkg install ./file → sibling removal bounded
	 * to the two own families → post-check access(). The service is NOT
	 * restarted here — same contract as before (the caller restarts the
	 * service after a successful install). */
	const feed_pkg = ARGV[1];
	if (!match(feed_pkg, /^[a-z0-9-]+$/) || length(feed_pkg) > 64) {
		result = { result: false, error: 'invalid feed package name' };
	} else if (!feed_configured()) {
		result = { result: false, error: 'own feed is not configured' };
	} else {
		result = feed_install_pkg(feed_pkg);
	}

} else if (action === 'postcheck_restart') {
	/* Field report 2026-11-08 (hiddify-core 5.1.0→5.5.5): the feed path used
	 * to end on a replaced FILE while the RUNNING core kept serving the old
	 * binary — nobody restarted the service on this branch (the "caller
	 * restarts" contract had no caller). Tail of the feed core install:
	 * probe the NEW binary FIRST — a broken build must never take the
	 * service down (the old core keeps serving, the op fails honestly);
	 * only a healthy probe earns the restart, then an identity liveness
	 * wait with the same exe set the sentinel/registry uses. */
	const core = ARGV[1];
	const expect = trim(ARGV[2] || '');
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { result: false, error: 'illegal core' };
	} else {
		const bin = (core === 'hiddify') ? '/usr/bin/hiddify-core' : '/usr/bin/sing-box';
		if (!access(bin)) {
			result = { result: false, error: `core binary ${bin} absent after install` };
		} else {
			/* the replaced file (mtime+size changed) re-probes automatically */
			const info = core_features_cached(bin);
			if (!info || !info.version)
				result = { result: false, error: 'новый бинарник не отвечает на version — перезапуск отменён, прежнее ядро продолжает работать' };
			else if (length(expect) && feed_vercmp_base(feed_strip_rev('' + info.version), feed_strip_rev('' + expect)) !== 0)
				result = { result: false, error: `после установки бинарник отвечает ${info.version}, ожидалось ${expect} — перезапуск отменён` };
			else {
				/* Detached restart with rc collection — a 2-arg system()
				 * deadline KILLS the init script mid-flight and leaves the
				 * service STOPPED (field-proven 2026-11-09 01:35: the postcheck
				 * restart stall outlived the 120 s cap, the killed shell
				 * stopped the service and the start phase never ran). The
				 * restart runs detached, we only POLL liveness and never
				 * kill: an orphaned init script finishes its work, and the
				 * sentinel auto-starts a dead core as a backstop. */
				system('rm -f /tmp/hp_pc.rc /tmp/hp_pc.pid');
				system('( /etc/init.d/ravnex restart >/dev/null 2>&1; echo $? > /tmp/hp_pc.rc ) </dev/null & echo $! > /tmp/hp_pc.pid');
				let alive = false;
				/* 🔴 ucode for..in over an ARRAY yields ELEMENTS (not indices —
				 * the same construct feed_fetch relies on with `u.repo`), so
				 * `exes[e]` inside for..in was undefined and pm_find was called
				 * with a broken spec 48 times: the live core was never seen
				 * (first E2E run, 2026-11-09). Classic indexed loop instead,
				 * exe set identical to config_heal/zapret_autopilot. */
				for (let i = 0; i < 48 && !alive; i++) {
					sleep(5000);
					if (core === 'hiddify')
						alive = length(pm_find({ exe: 'hiddify-core' })) > 0;
					else
						alive = length(pm_find({ exe: 'sing-box' })) > 0 ||
							length(pm_find({ exe: 'sing-box-core' })) > 0;
				}
				result = alive
					? { result: true, alive: true, version: info.version }
					: { result: true, alive: false, version: info.version,
						error: 'новое ядро не поднялось за ~240 с — установка честно не завершена; рестарт продолжается в фоне, Sentinel также поднимет ядро (hiddify-c.log)' };
			}
		}
	}

} else if (action === 'install_kmods') {
	const pkg_manager = ARGV[1] || detect_pkg_manager();
	let exit_code = 1;
	/* No --no-cache: it forces apk to refetch the package index over the network
	 * (slow / >60s on poor uplinks, and the index is usually already cached from the
	 * app install). The kmods are tiny and resolve from the local index in seconds. */
	if (pkg_manager === 'apk')
		exit_code = system('apk add kmod-nft-tproxy kmod-tun >/dev/null 2>&1', 120000);
	else if (pkg_manager === 'opkg')
		exit_code = system('opkg install kmod-nft-tproxy kmod-tun >/dev/null 2>&1', 60000);
	result = (exit_code === 0)
		? { result: true }
		: { result: false, error: `kmod install failed (pkg_manager=${pkg_manager || 'none'})` };

} else if (action === 'remove') {
	const core = ARGV[1];
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { result: false, error: 'illegal core' };
	} else if (core === 'singbox-lite') {
		/* lite was never installed through the package manager — its files are
		 * plain binaries under /usr/bin (+ a version cache). IMPORTANT: full
		 * and lite SHARE the /usr/bin/sing-box path, so only delete when the
		 * on-disk binary is actually the lite build (compressed wrapper, or a
		 * normal ELF whose version output identifies lite). */
		const sb = '/usr/bin/sing-box';
		const is_wrapper = access(sb) && bin_bytes(sb) < LITE_WRAPPER_MAX_BYTES;
		let is_lite = is_wrapper;
		if (!is_wrapper && access(sb)) {
			/* cached wrapper is mtime/size-validated — a replaced binary re-probes */
			const f = core_features_cached(sb);
			is_lite = !!f.extended && !f.wrapper && (f.lite ?? false);
		}
		if (!access(sb)) {
			result = { result: true, removed: [], note: 'sing-box is not present' };
		} else if (!is_lite) {
			result = { result: false, error: 'this path holds the FULL sing-box-extended build — remove it from the sing-box-extended card' };
		} else {
			/* Stop the service first: procd must not respawn the (deleted)
			 * core, and a restart after removal may have no core left. */
			system('/etc/init.d/ravnex stop >/dev/null 2>&1');
			const targets = [sb, '/usr/libexec/sing-box-core', '/etc/sing-box-version.cache'];
			let removed = [];
			for (let f in targets)
				if (access(f)) {
					system(`rm -f ${shellquote(f)} 2>/dev/null`);
					push(removed, f);
				}
			/* Restart only when another core can take over; otherwise leave
			 * the service stopped (interception is down either way) and say
			 * so honestly. */
			if (access('/usr/bin/hiddify-core')) {
				system('/etc/init.d/ravnex start >/dev/null 2>&1');
				result = { result: true, removed };
			} else {
				result = { result: true, removed, warning: 'no other core installed — the service is stopped; install hiddify-core or sing-box-extended to run the proxy' };
			}
		}
	} else {
		const pkg_manager = detect_pkg_manager();
		if (!pkg_manager) {
			result = { result: false, error: 'no supported package manager found' };
		} else {
			const pkg_name = core === 'hiddify' ? 'hiddify-core' : 'sing-box-extended';
			const exit_code = pkg_manager === 'apk'
				? system(`apk del ${pkg_name} >/dev/null 2>&1`, 30000)
				: system(`opkg remove ${pkg_name} >/dev/null 2>&1`, 30000);
			result = { result: (exit_code === 0) };
		}
	}

} else {
	result = { error: `unknown action: ${action}` };
}

printf('%s\n', result);
