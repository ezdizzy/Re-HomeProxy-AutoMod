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

/* GitHub API request (seance 177). curl-first (TSPU lesson 161), wget fallback;
 * the user's GitHub token (uci ravnex.config.github_token) rides along when
 * set — anonymous API calls burn the shared egress rate limit, authenticated
 * ones don't. A missing/throttled token only drops the header, never breaks
 * the call. Returns parsed JSON or null. */
function gh_token() {
	const fd = popen('uci -q get ravnex.config.github_token 2>/dev/null');
	if (!fd) return '';
	const t = trim(fd.read('all'));
	fd.close();
	return t;
}

function gh_api(url, timeout_ms) {
	const tok = gh_token();
	const auth = length(tok) ? `--header "Authorization: token ${tok}" ` : '';
	/* 8 s hard cap PER ATTEMPT: prepare/check_remote run synchronously under
	 * the LuCI XHR timeout (20 s) — curl(8) + wget(8) is the worst case. */
	const curl = gh_has_curl();
	let raw = '';
	if (curl) {
		const fd = popen(`${curl} -fsL --connect-timeout 6 --max-time 8 ${auth}${shellquote(url)} 2>/dev/null`);
		if (fd) { raw = trim(fd.read('all')); fd.close(); }
	}
	if (!length(raw)) {
		const wfd = popen(`wget -qO- --timeout=8 ${auth}${shellquote(url)} 2>/dev/null`);
		if (wfd) { raw = trim(wfd.read('all')); wfd.close(); }
	}
	if (!length(raw))
		return null;
	let data;
	try { data = json(raw); } catch (e) { data = null; }
	return data;
}

/* Per-asset SHA256 digest (GitHub API "digest": "sha256:<hex>") — the honesty
 * gate for every original-source download (decision 3). Returns the hex part
 * or '' when the asset carries no digest. */
function asset_digest(asset) {
	const d = (asset && asset.digest) ? '' + asset.digest : '';
	const m = match(d, /^sha256:([0-9a-f]{64})$/);
	return m ? m[1] : '';
}

/* Pick one release asset by exact name or by prefix+suffix bounds. All string
 * ops (no dynamic regex in ucode). Returns { name, url, sha256 } or null. */
function asset_find(assets, name_prefix, name_suffix) {
	for (let a in (assets || [])) {
		const n = '' + (a?.name || '');
		if (!length(n)) continue;
		if (length(name_prefix) && substr(n, 0, length(name_prefix)) != name_prefix) continue;
		if (length(name_suffix)) {
			const tail = substr(n, length(n) - length(name_suffix));
			if (tail != name_suffix) continue;
		}
		return { name: n, url: a?.browser_download_url || null, sha256: asset_digest(a) };
	}
	return null;
}

/* Latest release tag of a repo, stripped of the leading "v" ('' on failure). */
function gh_repo_latest_version(repo) {
	const data = gh_api(`https://api.github.com/repos/${repo}/releases/latest`);
	if (!data || !data.tag_name) return '';
	return replace('' + data.tag_name, /^v/, '');
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

/* Footprint thresholds (KB) for the upstream hiddify-core FULL build.
 * Пороги полной апстрим-сборки v5.x (arm64-musl: бинарник ≈101 МиБ, тарбол
 * ≈35.4 МиБ, apk-ассет ≈35-40 МиБ) — крупнее старой форковой (Go 1.27 +
 * cronet). Тарбол/apk кладётся в /tmp, бинарник распаковывается прямо в
 * оверлей (staging) → swap либо ставится пакетом. */
const FULL_OVERLAY_RAW_KB  = 81920;   /* ~80 MB free for the full binary on an uncompressed overlay */
const FULL_OVERLAY_COMP_KB = 32768;   /* ~32 MB on a compressing overlay (binary stores ~3x smaller) */
const UP_FULL_OVERLAY_RAW_KB  = 112640;   /* ~110 MB на несжимающем оверлее */
const UP_FULL_OVERLAY_COMP_KB = 40960;    /* ~40 MB на сжимающем (jffs2/ubifs) */
const UP_FULL_TMP_KB          = 46080;    /* тарбол + запас в /tmp */

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

/* ── Сеанс 177 (ч.265): «ВСЁ ИЗ ОРИГИНАЛЬНЫХ РЕПОЗИТОРИЕВ» — карта источников ──
 * Все ядра тянутся ТОЛЬКО из оригинальных репозиториев (решения ×10, план 25).
 * hiddify/hiddify-core с v5.4.0 ПУБЛИКУЕТ OpenWrt-пакеты apk+ipk для 31 арх
 * (имена: hiddify-core-<ver>-r<N>_<openwrt-arch>.apk / hiddify-core_<ver>_
 * <openwrt-arch>.ipk, musl; naive/cronet-флейвор НЕ брать — musl-CGO тарболы
 * несут NaïveProxy, пакетные — тоже musl-сборка). Релизы пушит CI почти
 * ежедневно — гейт «не новее latest» считается по релизу при установке.
 * Форк 1andrevich СОВСЕМ УШЁЛ (заморожен на v4.1.0; его единственная функция —
 * публикация пакетов — теперь у оригинала). Компактной UPX-сборки у hiddify-core
 * НЕ СУЩЕСТВУЕТ — вариант честно не предлагается (решение 2).
 * sing-box-extended = shtorm-7 (apk+ipk ×31 арх: sing-box-extended_<ver>_
 * openwrt_<arch>.{apk,ipk}; UPX-вариант = -compressed тарболы).
 * sing-box-extended-lite = MANCrimSon (ТОЛЬКО тарболы ×5 арх: amd64/arm64/
 * armv7/mips-softfloat/mipsle-softfloat, есть -compressed UPX-варианты;
 * их install.sh остаётся фолбэком, прямой тарбол-путь — первичен и гейтуется).
 * Целостность: SHA256 = per-asset digest из GitHub API (решение 3), установка
 * пакетов с --allow-untrusted. Роллбэк = ЯВНАЯ кнопка (выбор тега → download →
 * SHA256 → подтверждение; БЕЗ кэшей на роутере, решение 8). */
const HIDDIFY_REPO          = 'hiddify/hiddify-core';
const HIDDIFY_UPSTREAM_DL   = 'https://github.com/hiddify/hiddify-core/releases/latest/download/';
const HIDDIFY_UPSTREAM_API  = 'https://api.github.com/repos/hiddify/hiddify-core/releases/latest';
/* OpenWrt OPENWRT_ARCH → апстрим-тарбол (musl CGO, где cronet существует;
 * статические для MIPS/старых ARM — без NaïveProxy). Первичный путь —
 * ОРИГИНАЛЬНЫЕ apk/ipk (см. карту выше); тарбол = фолбэк для архов/тегов,
 * где пакета нет, и для «не влезает в пороги пакета» сценариев нет — пакет
 * и тарбол несут одинаковый musl-бинарник. */
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

/* Смешанная карта OPENWRT_ARCH → Go-таргет для тарбол-семейства shtorm-7/
 * MANCrimSon (производные sing-box). Только реально существующие ассеты;
 * отсутствие значения = честный отказ prepare_install (в отличие от форк-эры
 * никаких «откуда ни возьмись» сборок не подставляем). */
const GOARCH_LITE = {
	'aarch64_generic':      'arm64',
	'aarch64_cortex-a53':   'arm64',
	'aarch64_cortex-a72':   'arm64',
	'aarch64_cortex-a76':   'arm64',
	'x86_64':               'amd64',
	'mipsel_24kc':          'mipsle-softfloat',
	'mipsel_74kc':          'mipsle-softfloat',
	'mips_24kc':            'mips-softfloat',
	'arm_cortex-a7_neon-vfpv4': 'armv7',
	'arm_cortex-a7_vfpv4':  'armv7',
	'arm_cortex-a15_neon-vfpv4': 'armv7'
};
/* shtorm-7 -compressed (UPX) тарболы шире lite: + 386/riscv64/softfloat-BE
 * отсутствуют у lite. Те же ключи, что GOARCH_LITE, плюс слабые архи. */
const GOARCH_SBX = {
	'aarch64_generic':      'arm64',
	'aarch64_cortex-a53':   'arm64',
	'aarch64_cortex-a72':   'arm64',
	'aarch64_cortex-a76':   'arm64',
	'x86_64':               'amd64',
	'i386_pentium4':        '386',
	'i386_pentium-mmx':     '386',
	'mipsel_24kc':          'mipsle-softfloat',
	'mipsel_74kc':          'mipsle-softfloat',
	'mipsel_mips32':        'mipsle-softfloat',
	'mipsel_24kc_24kf':     'mipsle',
	'mips_24kc':            'mips-softfloat',
	'mips_4kec':            'mips-softfloat',
	'mips_mips32':          'mips-softfloat',
	'arm_cortex-a5_vfpv4':  'armv7',
	'arm_cortex-a7_neon-vfpv4': 'armv7',
	'arm_cortex-a7_vfpv4':  'armv7',
	'arm_cortex-a8_vfpv3':  'armv7',
	'arm_cortex-a9_neon':   'armv7',
	'arm_cortex-a9_vfpv3-d16': 'armv7',
	'arm_cortex-a15_neon-vfpv4': 'armv7',
	'riscv64_generic':      'riscv64'
};

/* Единые адреса оригиналов (де-форк, сеанс 177). */
const SBX7_REPO            = 'shtorm-7/sing-box-extended';
const SBX7_API             = 'https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest';
const LITE_REPO            = 'MANCrimSon/sing-box-extended-lite';
const LITE_REPO_API        = 'https://api.github.com/repos/MANCrimSon/sing-box-extended-lite/releases/latest';
const LITE_INSTALLER_URL   = 'https://raw.githubusercontent.com/MANCrimSon/sing-box-extended-lite/main/install.sh';

/* Repo API base per core family (de-fork map, seance 177).
 * 🔴 ucode lex-resolution: helper functions must be declared AFTER every
 * const they reference (a const declared later is undeclared inside an
 * earlier-defined function body — live-caught on remote_tags, ч.265). */
function core_repo(core) {
	return (core === 'hiddify') ? HIDDIFY_REPO
		: (core === 'singbox') ? SBX7_REPO : LITE_REPO;
}

/* Space gates shared by prepare_install/prepare_rollback (same thresholds the
 * old branches enforced; UPX tarball needs flash for the packed binary but
 * RAM for the decompressed image at launch). Returns null or an error string. */
function core_space_gate(kind, overlay_free_kb, tmp_free_kb, ram_free_kb) {
	const comp = overlay_compresses();
	if (kind === 'lite_tarball') {
		/* lite: gates already applied by the lite branch (effective-flash
		 * accounting with the replaced-binary credit) — nothing here. */
		return null;
	}
	const overlay_need = (kind === 'sbx_upx') ? 35840
		: (comp ? UP_FULL_OVERLAY_COMP_KB : UP_FULL_OVERLAY_RAW_KB);
	const tmp_need = (kind === 'sbx_upx') ? 46080 : UP_FULL_TMP_KB;
	if (overlay_free_kb < overlay_need)
		return `Not enough overlay space for the ${kind === 'sbx_upx' ? 'UPX-compressed' : 'full'} build: ${overlay_free_kb} KB free, need ~${overlay_need} KB.`;
	if (tmp_free_kb < tmp_need)
		return `not enough /tmp space: ${tmp_free_kb} KB free, need ~${int(tmp_need / 1024)} MB`;
	if (kind === 'sbx_upx' && ram_free_kb < 98304)
		return `Not enough RAM for the UPX build: ${ram_free_kb} KB free (need ~96 MB — the UPX binary decompresses into RAM at launch).`;
	return null;
}

/* Resolve ONE core asset out of a release object (de-fork, seance 177).
 * hiddify: original apk/ipk preferred (hiddify-core-<ver>-r<N>_<arch>.<ext> /
 * hiddify-core_<ver>_<arch>.<ext>), upstream tarball fallback (arch map).
 * singbox: shtorm-7 openwrt apk/ipk (sing-box-extended_<ver>_openwrt_<arch>.
 * <ext>); variant 'upx' = -compressed tarball (GOARCH_SBX). lite: MANCrimSon
 * tarball (GOARCH_LITE), variant normal|compressed. Returns
 * { kind, pick:{name,url,sha256}, ver, goarch? } or { error }. */
function resolve_original_asset(core, variant, rel, pkg_manager, arch) {
	const ext = (pkg_manager === 'apk') ? '.apk' : '.ipk';
	const ver = (rel && rel.tag_name) ? replace('' + rel.tag_name, /^v/, '') : null;
	if (!length(ver))
		return { error: 'release has no tag' };
	const assets = rel.assets || [];
	if (core === 'hiddify') {
		let pick = asset_find(assets, `hiddify-core-${ver}-r`, `_${arch}${ext}`);
		if (!pick)
			pick = asset_find(assets, `hiddify-core_${ver}_`, `_${arch}${ext}`);
		if (pick && length(pick.url))
			return { kind: 'pkg', pick, ver };
		const tb = HIDDIFY_UPSTREAM_ASSET[arch] || null;
		if (!tb)
			return { error: `оригинал hiddify-core не публикует пакет или тарбол для архитектуры ${arch}` };
		const tpick = asset_find(assets, tb, '.tar.gz');
		if (tpick && length(tpick.url))
			return { kind: 'tarball', pick: tpick, ver };
		/* asset list blind (drafts/throttle) — latest/download path without digest */
		return { kind: 'tarball', pick: { name: tb, url: HIDDIFY_UPSTREAM_DL + tb, sha256: '' }, ver };
	}
	if (core === 'singbox') {
		if (variant === 'upx') {
			const ga = GOARCH_SBX[arch] || null;
			if (!ga)
				return { error: `UPX-сборка sing-box-extended не публикуется для архитектуры ${arch}` };
			const name = `sing-box-${ver}-linux-${ga}-compressed.tar.gz`;
			const pick = asset_find(assets, name, '.tar.gz');
			if (!pick || !length(pick.url))
				return { error: `в релизе shtorm-7 нет ${name}` };
			return { kind: 'sbx_upx', pick, ver, goarch: ga };
		}
		const pick = asset_find(assets, `sing-box-extended_${ver}_openwrt_${arch}`, ext);
		if (pick && length(pick.url))
			return { kind: 'pkg', pick, ver };
		return { error: `в релизе shtorm-7 нет пакета для ${arch}${ext}` };
	}
	/* singbox-lite */
	const ga = GOARCH_LITE[arch] || null;
	if (!ga)
		return { error: `MANCrimSon не публикует сборку для архитектуры ${arch} (доступны: amd64/arm64/armv7/mips-softfloat/mipsle-softfloat)` };
	const suffix = (variant === 'compressed') ? '-compressed' : '';
	const name = `sing-box-extended-lite-${ver}-linux-${ga}${suffix}.tar.gz`;
	const pick = asset_find(assets, name, '.tar.gz');
	if (!pick || !length(pick.url))
		return { error: `в релизе MANCrimSon нет ${name}` };
	return { kind: 'lite_tarball', pick, ver, goarch: ga };
}

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
/* Single repo since the rename — see the luci.ravnex feed block (ч.286). */
const FEED_REPOS = ['ezdizzy/ravnex'];
/* s200: whitelist of feed packages this build serves — mirrors FEED_PKGS in
 * luci.ravnex verbatim (зеркало ч.223: двойные копии синхронизировать ВСЕГДА).
 * The install_feed_pkg action refuses foreign names with an honest error;
 * the manifest remains the truth for versions/files inside feed_install_pkg. */
const FEED_PKGS = ['mosdns', 'probe_pool',
	'sni_sniffer', 'byedpi', 'zapret2'];
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

/* Zoo coverage for the version gates: the PM record and the on-disk binary
 * can DIVERGE (field case: apk record hiddify-core-4.1.0 = an old fork
 * package while the binary is the 5.1.0 upstream tarball), and a file
 * install overwrites the BINARY — live-proven on apk 3.0.5 (session 173):
 * `apk add ./older.apk` downgrades silently ("Downgrading a -> b"), rewrites
 * the world pin and exits 0. The downgrade gate therefore compares the feed
 * candidate against the BINARY version too, whenever a probe exists. */
function feed_bin_version(pkg) {
	const bin = FEED_BIN_PATH[pkg];
	if (!bin || !access(bin))
		return null;
	if (pkg === 'hiddify-core' || pkg === 'hiddify-core-compact' ||
	    pkg === 'sing-box-extended' || pkg === 'sing-box-extended-lite') {
		const bi = core_features_cached(bin);
		return (bi && bi.version) ? '' + bi.version : null;
	}
	if (pkg === 'mosdns') {
		const fd = popen(shellquote(bin) + ' version 2>/dev/null');
		if (fd) {
			const out = trim(fd.read('all'));
			fd.close();
			const m = match(out, /v?([0-9]+(\.[0-9]+)*)/);
			return m ? m[1] : null;
		}
	}
	if (pkg === 'probe_pool' || pkg === 'sni_sniffer') {
		const fd = popen(shellquote(bin) + ' -version 2>/dev/null');
		if (fd) {
			const out = trim(fd.read('all'));
			fd.close();
			const m = match(out, /([0-9]+\.[0-9]+\.[0-9]+)/);
			return m ? m[1] : null;
		}
	}
	/* zapret2/byedpi: no stable -version probe — the PM record governs. */
	return null;
}

/* Silent-downgrade gate (ch.261(1г) gate survives the de-fork, seance 177):
 * a NON-rollback install whose candidate is OLDER than the running binary is
 * refused — the PM record alone cannot catch it (absent on tarball boxes), so
 * the comparison runs against the RUNNING BINARY probe. prepare carries the
 * candidate version; the runner forwards it (ARGV[4]) with mode ARGV[5]:
 * ONLY the explicit rollback action (a user-chosen older tag) bypasses this
 * gate. Equal (repair/reinstall) and newer stay allowed; a failed version
 * lookup never blocks the install — postcheck_restart keeps the outcome
 * honest. */
function core_downgrade_error(core, cand_ver) {
	const bin = (core === 'hiddify') ? '/usr/bin/hiddify-core' : '/usr/bin/sing-box';
	const cur_info = core_features_cached(bin);
	const cur = (cur_info && cur_info.version) ? '' + cur_info.version : '';
	if (!length(cur) || !length(cand_ver))
		return null;
	return (feed_vercmp_base(feed_strip_rev('' + cand_ver), feed_strip_rev(cur)) < 0)
		? `candidate ${cand_ver} is OLDER than the running core ${cur} - refusing a silent downgrade (use the explicit rollback action to install an older release)`
		: null;
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
	/* 🔴 Downgrade honesty (mirror of the rpcd copy + zoo coverage, ch.248/260
	 * + session 173): never silently downgrade. The gate holds against BOTH
	 * the PM record and the probed binary — the zoo (record older than the
	 * running binary) must not let a file-install regress the binary. A
	 * repair/reinstall of the SAME version stays allowed (live-proven:
	 * `apk add ./same.apk` reinstalls cleanly, rc=0). Checked BEFORE the
	 * download — a refusal must not cost a 100 MB fetch. */
	const prev_ver = feed_installed_version(pkg);
	const bin_ver = feed_bin_version(pkg);
	const known = [];
	if (prev_ver != null) push(known, 'запись ' + prev_ver);
	if (bin_ver != null) push(known, 'бинарник ' + bin_ver);
	if ((prev_ver != null && feed_vercmp_base(feed_strip_rev('' + entry.version), feed_strip_rev('' + prev_ver)) < 0) ||
	    (bin_ver != null && feed_vercmp_base(feed_strip_rev('' + entry.version), feed_strip_rev('' + bin_ver)) < 0))
		return { result: false, error: `в фиде ${pkg} ${entry.version} не новее установленного (${join(', ', known)}) — установка отменена` };
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
	} else {
		/* ч.265 (де-форк): для КАЖДОГО семейства оригинал публикует релизы —
		 * check_remote только читает latest (токен ездит с gh_api). Годность
		 * архива/ассета и порогов места — работа prepare_install. */
		const api_url = (core === 'hiddify') ? HIDDIFY_UPSTREAM_API
			: (core === 'singbox') ? SBX7_API : LITE_REPO_API;
		const data = gh_api(api_url, 12000);
		if (data && data.tag_name)
			result = { tag: data.tag_name, version: replace(data.tag_name, /^v/, ''), source: 'upstream' };
		else if (data)
			result = { error: 'could not read tag_name from response' };
		else
			result = { error: 'no response from GitHub API' };
	}

} else if (action === 'prepare_install') {
	const core = ARGV[1];
	const variant = ARGV[2] || '';   /* singbox: 'standard' | 'upx' (original -compressed tarball); lite: 'normal' | 'compressed'; hiddify: only 'standard' exists */
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { error: 'illegal core' };
	} else {
		const pkg_manager = detect_pkg_manager();
		if (!pkg_manager) {
			result = { error: 'no supported package manager found (apk or opkg)' };
		} else if (core === 'singbox-lite') {
			/* ч.265: lite = ПРЯМОЙ тарбол MANCrimSon с SHA256-гейтом (первичный
			 * путь; лейаут установки идентичен их установщику: normal →
			 * /usr/bin/sing-box, compressed → UPX-бинарник в
			 * /usr/libexec/sing-box-core + sh-обёртка + /etc/sing-box-version.
			 * cache). Их install.sh остаётся фолбэком на случай слепого API
			 * (без гейта — note говорит об этом честно). Пороги те же, что у
			 * установщика проекта. */
			const arch = detect_arch();
			if (!arch || !match(arch, /^[a-zA-Z0-9_-]+$/)) {
				result = { error: 'could not detect device architecture' };
			} else {
				const tmp_free_kb = free_kb('/tmp');
				if (tmp_free_kb < LITE_TMP_MIN_KB) {
					result = { error: `not enough /tmp space for the lite tarball: ${tmp_free_kb} KB free, need ~20 MB` };
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
					if (chosen === 'normal' && effective_kb < LITE_NORMAL_MIN_KB) {
						result = { error: `Not enough effective flash for the lite normal build: ${effective_kb} KB free (need ~50 MB). Try the compressed (UPX) build — it needs ~96 MB free RAM.` };
					} else if (chosen === 'compressed' && overlay_free_kb < LITE_COMPRESSED_MIN_KB) {
						result = { error: `Not enough overlay for the lite compressed build: ${overlay_free_kb} KB free (need ~16 MB).` };
					} else if (chosen === 'compressed' && ram_free_kb < LITE_COMPRESSED_RAM_KB) {
						result = { error: `Not enough RAM for the lite compressed build: ${ram_free_kb} KB free (need ~96 MB — the UPX binary decompresses into RAM at launch).` };
					} else {
						const rel = gh_api(LITE_REPO_API, 20000);
						const pick = rel ? resolve_original_asset('lite', chosen, rel, pkg_manager, arch)
							: { error: 'failed to contact GitHub API' };
						if (pick.error && rel) {
							/* arch/asset mismatch — HARD error: their installer
							 * would fail identically; refuse honestly up front. */
							result = { error: pick.error };
						} else if (pick.error) {
							/* API blind: fall back to the original project installer
							 * (no SHA256 gate exists on that path — the note says
							 * so honestly). */
							result = {
								pkg_manager, arch, variant: chosen, source: 'installer',
								note: 'GitHub API недоступен — ставим оригинальным установщиком проекта (без SHA256-гейта)',
								installer_url: LITE_INSTALLER_URL,
								tmp_path: `/tmp/sing-box-extended-lite-installer-${chosen}.sh`
							};
						} else {
							result = {
								pkg_manager, arch, variant: chosen,
								source: 'upstream', kind: 'lite_tarball',
								dl_url: pick.pick.url,
								tmp_path: `/tmp/sing-box-extended-lite-${chosen}.tar.gz`,
								sha256: pick.pick.sha256,
								expect_version: pick.ver,
								note: `original tarball (MANCrimSon ${pick.ver}${chosen === 'compressed' ? ', UPX' : ''})`
							};
						}
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

					/* ч.265 (де-форк): НИКАКОГО фида и форка для ядер — только
					 * оригинальные релизы с SHA256-гейтом. hiddify: оригинальный
					 * apk/ipk (первичный; имена hiddify-core-<ver>-r<N>_<arch>) или
					 * апстрим-тарбол (фолбэк, musl-CGO = NaïveProxy на борту),
					 * обмен через staging на оверлее. sing-box-extended: shtorm-7
					 * apk/ipk (sing-box-extended_<ver>_openwrt_<arch>); variant
					 * 'upx' = оригинальный -compressed (UPX) тарбол — только по
					 * явному выбору (на MIPS UPX ненадёжен — note честно скажет). */

				if (core === 'hiddify') {
					if (variant === 'upx') {
						result = { error: 'у оригинального hiddify-core нет компактной UPX-сборки (форк ушёл) — доступна только полная сборка' };
					} else {
						const rel = gh_api(HIDDIFY_UPSTREAM_API, 20000);
						const pick = rel ? resolve_original_asset('hiddify', variant, rel, pkg_manager, arch)
							: { error: 'failed to contact GitHub API' };
						if (pick.error)
							result = { error: pick.error };
						else {
							const gate = core_space_gate(pick.kind, overlay_free_kb, tmp_free_kb, ram_free_kb);
							if (gate)
								result = { error: gate };
							else
								result = {
									pkg_manager, arch, variant: 'standard',
									source: 'upstream', kind: pick.kind,
									dl_url: pick.pick.url,
									tmp_path: (pick.kind === 'pkg') ? `/tmp/hiddify-core${ext}` : '/tmp/hiddify-core.tar.gz',
									sha256: pick.pick.sha256,
									expect_version: pick.ver,
									note: (pick.kind === 'pkg')
										? `original package (hiddify/hiddify-core ${pick.ver})`
										: `original tarball (hiddify/hiddify-core ${pick.ver})`
								};
						}
					}
				} else {
					const rel = gh_api(SBX7_API, 20000);
					const pick = rel ? resolve_original_asset('singbox', variant, rel, pkg_manager, arch)
						: { error: 'failed to contact GitHub API' };
					if (pick.error)
						result = { error: pick.error };
					else {
						const gate = core_space_gate(pick.kind, overlay_free_kb, tmp_free_kb, ram_free_kb);
						if (gate) {
							result = { error: gate };
						} else if (pick.kind === 'sbx_upx') {
							const mips_note = (arch === 'mipsel_24kc' || arch === 'mips_24kc')
								? ' (UPX на MIPS ненадёжен — установлен по явному выбору)' : '';
							result = {
								pkg_manager, arch, variant: 'upx',
								source: 'upstream', kind: 'sbx_upx',
								dl_url: pick.pick.url,
								tmp_path: '/tmp/sing-box-extended-compressed.tar.gz',
								sha256: pick.pick.sha256,
								expect_version: pick.ver,
								note: `original UPX tarball (shtorm-7 ${pick.ver})${mips_note}`
							};
						} else {
							result = {
								pkg_manager, arch, variant: 'standard',
								source: 'upstream', kind: 'pkg',
								dl_url: pick.pick.url,
								tmp_path: `/tmp/sing-box-extended${ext}`,
								sha256: pick.pick.sha256,
								expect_version: pick.ver,
								note: `original package (shtorm-7 ${pick.ver})`
							};
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

} else if (action === 'verify_sha') {
	/* ч.265: honesty gate for EVERY original-source download — the runner and
	 * install.sh call this between download_pkg and install_pkg with the
	 * per-asset digest taken from the GitHub API (decision 3). A mismatch
	 * removes the file and refuses loudly. */
	const tmp_path = ARGV[1];
	const want = trim(ARGV[2] || '');
	if (!tmp_path || !match(want, /^[0-9a-f]{64}$/)) {
		result = { result: false, error: 'verify_sha: missing or invalid arguments' };
	} else if (!access(tmp_path)) {
		result = { result: false, error: `downloaded file ${tmp_path} is missing` };
	} else {
		let sum = '';
		const fd = popen(`sha256sum ${shellquote(tmp_path)} 2>/dev/null`);
		if (fd) { sum = trim(fd.read('all')); fd.close(); }
		const m = match(sum, /^([0-9a-f]{64})/);
		if (!m) {
			result = { result: false, error: 'sha256sum failed for the downloaded file' };
		} else if (m[1] != want) {
			system(`rm -f ${shellquote(tmp_path)}`);
			result = { result: false, error: `SHA256 mismatch: expected ${want}, got ${m[1]} — файл удалён` };
		} else {
			result = { result: true, sha256: m[1] };
		}
	}

} else if (action === 'remote_tags') {
	/* ч.265: rollback helper — the last ~10 release tags of the ORIGINAL repo
	 * for a core family. Nothing is cached on the router (decision 8): the UI
	 * fetches this list live every time. */
	const core = ARGV[1];
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { error: 'illegal core' };
	} else {
		const data = gh_api(`https://api.github.com/repos/${core_repo(core)}/releases?per_page=12`, 15000);
		if (!data || type(data) != 'array') {
			result = { error: 'no response from GitHub API' };
		} else {
			const tags = [];
			for (let r in data) {
				if (!r || r.draft || !r.tag_name) continue;
				push(tags, { tag: r.tag_name, version: replace('' + r.tag_name, /^v/, ''),
					name: r.name || '', date: (r.published_at || '') });
				if (length(tags) >= 10) break;
			}
			result = { tags };
		}
	}

} else if (action === 'prepare_rollback') {
	/* ч.265: ЯВНЫЙ откат (решения 8/9) — пользователь выбирает тег, prepare
	 * резолвит ИМЕННО этот релиз (не latest): apk/ipk оригинала при наличии,
	 * иначе тарбол; SHA256-гейт тот же; гейт «не новее» ОБХОДИТСЯ — но только
	 * потому, что install_pkg получит mode='rollback'. Кэшей на роутере нет:
	 * скачивание по запросу, tmp-файл удаляется сразу после установки. */
	const core = ARGV[1];
	const variant = ARGV[2] || '';
	const tag = trim(ARGV[3] || '');
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { error: 'illegal core' };
	} else if (!length(tag) || !match(tag, /^[a-zA-Z0-9._-]+$/)) {
		result = { error: 'illegal tag' };
	} else {
		const pkg_manager = detect_pkg_manager();
		if (!pkg_manager) {
			result = { error: 'no supported package manager found (apk or opkg)' };
		} else if (core === 'hiddify' && variant === 'upx') {
			result = { error: 'у оригинального hiddify-core нет компактной UPX-сборки — откат ставит полную сборку' };
		} else {
			const arch = detect_arch();
			if (!arch || !match(arch, /^[a-zA-Z0-9_-]+$/)) {
				result = { error: 'could not detect device architecture' };
			} else {
				const rel = gh_api(`https://api.github.com/repos/${core_repo(core)}/releases/tags/${tag}`, 20000);
				if (!rel || !rel.tag_name) {
					result = { error: `тег ${tag} не найден в оригинальном репозитории (GitHub недоступен или тега нет)` };
				} else {
					const pick = resolve_original_asset(core, (core === 'hiddify') ? 'standard' : variant, rel, pkg_manager, arch);
					if (pick.error) {
						result = { error: pick.error };
					} else {
						const tmp_free_kb = free_kb('/tmp');
						if (tmp_free_kb < 30720) {
							result = { error: `not enough /tmp space: ${tmp_free_kb} KB free, need 30 MB` };
						} else if (core !== 'singbox-lite') {
							let overlay_free_kb = free_kb('/overlay');
							if (!overlay_free_kb) overlay_free_kb = free_kb('/');
							const ram_free_kb = free_ram_kb();
							const gate = core_space_gate(pick.kind, overlay_free_kb, tmp_free_kb, ram_free_kb);
							if (gate) {
								result = { error: gate };
							} else {
								const ext = (pkg_manager === 'apk') ? '.apk' : '.ipk';
								result = {
									pkg_manager, arch,
									variant: (pick.kind === 'sbx_upx') ? 'upx' : (pick.kind === 'lite_tarball' ? variant : 'standard'),
									source: 'upstream', kind: pick.kind, mode: 'rollback',
									dl_url: pick.pick.url,
									tmp_path: (pick.kind === 'pkg')
										? ((core === 'hiddify') ? `/tmp/hiddify-core${ext}` : `/tmp/sing-box-extended${ext}`)
										: (core === 'hiddify') ? '/tmp/hiddify-core.tar.gz'
											: (pick.kind === 'sbx_upx') ? '/tmp/sing-box-extended-compressed.tar.gz'
											: `/tmp/sing-box-extended-lite-${variant || 'normal'}.tar.gz`,
									sha256: pick.pick.sha256,
									expect_version: pick.ver,
									note: `rollback to ${rel.tag_name} (${core_repo(core)})`
								};
							}
						} else {
							/* lite rollback: the same effective-flash accounting as prepare_install */
							let overlay_free_kb = free_kb('/overlay');
							if (!overlay_free_kb) overlay_free_kb = free_kb('/');
							const cur_kb = int(bin_bytes('/usr/bin/sing-box') / 1024);
							const effective_kb = overlay_free_kb + cur_kb;
							const ram_free_kb = free_ram_kb();
							if ((variant !== 'compressed') && effective_kb < LITE_NORMAL_MIN_KB) {
								result = { error: `Not enough effective flash for the lite normal rollback: ${effective_kb} KB free (need ~50 MB).` };
							} else if ((variant === 'compressed') && (overlay_free_kb < LITE_COMPRESSED_MIN_KB || ram_free_kb < LITE_COMPRESSED_RAM_KB)) {
								result = { error: `Not enough overlay/RAM for the lite compressed rollback (${overlay_free_kb} KB / ${ram_free_kb} KB free).` };
							} else {
								result = {
									pkg_manager, arch, variant: variant || 'normal',
									source: 'upstream', kind: 'lite_tarball', mode: 'rollback',
									dl_url: pick.pick.url,
									tmp_path: `/tmp/sing-box-extended-lite-${variant || 'normal'}.tar.gz`,
									sha256: pick.pick.sha256,
									expect_version: pick.ver,
									note: `rollback to ${rel.tag_name} (MANCrimSon${variant === 'compressed' ? ', UPX' : ''})`
								};
							}
						}
					}
				}
			}
		}
	}

} else if (action === 'install_pkg') {
	const core        = ARGV[1];
	const tmp_path    = ARGV[2];
	const pkg_manager = ARGV[3];
	const cand_ver    = trim(ARGV[4] || '');   /* candidate version from prepare — silent-downgrade gate input */
	const mode        = trim(ARGV[5] || '');   /* '' | 'rollback' — ONLY the explicit rollback bypasses the gate */
	if (!(core in ['hiddify', 'singbox', 'singbox-lite']) || !tmp_path || !pkg_manager) {
		result = { result: false, error: 'invalid arguments' };
	} else if (mode !== 'rollback' && length(cand_ver) && core_downgrade_error(core, cand_ver)) {
		/* Silent downgrade refused (ch.261 gate survives the de-fork). An
		 * explicit user rollback (chosen older tag) lands here with
		 * mode='rollback' — decision 8/9. */
		result = { result: false, error: core_downgrade_error(core, cand_ver) };
	} else if (core === 'singbox-lite' && match(tmp_path, /\.tar\.gz$/)) {
		/* ч.265: direct ORIGINAL tarball (MANCrimSon), SHA256-checked by the
		 * verify stage before this. Layout replication of their installer:
		 * normal → plain binary at /usr/bin/sing-box; compressed → UPX binary
		 * at /usr/libexec/sing-box-core + tiny sh wrapper at /usr/bin/sing-box
		 * (answers `version` from /etc/sing-box-version.cache). Staging ON the
		 * overlay (tens of MB do not fit small tmpfs), mv = rename(2). */
		const vm = match(tmp_path, /-(normal|compressed)\.tar\.gz$/);
		const compressed = (vm && vm[1] === 'compressed');
		const stage = '/usr/libexec/.lite-up';
		const cmd =
			`{ rm -rf ${shellquote(stage)}; mkdir -p ${shellquote(stage)}; }` +
			` && tar -xzf ${shellquote(tmp_path)} -C ${shellquote(stage)}` +
			` && BIN=$(find ${shellquote(stage)} -type f -name sing-box | head -n1)` +
			` && [ -n "$BIN" ] && [ -s "$BIN" ]` +
			` && chmod 755 "$BIN"` +
			` && "$BIN" version >/dev/null 2>&1` +
			(compressed
				? ` && mv -f "$BIN" /usr/libexec/sing-box-core`
				: ` && mv -f "$BIN" /usr/bin/sing-box && rm -f /usr/libexec/sing-box-core`) +
			` && rm -rf ${shellquote(stage)} ${shellquote(tmp_path)}`;
		const exit_code = system(cmd, 300000);
		if (exit_code !== 0) {
			system(`rm -rf ${shellquote(stage)}`);
			result = { result: false, error: 'lite tarball extraction/validation failed' };
		} else {
			/* Version cache + wrapper — the installer's contract, byte-for-byte
			 * (the wrapper answers `version` from the cache, everything else
			 * execs the real binary). Writing the wrapper goes through a temp
			 * file + rename: overwriting a RUNNING exe with open/truncate
			 * fails with ETXTBSY, rename(2) does not. */
			const real_bin = compressed ? '/usr/libexec/sing-box-core' : '/usr/bin/sing-box';
			let banner = '';
			const bfd = popen(`${shellquote(real_bin)} version 2>/dev/null`);
			if (bfd) { banner = trim(bfd.read('all')); bfd.close(); }
			if (length(banner)) {
				system('mkdir -p /etc');
				const tmp_cache = '/etc/sing-box-version.cache.tmp';
				writefile(tmp_cache, banner + '\n');
				rename(tmp_cache, '/etc/sing-box-version.cache');
				system('chmod 644 /etc/sing-box-version.cache 2>/dev/null; true');
			}
			if (compressed) {
				const tmp_wrap = '/usr/bin/.sing-box.wrap';
				writefile(tmp_wrap,
					'#!/bin/sh\n' +
					'REAL_BIN="/usr/libexec/sing-box-core"\n' +
					'VERSION_CACHE="/etc/sing-box-version.cache"\n\n' +
					'if [ "$#" -eq 1 ] && [ "$1" = "version" ]; then\n' +
					'    if [ -s "$VERSION_CACHE" ]; then\n' +
					'        cat "$VERSION_CACHE"\n' +
					'        exit 0\n' +
					'    fi\n' +
					'fi\n\n' +
					'exec "$REAL_BIN" "$@"\n');
				rename(tmp_wrap, '/usr/bin/sing-box');
				system('chmod 755 /usr/bin/sing-box 2>/dev/null; true');
			}
			result = { result: true, note: `original tarball installed (${compressed ? 'UPX' : 'normal'})` };
		}
	} else if (core === 'singbox-lite') {
		/* FALLBACK (ч.265): the lite project's own install.sh — used only when
		 * the GitHub API was blind at prepare time (see prepare_install). It
		 * downloads the right tar.gz for the arch, validates the binary, swaps
		 * it and restarts the services it stopped (with an automatic rollback
		 * to the previous binary if the new core does not come up). No SHA256
		 * gate exists on this path — the prepare note says so honestly. */
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
	} else if (core === 'singbox' && match(tmp_path, /\.tar\.gz$/)) {
		/* ч.265: original -compressed (UPX) tarball of shtorm-7 — the explicit
		 * «extended-UPX» variant. Same staging pattern as the hiddify tarball;
		 * a UPX binary self-unpacks at exec (crash-prone on soft-float MIPS —
		 * that is why AUTO-pick never chose it there; the explicit choice
		 * lands here with eyes open). */
		const stage = '/usr/libexec/.sbx-up';
		const sib_up = FEED_SIBLING['sing-box-extended'];
		if (sib_up)
			system(`${(pkg_manager === 'apk') ? 'apk del' : 'opkg remove'} ${shellquote(sib_up)} >/dev/null 2>&1; true`);
		const cmd =
			`{ rm -rf ${shellquote(stage)}; mkdir -p ${shellquote(stage)}; }` +
			` && tar -xzf ${shellquote(tmp_path)} -C ${shellquote(stage)}` +
			` && BIN=$(find ${shellquote(stage)} -type f -name sing-box | head -n1)` +
			` && [ -n "$BIN" ] && [ -s "$BIN" ]` +
			` && "$BIN" version >/dev/null 2>&1` +
			` && mv -f "$BIN" /usr/bin/sing-box` +
			` && rm -rf ${shellquote(stage)} ${shellquote(tmp_path)}` +
			` && rm -f /usr/libexec/sing-box-core /etc/sing-box-version.cache`;
		const exit_code = system(cmd, 300000);
		result = exit_code === 0
			? { result: true, note: 'original UPX tarball installed' }
			: { result: false, error: 'UPX tarball extraction/validation failed' };
	} else if (core === 'hiddify' && match(tmp_path, /\.tar\.gz$/)) {
		/* ч.129 (ан-146): апстрим-тарбол hiddify/hiddify-core. Структура:
		 * hiddify-core-linux-<target>[-musl]/hiddify-core (+ LICENSE.md).
		 * Распаковка прямо в staging НА ОВЕРЛЕЕ (не в /tmp — бинарник ~101 МиБ,
		 * tmpfs его не удержит на малых роутерах), валидный запуск, атомарный
		 * mv на /usr/bin/hiddify-core, уборка staging+тарбола. mv внутри одного
		 * оверлея = rename(2) без копирования. */
		const stage = '/usr/libexec/.hiddify-up';
		/* Sibling hygiene (session 173 — mirror of the feed path): the tarball
		 * swap replaces the shared /usr/bin/hiddify-core slot; a compact
		 * sibling record would keep describing the SAME binary we just
		 * replaced (zoo class). Best-effort, matching FEED_SIBLING. */
		const sib_up = FEED_SIBLING['hiddify-core'];
		if (sib_up)
			system(`${(pkg_manager === 'apk') ? 'apk del' : 'opkg remove'} ${shellquote(sib_up)} >/dev/null 2>&1; true`);
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
			? { result: true, note: 'original tarball installed' }
			: { result: false, error: 'upstream tarball extraction/validation failed' };
	} else {
		/* Sibling hygiene (session 173 — mirror of the feed path): the original
		 * apk / GitHub asset occupies the same binary slot as its sibling;
		 * installing it must not leave the sibling record behind (the next
		 * feed update would silently flip the family back). Best-effort;
		 * the lite core is owned by its installer/tarball paths — skipped above. */
		const sib_fam = (core === 'hiddify')
			? FEED_SIBLING['hiddify-core']
			: FEED_SIBLING['sing-box-extended'];
		if (sib_fam)
			system(`${(pkg_manager === 'apk') ? 'apk del' : 'opkg remove'} ${shellquote(sib_fam)} >/dev/null 2>&1; true`);
		let exit_code;
		if (core === 'hiddify' && pkg_manager === 'apk') {
			/* ч.265 (де-форк): оригинальные пакеты hiddify НЕ подписаны нашим
			 * ключом — --allow-untrusted всегда (ключ 1andrevich/homeproxy-
			 * hiddify удалён вместе с форк-веткой). Целостность держит
			 * SHA256-гейт verify-стадии (digest из GitHub API). */
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
	} else if (index(FEED_PKGS, feed_pkg) < 0) {
		/* s200: whitelist-gate по FEED_PKGS — синхронно с RPC-дверью
		 * luci.ravnex (чужое имя = честный отказ, не поиск по манифесту). */
		result = { result: false, error: feed_pkg + ' не входит в набор пакетов фида этой сборки' };
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
