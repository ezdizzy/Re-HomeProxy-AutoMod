#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';

import { access, popen, readfile, writefile, rename, stat, mkdir, unlink, opendir } from 'fs';

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

/* Optional GitHub mirror (set by a provisioning tool or the user as
 * uci homeproxy.config.github_mirror). Used ONLY as a FALLBACK: every fetch tries
 * GitHub first and only swaps to the mirror if GitHub fails — so a healthy GitHub is
 * never bypassed, but a blocked/failed one still gets the file via the mirror. */
function gh_mirror_base() {
	let base = null;
	const fd = popen('uci -q get homeproxy.config.github_mirror 2>/dev/null');
	if (fd) { base = trim(fd.read('all')); fd.close(); }
	return (base && length(base)) ? replace(base, /\/+$/, '') : null;
}

function gh_mirror_of(url, base) {
	const m = match(url, /^https:\/\/github\.com(\/[^\/]+\/[^\/]+\/releases\/.+)$/);
	return m ? `${base}${m[1]}` : null;
}

/* GitHub-first, mirror-FALLBACK download. Returns wget exit code (0 = success). */
function gh_fetch(url, dest, timeout_ms) {
	let rc = system(`wget -qO ${shellquote(dest)} --timeout=15 ${shellquote(url)} 2>/dev/null`, timeout_ms);
	if (rc !== 0) {
		const base = gh_mirror_base();
		const mu = base ? gh_mirror_of(url, base) : null;
		if (mu)
			rc = system(`wget -qO ${shellquote(dest)} --timeout=15 ${shellquote(mu)} 2>/dev/null`, timeout_ms);
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
const VERSION_CACHE = '/var/run/homeproxy/core_versions.json';

function read_version_cache() {
	if (!access(VERSION_CACHE))
		return {};
	let cache;
	try { cache = json(readfile(VERSION_CACHE) || ''); } catch (e) { cache = null; }
	return (cache && type(cache) == 'object') ? cache : {};
}

function write_version_cache(cache) {
	mkdir('/var/run/homeproxy');
	const tmp = VERSION_CACHE + '.tmp';
	writefile(tmp, sprintf('%.J', cache) + '\n');
	rename(tmp, VERSION_CACHE);
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
	if (bin_bytes(bin) > 0 && bin_bytes(bin) < LITE_WRAPPER_MAX_BYTES && access('/usr/libexec/sing-box-core'))
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
				 * wrapper of the compressed (UPX) lite build. */
				variant: singbox_installed
					? (bin_bytes('/usr/bin/sing-box') < LITE_WRAPPER_MAX_BYTES ? 'compressed' : 'normal')
					: null
			}
		};

} else if (action === 'check_remote') {
	const core = ARGV[1];
	if (!(core in ['hiddify', 'singbox', 'singbox-lite'])) {
		result = { error: 'illegal core' };
	} else {
		const api_url = core === 'hiddify'
			? 'https://api.github.com/repos/1andrevich/hiddify-core/releases/latest'
			: core === 'singbox'
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
					if (chosen === 'normal' && effective_kb < LITE_NORMAL_MIN_KB) {
						result = { error: `Not enough effective flash for the lite --normal build: ${effective_kb} KB free (need ~50 MB). Try the compressed (UPX) build — it needs ~96 MB free RAM.` };
					} else if (chosen === 'compressed' && overlay_free_kb < LITE_COMPRESSED_MIN_KB) {
						result = { error: `Not enough overlay for the lite compressed build: ${overlay_free_kb} KB free (need ~16 MB).` };
					} else if (chosen === 'compressed' && ram_free_kb < LITE_COMPRESSED_RAM_KB) {
						result = { error: `Not enough RAM for the lite compressed build: ${ram_free_kb} KB free (need ~96 MB — the UPX binary decompresses into RAM at launch).` };
					} else {
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

					if (core === 'hiddify') {
						/* Auto-pick the build from free overlay (+ free RAM for the compact one).
						 * ARGV[2] ('standard'|'upx') is an advanced override; size-checked either way.
						 * This is the guardrail for the "full binary truncates on a small overlay →
						 * SIGBUS" trap: never offer a build the device can't actually hold/run. */
						let chosen = variant;
						let note = null;
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
									dl_url: `https://github.com/1andrevich/hiddify-core/releases/${hp_path}/hiddify-core_${arch}${ext}`,
									tmp_path: `/tmp/hiddify-core${ext}`
								};
							}
						}
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
			const exit_code = system(
				`{ sh ${shellquote(tmp_path)} ${lflag}; } >${shellquote(logf)} 2>&1` +
				`; RC=$?; rm -f ${shellquote(tmp_path)}; exit $RC`,
				300000
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
					system('/etc/init.d/homeproxy start >/dev/null 2>&1');
					result = { result: true,
						note: 'installed; the installer health-check only watches sing-box and returned an error (the active core is not sing-box) — the service was restarted' };
				} else {
					result = { result: false, error: `lite installer failed — see ${logf}` };
				}
			} else {
				const alive = system('pidof sing-box sing-box-core >/dev/null 2>&1') === 0;
				result = alive
					? { result: true }
					: { result: true, warning: `installer finished but sing-box is not running — see ${logf}` };
			}
		}
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
			system('/etc/init.d/homeproxy stop >/dev/null 2>&1');
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
				system('/etc/init.d/homeproxy start >/dev/null 2>&1');
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
