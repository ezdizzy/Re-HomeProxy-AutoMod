#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Routing Wizard: TG WS Proxy runner (D8, Ф7).
 *
 * One-shot background runner spawned by the rpcd methods wizard_tgwsp_check /
 * wizard_tgwsp_install. The mode comes from a file (ARGV indexing differs
 * between ucode builds on this platform), the result goes to a small JSON
 * status file + a log file, both under /var/run/homeproxy.
 *
 *   mode 'check'   → /usr/bin/tg-ws-proxy-rs --check  (self-diagnostics:
 *                    reads the component's UCI READ-ONLY and passes the same
 *                    upstream flags its service runs with, probes every CF
 *                    domain and MTProto upstream with latency, prints OK/FAIL
 *                    lines, exit 0 = all pass; results parsed into details[])
 *   mode 'install' → download the OFFICIAL one-liner installer of
 *                    valnesfjord/tg-ws-proxy-rs and run it. The installer
 *                    itself verifies the release archive and LuCI package
 *                    against the SHA-256 digests served by the GitHub
 *                    release API — that is the trust boundary, this script
 *                    only checks that what it fetched is a shell script.
 *   mode 'go_install' → the d0mhate Go bridge (the transparent SOCKS5 exit).
 *   mode 'go_init'    → regenerate /etc/init.d/tgws-go from the CURRENT
 *                    template (no download) + restart the running bridge.
 *
 * This component is THIRD-PARTY (MIT, valnesfjord/tg-ws-proxy-rs): the Wizard
 * never edits its UCI, never packs the binary and never opens a WAN port;
 * the component's own LuCI page stays the single configuration point.
 *
 * Status files (atomic tmp+mv — RPC readers run concurrently):
 *   /var/run/homeproxy/tgwsp_check.json    {running,stage,rc,ok,fail,details[],
 *                                           sync{state,count},ts}
 *   /var/run/homeproxy/tgwsp_install.json  {running,stage,rc,ts}
 * Logs:
 *   /var/run/homeproxy/tgwsp_check.log / tgwsp_install.log
 *
 * ucode constraints honored: no hoisting, push(arr, x) as a function,
 * for-in over an array yields ELEMENTS, match() with regex literals only,
 * json() parses but never serializes (sprintf('%.J') writes JSON),
 * system(cmd, timeout_ms) bounds every external call (no `timeout` binary
 * on this router), no fs.remove (system rm).
 */

'use strict';

import { access, readfile, writefile, open, popen } from 'fs';
import { cursor } from 'uci';

const RUN_DIR = '/var/run/homeproxy';
const MODE = RUN_DIR + '/tgwsp_mode.txt';

const CHECK_STATUS = RUN_DIR + '/tgwsp_check.json';
const CHECK_LOG = RUN_DIR + '/tgwsp_check.log';
const INSTALL_STATUS = RUN_DIR + '/tgwsp_install.json';
const INSTALL_LOG = RUN_DIR + '/tgwsp_install.log';

const RS_BIN = '/usr/bin/tg-ws-proxy-rs';
/* Verified against the upstream README (docs/OpenWrtPackage.md): the
 * one-liner installer URL. The digests of the actual artifacts come from
 * the GitHub release API inside the installer itself. */
const INSTALL_URL = 'https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh';
const INSTALL_TMP = '/tmp/tgwsp_install.sh';

/* ═══ F8-F2 «tg-ws (transparent)»: the SOCKS5 bridge (go variant) ════════
 * d0mhate/-tg-ws-proxy-Manager-go is the only variant with a SOCKS5 mode —
 * the front-end sing-box needs for the transparent tgws-out path. Installed
 * as OUR procd instance (loopback listener), binary verified against the
 * GitHub release API digest — the same trust boundary the rs installer uses. */
const GO_BIN = '/usr/bin/tg-ws-proxy-go';
const GO_INIT = '/etc/init.d/tgws-go';
const GO_API_URL = 'https://api.github.com/repos/d0mhate/-tg-ws-proxy-Manager-go/releases/latest';
const GO_API_TMP = '/tmp/tgwsp_go_api.json';
const GO_BIN_TMP = '/tmp/tgwsp_go.bin';
const GO_STATUS = RUN_DIR + '/tgwsp_go_install.json';
const GO_LOG = RUN_DIR + '/tgwsp_go_install.log';
const GO_PORT = 1080;
/* Issue #6: CF-domain sync rs → bridge. The Go bridge has no domain
 * discovery of its own — its built-in CF pool rots over time and the
 * provider cuts the tcp_fallback path it degenerates to (ws=0, tcp_fb only).
 * The rs check fetches + probes the LIVE default CF domain list; with the
 * sync flag on (config.tgws_sync_rs) the OK Cloudflare-proxy domains are
 * written to OUR UCI (config.tgws_rs_domains) and the bridge restarts with
 * --cf-domain when the list actually changed. Our UCI only — the foreign
 * rs UCI (tg-ws-proxy-rs.*) is never written. */
const GO_SYNC_FLAG = 'tgws_sync_rs';
const GO_SYNC_LIST = 'tgws_rs_domains';
const GO_SYNC_CAP = 40;
/* Egress-exempt group (lesson 83): the bridge dials its own upstream —
 * Cloudflare WS edges AND the tcp_fallback path straight to Telegram IPs.
 * Without an exclusion those dials are re-intercepted by the OUTPUT
 * redirect, matched by the telegram rule (91.105.192.x:80 ∈ telegram.srs)
 * and pushed back into tgws-out → the bridge dials the same target again →
 * infinite dial loop (~900 conn/s, 9.6M connections in 2.7 h, conntrack
 * dport=80/dport=1080 ~11k each, CPU 100%, load >10, ping up on every VPN
 * node). Same defect class as ciadpi: the firewall already returns packets
 * of the byedpi group from homeproxy_output_redir / homeproxy_mangle_output
 * (firewall_post.ut skgid guard, infra.byedpi_gid). The bridge carries that
 * supplementary group so its egress leaves directly, as designed. */
const GO_EGRESS_GROUP = 'byedpi';
let _egress_gid = '8181';
{
	const gfd = popen('uci -q get homeproxy.infra.byedpi_gid 2>/dev/null');
	if (gfd) {
		const gv = lc(trim(gfd.read('all') || ''));
		gfd.close();
		if (match(gv, /^[0-9]+$/))
			_egress_gid = gv;
	}
}
const GO_GID = _egress_gid;
/* Release asset per OpenWrt arch (verified against the v1.4.1 asset list). */
const GO_ASSET_MAP = {
	'aarch64': 'tg-ws-proxy-openwrt-aarch64',
	'mipsel_24kc': 'tg-ws-proxy-openwrt-mipsel_24kc',
	'mips_24kc': 'tg-ws-proxy-openwrt-mips_24kc',
	'armv7': 'tg-ws-proxy-openwrt-armv7',
	'armv8l': 'tg-ws-proxy-openwrt-armv7',
	'x86_64': 'tg-ws-proxy-openwrt-x86_64'
};
/* Init template. Log policy (ч.124): the binary's 5 s stats block goes to
 * STDOUT with no quiet flag upstream, so procd stdout→syslog is OFF by
 * default (UCI homeproxy.config.tgws_syslog='1' opts back in) — the feed
 * evicted the boot log from the 64 KB logd ring within ~30 min (lesson 131).
 * Deploy to existing installs: runner mode 'go_init' (regenerate + restart). */
const GO_INIT_BODY = `#!/bin/sh /etc/rc.common
# tg-ws bridge (SOCKS5, d0mhate/-tg-ws-proxy-Manager-go) — procd instance
# managed by Re:HomeProxy AutoMod. Loopback-only listener: only the sing-box
# core on this router talks to it, nothing is exposed to LAN or WAN.
# CF route first: the direct WS path to Telegram IPs is cut by the provider
# (R3-FIX-2, 2026-10-20), the Cloudflare edge path is not.
# Egress-exempt group (lesson 83): without it the bridge's own dials loop
# back through the OUTPUT redirect → tgws-out → the bridge → dial again.
START=99
STOP=10
USE_PROCD=1

start_service() {
	# Idempotent: the group is shared with ciadpi (byedpi, infra.byedpi_gid);
	# firewall_post.ut exempts this gid from the redirect by skgid.
	grep -q '^byedpi:' /etc/group || echo 'byedpi:x:${GO_GID}:' >> /etc/group
	procd_open_instance tgwsbridge
	# Fresh CF domains synced from the rs check (config.tgws_sync_rs, issue
	# #6): the Go bridge has no domain discovery of its own — its built-in
	# pool rots and the traffic degenerates to the tcp_fallback path the
	# provider cuts. The list is written by the Wizard's check; when absent
	# the bridge runs exactly as before (built-in pool).
	RS_DOMAINS=$(uci -q get homeproxy.config.tgws_rs_domains)
	if [ -n "$RS_DOMAINS" ]; then
		procd_set_param command ${GO_BIN} --mode socks5 --host 127.0.0.1 --port ${GO_PORT} --cf-proxy --cf-proxy-first --cf-balance --cf-domain "$RS_DOMAINS"
	else
		procd_set_param command ${GO_BIN} --mode socks5 --host 127.0.0.1 --port ${GO_PORT} --cf-proxy --cf-proxy-first --cf-balance
	fi
	# Supplementary group only (uid stays root): the socket gid carries the
	# skgid guard — the bridge's egress skips the redirect and dials directly.
	procd_set_param group "${GO_EGRESS_GROUP}"
	procd_set_param respawn 3600 5 5
	# The binary has NO quiet flag (--verbose only adds more): it prints a
	# stats block to STDOUT every 5 s, and procd feeds stdout to syslog at
	# daemon.info — ~100k lines/day that evict the boot log from the 64 KB
	# logd ring buffer within ~30 min (lesson 131, ч.120). Default: stdout
	# stays away from syslog (the service itself is unaffected; Go panic
	# traces still arrive via stderr). Opt back in with:
	#   uci set homeproxy.config.tgws_syslog='1'; uci commit homeproxy
	if [ "$(uci -q get homeproxy.config.tgws_syslog)" = "1" ]; then
		procd_set_param stdout 1
	else
		procd_set_param stdout 0
	fi
	procd_set_param stderr 1
	procd_close_instance
}
`;

/* ── Helpers (NO hoisting in ucode: declared before first call) ── */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function atomic_write(path, content) {
	const tmp = path + '.tmp';
	writefile(tmp, content);
	system(`mv -f ${sq(tmp)} ${sq(path)}`);
}

function write_status(path, obj) {
	obj.ts = time();
	atomic_write(path, sprintf('%.J', obj) + '\n');
}

function log(path, msg) {
	const fd = open(path, 'a');
	if (fd) {
		fd.write(sprintf('[%d] %s\n', time(), msg));
		fd.close();
	}
}

/* ═══ mode: check ═══════════════════════════════════════════════════════ */

/* join() is BROKEN on this ucode build (lesson 47 family: returns null for
 * arrays) — build the comma list by hand. */
function join_list(arr) {
	let s = '';
	for (let i = 0; i < length(arr); i++)
		s += (i ? ',' : '') + arr[i];
	return s;
}

/* A repeatable rs option: a UCI list (DynamicList) or the legacy scalar
 * form the component's own init script keeps accepting. */
function rs_vals(c, opt) {
	const vals = [];
	const v = c.get('tg-ws-proxy-rs', 'main', opt);
	if (type(v) === 'array') {
		for (let x in v) {
			const s = trim('' + x);
			if (length(s))
				push(vals, s);
		}
	} else if (v != null && length(trim('' + v))) {
		for (let part in split(trim('' + v), /[[:space:],]+/))
			if (length(trim(part)))
				push(vals, trim(part));
	}
	return vals;
}

function rs_flag(c, opt) {
	return (trim('' + (c.get('tg-ws-proxy-rs', 'main', opt) || '')) === '1');
}

/* (Re)write OUR init script from the CURRENT template — used by the bridge
 * install and by the CF-domain sync (an install done with an older template
 * must still get the --cf-domain branch, issue #6). Idempotent, no restart.
 * The script is ours (written by the go-install runner); the binary must
 * exist for the script to make sense. */
function ensure_go_init() {
	if (!access(GO_BIN))
		return false;
	writefile(GO_INIT, GO_INIT_BODY);
	system('chmod 755 ' + sq(GO_INIT));
	system(sq(GO_INIT) + ' enable >/dev/null 2>&1; true');
	return true;
}

function go_bridge_running() {
	let running = false;
	const pf = popen('pidof tg-ws-proxy-go 2>/dev/null');
	if (pf) {
		running = length(trim(pf.read('all') || '')) > 0;
		pf.close();
	}
	return running;
}

/* Issue #6: harvest the OK Cloudflare-proxy domains from the check details
 * (the probe label of a cf_domain is "kws2.<domain>") into OUR UCI and
 * restart the bridge only when the list actually changed AND the bridge is
 * actually running — a deliberately stopped bridge must stay stopped (its
 * next start picks the fresh list up from UCI). */
function sync_go_domains(c, details) {
	if (trim('' + (c.get('homeproxy', 'config', GO_SYNC_FLAG) || '')) !== '1')
		return { state: 'off', count: 0 };
	const doms = [];
	for (let d in details) {
		if (d.status !== 'ok')
			continue;
		if (substr(d.name, 0, 5) !== 'kws2.')
			continue;
		const dom = substr(d.name, 5);
		if (!length(dom) || index(doms, dom) >= 0)
			continue;
		push(doms, dom);
		if (length(doms) >= GO_SYNC_CAP)
			break;
	}
	if (!length(doms))
		return { state: 'none', count: 0 };
	const list = join_list(doms);
	const prev = trim('' + (c.get('homeproxy', 'config', GO_SYNC_LIST) || ''));
	if (list === prev)
		return { state: 'unchanged', count: length(doms) };
	c.set('homeproxy', 'config', GO_SYNC_LIST, list);
	c.commit('homeproxy');
	/* Restart OUR bridge only when it is actually running — a deliberately
	 * stopped bridge must stay stopped; its next start picks the list up.
	 * The init script is regenerated first: installs made before the sync
	 * feature carry an older template without the --cf-domain branch. */
	const running = go_bridge_running();
	if (running && access(GO_INIT)) {
		ensure_go_init();
		system(sq(GO_INIT) + ' restart >/dev/null 2>&1; true');
	}
	return { state: running ? 'written' : 'written_stopped', count: length(doms) };
}

function run_check() {
	write_status(CHECK_STATUS, { running: true, stage: 'check' });
	system('rm -f ' + sq(CHECK_LOG) + ' 2>/dev/null');
	log(CHECK_LOG, 'tg-ws-proxy-rs --check started by the Wizard');
	/* Read-only peek at the component's UCI (issue #5): --check must probe
	 * the SAME upstreams the service actually uses — a bare --check has
	 * nothing configured and honestly answers "Nothing to check". The
	 * component's own init script translates exactly these UCI options into
	 * the TG_* environment the binary reads; the Wizard never writes them. */
	const c = cursor();
	const dd = rs_flag(c, 'default_domains');
	const cf = rs_vals(c, 'cf_domain');
	const cw = rs_vals(c, 'cf_worker_domain');
	const mp = rs_vals(c, 'mtproto_proxy');
	const ob = trim('' + (c.get('tg-ws-proxy-rs', 'main', 'outbound_proxy') || ''));
	const nop = rs_flag(c, 'no_outbound_proxy');
	const stls = rs_flag(c, 'danger_accept_invalid_certs');
	let cmd = sq(RS_BIN) + ' --check';
	if (dd)
		cmd += ' --default-domains';
	if (length(cf))
		cmd += ' --cf-domain ' + sq(join_list(cf));
	if (length(cw))
		cmd += ' --cf-worker-domain ' + sq(join_list(cw));
	for (let p in mp)
		cmd += ' --mtproto-proxy ' + sq(p);
	if (length(ob))
		cmd += ' --outbound-proxy ' + sq(ob);
	else if (nop)
		cmd += ' --no-outbound-proxy';
	if (stls)
		cmd += ' --danger-accept-invalid-certs';
	/* Flag SUMMARY only — --mtproto-proxy carries the secret, never log it. */
	log(CHECK_LOG, sprintf('flags: default_domains=%s cf=%d worker=%d mtproto=%d outbound=%s skip_tls=%s',
		dd ? 'yes' : 'no', length(cf), length(cw), length(mp),
		length(ob) ? 'set' : (nop ? 'off' : 'none'), stls ? 'yes' : 'no'));
	/* system() with a wall-clock cap (no `timeout` binary on this router):
	 * --default-domains first fetches the live list from GitHub, then every
	 * domain/upstream is probed with its own latency probe — 7 minutes is a
	 * generous ceiling; a hang surfaces as a non-zero rc. */
	const rc = system(cmd + ' >> ' + sq(CHECK_LOG) + ' 2>&1', 420000);
	/* Parse the probe verdicts: the binary prints one line per probe as
	 * "  <label padded>  ... [OK ]  230ms" / "... [FAIL]  <message>" (the
	 * OK marker carries a trailing space inside the brackets). POSIX-ERE —
	 * no lazy quantifiers, greedy is safe: "... [" occurs once per line. */
	let ok = 0, fail = 0;
	const details = [];
	const out = readfile(CHECK_LOG) || '';
	const re = /^[[:space:]]*(.+)[[:space:]]+\.\.\.[[:space:]]+\[(OK|FAIL)[[:space:]]*\][[:space:]]*(.*)$/;
	for (let l in split(out, '\n')) {
		const m = match(l, re);
		if (!m)
			continue;
		const good = (m[2] === 'OK');
		push(details, { name: trim(m[1]), status: good ? 'ok' : 'fail',
			message: trim(m[3]) });
		if (good)
			ok++;
		else
			fail++;
	}
	const sync = sync_go_domains(c, details);
	write_status(CHECK_STATUS, {
		running: false,
		stage: (rc === 0) ? 'done' : 'error',
		rc: rc,
		ok: ok,
		fail: fail,
		details: details,
		sync: sync
	});
	log(CHECK_LOG, sprintf('check finished: rc=%d ok=%d fail=%d sync=%s(%d)',
		rc, ok, fail, sync.state, sync.count));
}

/* ═══ mode: install ═════════════════════════════════════════════════════ */

function run_install() {
	write_status(INSTALL_STATUS, { running: true, stage: 'fetch' });
	system('rm -f ' + sq(INSTALL_LOG) + ' ' + sq(INSTALL_TMP) + ' 2>/dev/null');
	log(INSTALL_LOG, 'downloading the official installer');

	/* Router-originated fetch rides the app's own output rules — GitHub
	 * raw is reachable (verified live); curl (busybox wget may lack TLS). */
	const rc1 = system('curl -fsSL --connect-timeout 10 --max-time 120 ' +
		sq(INSTALL_URL) + ' -o ' + sq(INSTALL_TMP) + ' >> ' + sq(INSTALL_LOG) + ' 2>&1', 130000);
	if (rc1 !== 0 || !access(INSTALL_TMP)) {
		write_status(INSTALL_STATUS, { running: false, stage: 'error', rc: rc1,
			error: 'installer download failed' });
		log(INSTALL_LOG, sprintf('download failed: rc=%d', rc1));
		return;
	}
	/* Sanity only — artifact digests are verified by the installer itself
	 * against the GitHub release API. */
	const head = substr(readfile(INSTALL_TMP) || '', 0, 2);
	if (head !== '#!') {
		write_status(INSTALL_STATUS, { running: false, stage: 'error',
			error: 'downloaded file is not a shell script' });
		log(INSTALL_LOG, 'downloaded file is not a shell script — aborted');
		return;
	}

	write_status(INSTALL_STATUS, { running: true, stage: 'install' });
	log(INSTALL_LOG, 'running the installer (digests verified from the GitHub release API)');
	const rc2 = system('sh ' + sq(INSTALL_TMP) + ' >> ' + sq(INSTALL_LOG) + ' 2>&1', 600000);
	system('rm -f ' + sq(INSTALL_TMP) + ' 2>/dev/null');
	write_status(INSTALL_STATUS, {
		running: false,
		stage: (rc2 === 0) ? 'done' : 'error',
		rc: rc2
	});
	log(INSTALL_LOG, sprintf('installer finished: rc=%d', rc2));
}

/* ═══ mode: go_install ══════════════════════════════════════════════════ */

function go_arch_asset() {
	const rel = trim(readfile('/etc/openwrt_release') || '');
	let arch = '';
	for (let l in split(rel, '\n')) {
		const m = match(l, /DISTRIB_ARCH='([^']*)'/);
		if (m) { arch = m[1]; break; }
	}
	if (!length(arch)) {
		const fd = popen('uname -m 2>/dev/null');
		if (fd) { arch = trim(fd.read('all') || ''); fd.close(); }
	}
	for (let k in GO_ASSET_MAP) {
		if (arch === k || index(arch, k) === 0)
			return GO_ASSET_MAP[k];
	}
	return null;
}

function port_listening(port) {
	const fd = popen('netstat -tln 2>/dev/null');
	if (!fd) return false;
	const out = fd.read('all') || '';
	fd.close();
	return index(out, ':' + port + ' ') >= 0;
}

function run_go_install() {
	write_status(GO_STATUS, { running: true, stage: 'api' });
	system('rm -f ' + sq(GO_LOG) + ' ' + sq(GO_API_TMP) + ' ' + sq(GO_BIN_TMP) + ' 2>/dev/null');
	log(GO_LOG, 'tg-ws bridge install started');

	/* A foreign tgm manager owns its own instance and init script — refuse
	 * instead of silently fighting it for the binary and the process. */
	if (access('/usr/bin/tgm')) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'foreign tgm manager detected' });
		log(GO_LOG, 'aborted: /usr/bin/tgm exists (foreign manager)');
		return;
	}
	/* Flash space check before the download (binary ~6.5 MB). */
	const dfd = popen('df / 2>/dev/null');
	if (dfd) {
		const df_out = trim(dfd.read('all') || '');
		dfd.close();
		log(GO_LOG, 'df /: ' + (split(df_out, '\n')[1] || df_out));
	}

	/* 1. Release API → asset URL + digest (the trust boundary). */
	const rc1 = system('curl -fsSL --connect-timeout 10 --max-time 30 ' +
		'-H "Accept: application/vnd.github+json" ' + sq(GO_API_URL) +
		' -o ' + sq(GO_API_TMP) + ' >> ' + sq(GO_LOG) + ' 2>&1', 40000);
	if (rc1 !== 0 || !access(GO_API_TMP)) {
		write_status(GO_STATUS, { running: false, stage: 'error', rc: rc1,
			error: 'release API fetch failed' });
		log(GO_LOG, sprintf('API fetch failed: rc=%d', rc1));
		return;
	}
	let api = null;
	try { api = json(readfile(GO_API_TMP) || ''); } catch (e) { api = null; }
	const asset_name = go_arch_asset();
	if (!asset_name) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'no release asset for this arch' });
		log(GO_LOG, 'arch not in the asset map — aborted');
		return;
	}
	let dl_url = null, digest = '', tag = '';
	if (api && type(api) === 'object') {
		tag = '' + (api.tag_name || '');
		for (let a in (api.assets || [])) {
			if (('' + (a.name || '')) === asset_name) {
				dl_url = '' + (a.browser_download_url || '');
				digest = '' + (a.digest || '');
				break;
			}
		}
	}
	if (!length(dl_url)) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'asset not found in the release' });
		log(GO_LOG, 'asset ' + asset_name + ' missing in ' + tag);
		return;
	}
	const want = match(digest, /sha256:([0-9a-fA-F]{64})/);
	if (!want) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'no sha256 digest in the release API' });
		log(GO_LOG, 'digest missing — aborted');
		return;
	}
	log(GO_LOG, sprintf('release %s, asset %s, digest %s', tag, asset_name, want[1]));

	/* 2. Download the binary. */
	write_status(GO_STATUS, { running: true, stage: 'download' });
	const rc2 = system('curl -fsSL --connect-timeout 10 --max-time 300 ' +
		sq(dl_url) + ' -o ' + sq(GO_BIN_TMP) + ' >> ' + sq(GO_LOG) + ' 2>&1', 310000);
	if (rc2 !== 0 || !access(GO_BIN_TMP)) {
		write_status(GO_STATUS, { running: false, stage: 'error', rc: rc2,
			error: 'binary download failed' });
		log(GO_LOG, sprintf('download failed: rc=%d', rc2));
		return;
	}

	/* 3. Verify SHA-256 (busybox sha256sum; compare lc-lowered digests). */
	write_status(GO_STATUS, { running: true, stage: 'verify' });
	const sfd = popen('sha256sum ' + sq(GO_BIN_TMP) + ' 2>/dev/null');
	let got = '';
	if (sfd) {
		const sm = match(sfd.read('all') || '', /^([0-9a-fA-F]{64})[[:space:]]/);
		if (sm) got = lc(sm[1]);
		sfd.close();
	}
	if (got !== lc(want[1])) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'sha256 mismatch' });
		log(GO_LOG, sprintf('sha256 mismatch: got %s want %s', got, want[1]));
		system('rm -f ' + sq(GO_BIN_TMP) + ' 2>/dev/null');
		return;
	}
	log(GO_LOG, 'sha256 verified');

	/* 4. Stop any running instance, install the binary (atomic mv + chmod). */
	write_status(GO_STATUS, { running: true, stage: 'install' });
	if (access(GO_INIT))
		system(sq(GO_INIT) + ' stop >/dev/null 2>&1; true');
	const kfd = popen("pgrep -f 'tg-ws-proxy-go' 2>/dev/null");
	if (kfd) {
		for (let pl in split(trim(kfd.read('all') || ''), '\n')) {
			const pid = int(trim(pl) || '0');
			if (pid > 0)
				system('kill ' + pid + ' 2>/dev/null; true');
		}
		kfd.close();
	}
	system('sleep 1');
	system('mv -f ' + sq(GO_BIN_TMP) + ' ' + sq(GO_BIN) + ' && chmod 755 ' + sq(GO_BIN));
	if (!access(GO_BIN)) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'binary install failed' });
		log(GO_LOG, 'mv to ' + GO_BIN + ' failed');
		return;
	}

	/* 5. Our procd instance (loopback-only listener) + autostart. */
	writefile(GO_INIT, GO_INIT_BODY);
	system('chmod 755 ' + sq(GO_INIT));
	system(sq(GO_INIT) + ' enable >/dev/null 2>&1; true');
	const rc3 = system(sq(GO_INIT) + ' start >> ' + sq(GO_LOG) + ' 2>&1', 20000);

	/* 6. The bridge must actually listen before the exit is offered. */
	let up = false;
	for (let t = 0; t < 6 && !up; t++) {
		system('sleep 1');
		up = port_listening(GO_PORT);
	}
	if (rc3 !== 0 || !up) {
		write_status(GO_STATUS, { running: false, stage: 'error', rc: rc3,
			error: 'bridge did not start (see the log)' });
		log(GO_LOG, sprintf('start rc=%d, listening=%s', rc3, up ? 'yes' : 'no'));
		return;
	}
	log(GO_LOG, 'bridge listening on 127.0.0.1:' + GO_PORT);

	/* 7. Turn the config flags on and regenerate so the tgws-out outbound
	 * exists in the running config (harmless until a rule references it). */
	write_status(GO_STATUS, { running: true, stage: 'config' });
	system('uci -q set homeproxy.config.tgws_enabled=1; true');
	system('uci -q set homeproxy.config.tgws_port=' + GO_PORT + '; true');
	system('uci -q commit homeproxy; true');
	const rc4 = system('ucode ' + sq('/etc/homeproxy/scripts/generate_client.uc') +
		' >> ' + sq(GO_LOG) + ' 2>&1', 60000);
	system('/etc/init.d/homeproxy reload >/dev/null 2>&1; true');

	write_status(GO_STATUS, { running: false, stage: 'done', rc: 0,
		version: tag, port: GO_PORT });
	log(GO_LOG, sprintf('install finished: rc_cfg=%d (bridge up on %d)', rc4, GO_PORT));
}

/* ═══ mode: go_init ═════════════════════════════════════════════════════ */

/* Maintenance: regenerate /etc/init.d/tgws-go from the CURRENT template
 * (no download) and restart the running bridge — used when the template
 * gains behavior the installed script lacks (issue #6 --cf-domain branch). */
function run_go_init() {
	write_status(GO_STATUS, { running: true, stage: 'init' });
	if (!ensure_go_init()) {
		write_status(GO_STATUS, { running: false, stage: 'error',
			error: 'tg-ws-proxy-go binary not installed' });
		return;
	}
	const running = go_bridge_running();
	if (running)
		system(sq(GO_INIT) + ' restart >/dev/null 2>&1; true');
	write_status(GO_STATUS, { running: false, stage: 'done', rc: 0,
		restarted: running });
}

/* ═══ Main ══════════════════════════════════════════════════════════════ */

const mode = trim(readfile(MODE) || '');
system('rm -f ' + sq(MODE) + ' 2>/dev/null');
if (mode === 'check')
	run_check();
else if (mode === 'install')
	run_install();
else if (mode === 'go_install')
	run_go_install();
else if (mode === 'go_init')
	run_go_init();
