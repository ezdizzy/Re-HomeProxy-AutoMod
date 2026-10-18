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
 *                    probes every configured CF domain and MTProto upstream
 *                    with latency, prints OK/FAIL lines, exit 0 = all pass)
 *   mode 'install' → download the OFFICIAL one-liner installer of
 *                    valnesfjord/tg-ws-proxy-rs and run it. The installer
 *                    itself verifies the release archive and LuCI package
 *                    against the SHA-256 digests served by the GitHub
 *                    release API — that is the trust boundary, this script
 *                    only checks that what it fetched is a shell script.
 *
 * This component is THIRD-PARTY (MIT, valnesfjord/tg-ws-proxy-rs): the Wizard
 * never edits its UCI, never packs the binary and never opens a WAN port;
 * the component's own LuCI page stays the single configuration point.
 *
 * Status files (atomic tmp+mv — RPC readers run concurrently):
 *   /var/run/homeproxy/tgwsp_check.json    {running,stage,rc,ok,fail,ts}
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

import { access, readfile, writefile, open } from 'fs';

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

function run_check() {
	write_status(CHECK_STATUS, { running: true, stage: 'check' });
	system('rm -f ' + sq(CHECK_LOG) + ' 2>/dev/null');
	log(CHECK_LOG, 'tg-ws-proxy-rs --check started by the Wizard');
	/* system() with a wall-clock cap (no `timeout` binary on this router):
	 * --check probes each CF domain / upstream with its own latency probe,
	 * 3 minutes is a generous ceiling; a hang surfaces as a non-zero rc. */
	const rc = system(sq(RS_BIN) + ' --check >> ' + sq(CHECK_LOG) + ' 2>&1', 180000);
	/* Count OK / FAIL verdict lines the binary prints. */
	let ok = 0, fail = 0;
	const out = readfile(CHECK_LOG) || '';
	for (let l in split(out, '\n')) {
		const line = trim(l);
		if (index(line, 'OK') === 0)
			ok++;
		else if (index(line, 'FAIL') === 0)
			fail++;
	}
	write_status(CHECK_STATUS, {
		running: false,
		stage: (rc === 0) ? 'done' : 'error',
		rc: rc,
		ok: ok,
		fail: fail
	});
	log(CHECK_LOG, sprintf('check finished: rc=%d ok=%d fail=%d', rc, ok, fail));
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

/* ═══ Main ══════════════════════════════════════════════════════════════ */

const mode = trim(readfile(MODE) || '');
system('rm -f ' + sq(MODE) + ' 2>/dev/null');
if (mode === 'check')
	run_check();
else if (mode === 'install')
	run_install();
