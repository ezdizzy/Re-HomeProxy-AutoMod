#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Strategy auto-pick runner (Ф8-F7, T3).
 *
 * Spawned by the wizard_auto_pick_start RPC: the RPC owns the lock and the
 * validation, this process drives the stages and rewrites the status file
 * atomically at every step (file-mode one-shot, the wizard_compose.uc
 * pattern — the lock lives in the RPC, never in the runner).
 *
 * Input:  /var/run/homeproxy/wizard_autopick_req.json
 *         { resource: "youtube"|"discord"|"telegram"|"general",
 *           mode: "quick"|"full", set_rule: true|false, ts }
 * Output: /var/run/homeproxy/wizard_autopick.json
 *         { running, stage: "started"|"fuzz"|"pick"|"apply"|"verify"|"done"|"error",
 *           resource, mode, chosen: {name, args, score, avg_tls_ms, tag_ms, runners},
 *           verify: {host, code, tsec, rc, ok}, rule: {source, node}, notes, error, ts }
 *
 * Flow:
 *   1. FUZZ — reuse zapret_fuzz_result.json when fresh (< 6 h) and complete;
 *      when a fuzz is already running, WAIT for it (someone else started it —
 *      a second sweep would fight the same temp queue); otherwise start
 *      zapret_fuzz.sh <mode> 2 in the background and poll its status.
 *   2. PICK — from the fuzz ranking: strategies whose host entry for the
 *      resource tag passed the round majority AND was NOT a free pass (a
 *      baseline pass cannot credit a strategy). Rank by that host's minimal
 *      TLS handshake (fastest resource = best), tie-break by the global
 *      score. "general" takes the global ranking head (strategies[0]).
 *   3. RULE — when set_rule, hand the resource rule to the EXISTING
 *      wizard_preset_apply RPC through ubus (its guards — one-rule-per-source,
 *      main_is_direct, mode check — stay the single implementation). Never
 *      edit proxy_ru_rule directly here.
 *   4. APPLY — snapshot BOTH engines to /etc/homeproxy/backups/zapret_prev.json
 *      (exactly the file the Restore button reads back), write
 *      zapret_cmd_opts + zapret_enabled=1 through the uci module (no shell),
 *      restart the service in the background.
 *   5. VERIFY — wait for the core to come back, then probe the resource
 *      through the CONFIGURED path (router-originated HTTPS, the scanner's
 *      live-probe method): HTTP code + seconds. youtube → www.youtube.com,
 *      discord → discord.com, telegram → web.telegram.org,
 *      general → gstatic generate_204.
 *
 * Honesty rules: the strategy only serves the resource when its rule leads
 * to zapret-out — the notes always carry the actual rule state; a failed
 * live check does NOT roll back automatically (the fuzz measured the
 * strategy on the isolated queue — the server snapshot + Restore button
 * stay available; an auto-rollback would also undo the user's intent).
 *
 * ucode constraints honored (05-doc): popen from fs; sleep() in ms; push()/
 * shift() functions; for-in over arrays yields elements; match() only with
 * /regex/ literals; json() is a parser (serialize via sprintf('%.J'));
 * atomic writes (tmp + mv -f); no optional chaining.
 */

import { readfile, access, writefile, popen } from 'fs';
import { cursor } from 'uci';

const RUN_DIR = '/var/run/homeproxy';
const REQ = RUN_DIR + '/wizard_autopick_req.json';
const OUT = RUN_DIR + '/wizard_autopick.json';
const FUZZ_STATUS = RUN_DIR + '/zapret_fuzz.json';
const FUZZ_RESULT = RUN_DIR + '/zapret_fuzz_result.json';
const BAK = '/etc/homeproxy/backups/zapret_prev.json';
const NFQWS = '/opt/zapret2/nfq2/nfqws2';

const RESOURCES = {
	youtube:  { tag: 'yt', host: 'www.youtube.com' },
	discord:  { tag: 'dc', host: 'discord.com' },
	telegram: { tag: 'tg', host: 'web.telegram.org' },
	general:  { tag: null, host: 'www.gstatic.com/generate_204' }
};
const FUZZ_FRESH = 6 * 3600;      /* reuse a ranking younger than 6 h       */
const FUZZ_WAIT_MAX = 2700;       /* cap for waiting a full fuzz (~45 min)  */
const CORE_WAIT_MAX = 90;         /* cap for the service restart            */
const VERIFY_TMO = 9;             /* live-path probe --max-time             */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function wstat(o) {
	o.ts = time();
	writefile(OUT + '.tmp', sprintf("%.J\n", o));
	system(`mv -f ${sq(OUT + '.tmp')} ${sq(OUT)}`);
}

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function note(res, msg) {
	if (res.notes == null)
		res.notes = [];
	push(res.notes, msg);
}

/* Rule state for the source (honest reporting only — never edited here).
 * cursor.foreach is the working enumeration (cursor.get with a TYPE answers
 * null in this ucode-uci build — caught live; cursor has no length()). */
function rule_state(src) {
	const c = cursor();
	let found = null;
	c.foreach('homeproxy', 'proxy_ru_rule', (s) => {
		if (found == null && s.source === src && s.enabled === '1')
			found = { source: src, node: s.node || '' };
	});
	return (found != null) ? found : { source: src, node: null };
}

/* Router-originated HTTPS probe (the scanner's live-probe method): rides
 * the app's own output interception, so the resource is served exactly the
 * way LAN clients are served. Returns {code, tsec, rc, ok}. */
function probe_live(url, host) {
	const bf = RUN_DIR + '/wiz_probe.body';
	const cf = RUN_DIR + '/wiz_probe.code';
	system(`rm -f ${sq(bf)} ${sq(cf)} 2>/dev/null`);
	const cmd = `curl -sL --max-redirs 3 -o ${sq(bf)} -w '%{http_code} %{time_total}' -k ` +
		`--connect-timeout 4 --max-time ${VERIFY_TMO} ${sq(url)} > ${sq(cf)} 2>/dev/null`;
	const rc = system(cmd, VERIFY_TMO * 1000 + 3000);
	const parts = split(trim(readfile(cf) || ''), /[[:space:]]+/);
	const code = (length(parts) && match(parts[0], /^[0-9]{3}$/)) ? parts[0] : '000';
	const tsec = (length(parts) > 1) ? ('' + parts[1]) : null;
	const ok = (rc === 0 && int(code) >= 200 && int(code) < 400);
	return { code: code, tsec: tsec, rc: rc, ok: ok, host: host };
}

/* Wait until the fuzz is no longer running (status file says so); the
 * result file is written just before the status flips to false. */
function wait_fuzz(deadline) {
	while (time() < deadline) {
		const st = read_json(FUZZ_STATUS);
		if (st == null || !st.running) {
			const r = read_json(FUZZ_RESULT);
			if (r && r.strategies && length(r.strategies))
				return r;
			/* status not running yet no result → the sweep just started;
			 * keep waiting until the status file exists at all. */
			if (st == null) {
				sleep(2000);
				continue;
			}
			return null;
		}
		sleep(10000);
	}
	return null;
}

function fuzz_fail(res) {
	const stx = read_json(FUZZ_STATUS);
	res.running = false;
	res.stage = 'error';
	res.error = (stx && stx.error)
		? ('the fuzz failed: ' + stx.error)
		: 'the fuzz did not finish in time';
	wstat(res);
}

/* After WE spawn a fuzz, wait until the status/result is owned by the NEW
 * run (its ts is not older than our spawn moment): the old files must not
 * be mistaken for the fresh ranking (race caught live — the first
 * wait_fuzz iteration ran before the new sweep rewrote the status). */
function wait_fuzz_owner(t_start) {
	while (time() < t_start + 120) {
		const sx = read_json(FUZZ_STATUS);
		if (sx && int(sx.ts || 0) >= t_start - 2)
			return true;
		const rx = read_json(FUZZ_RESULT);
		if (rx && int(rx.ts || 0) >= t_start - 2)
			return true;
		sleep(1000);
	}
	return false;
}

function main() {
	const req = read_json(REQ);
	const meta = RESOURCES[req && req.resource];
	if (meta == null) {
		wstat({ running: false, stage: 'error', error: 'invalid resource' });
		return;
	}
	const resource = req.resource;
	const mode = (req.mode === 'full') ? 'full' : 'quick';
	const res = {
		running: true, stage: 'started', resource: resource, mode: mode,
		rule: rule_state(resource), chosen: null, verify: null, notes: []
	};
	wstat(res);

	if (!access(NFQWS)) {
		res.running = false; res.stage = 'error';
		res.error = 'zapret2 is not installed';
		wstat(res);
		return;
	}

	/* 1. FUZZ — fresh result / wait for a running sweep / start one. */
	res.stage = 'fuzz';
	wstat(res);
	let fz = read_json(FUZZ_RESULT);
	const st = read_json(FUZZ_STATUS);
	const fresh = (fz && fz.strategies && length(fz.strategies) &&
		(fz.ts && (time() - int(fz.ts)) < FUZZ_FRESH));
	const running = (st && st.running);
	if (running) {
		note(res, 'A fuzz run is already in progress — waiting for it to finish…');
		wstat(res);
		fz = wait_fuzz(time() + FUZZ_WAIT_MAX);
		if (fz == null) {
			fuzz_fail(res);
			return;
		}
	} else if (!fresh) {
		note(res, 'Starting a ' + mode + ' fuzz (the previous ranking is missing or older than 6 h)…');
		wstat(res);
		const t0 = time();
		system(`sh /etc/homeproxy/scripts/zapret_fuzz.sh ${mode} 2 >/dev/null 2>&1 &`);
		if (!wait_fuzz_owner(t0)) {
			fuzz_fail(res);
			return;
		}
		fz = wait_fuzz(time() + FUZZ_WAIT_MAX);
		if (fz == null) {
			fuzz_fail(res);
			return;
		}
	} else {
		note(res, 'Reusing the existing fuzz ranking (younger than 6 h).');
	}

	/* 2. PICK — resource-tag ranking (majority pass, non-free-pass host). */
	res.stage = 'pick';
	wstat(res);
	let chosen = null;
	const runners = [];
	if (meta.tag == null) {
		/* general: the global ranking head (score order already encodes
		 * distinguishing successes minus handshake cost). */
		for (let s in fz.strategies) {
			if (s.ok > 0) { chosen = s; break; }
		}
	} else {
		const elig = [];
		for (let s in fz.strategies) {
			let h = null;
			for (let x in s.hosts)
				if (x.tag === meta.tag) { h = x; break; }
			if (h && h.ok && h.dist)
				push(elig, { s: s, ms: int(h.tls_ms) || 0 });
		}
		sort(elig, (a, b) => (a.ms - b.ms) || (b.s.score - a.s.score));
		if (length(elig)) {
			chosen = elig[0].s;
			for (let i = 1; i < length(elig) && i <= 3; i++)
				push(runners, elig[i].s.name + ' (' + elig[i].ms + ' ms)');
		}
	}
	if (chosen == null) {
		res.running = false; res.stage = 'error';
		res.error = (meta.tag == null)
			? 'no strategy passed any distinguishing host'
			: 'no corpus strategy passed the resource probe — try the full fuzz or the strategy generator';
		wstat(res);
		return;
	}
	if (chosen.args && (match(chosen.args, /[`$;&|<>\n]/) || !match(chosen.args, /^--[a-z]/))) {
		res.running = false; res.stage = 'error';
		res.error = 'the winning strategy has an unexpected shape — refused for safety';
		wstat(res);
		return;
	}
	res.chosen = {
		name: chosen.name || '', args: chosen.args || '',
		score: int(chosen.score) || 0, avg_tls_ms: int(chosen.avg_tls_ms) || 0,
		runners: runners
	};
	note(res, 'Picked: ' + (chosen.name || 'custom args') +
		((res.chosen.avg_tls_ms > 0) ? (' · avg TLS ' + res.chosen.avg_tls_ms + ' ms') : ''));

	/* 3. RULE — through the existing preset RPC (single guard set). */
	if (req.set_rule === true && resource !== 'general') {
		const payload = sprintf('{"source":%.J,"node":"zapret-out","urltest_nodes":[]}', resource);
		const fd = popen(`ubus call luci.homeproxy wizard_preset_apply ${sq(payload)} 2>/dev/null`);
		let out = '';
		if (fd) { out = trim(fd.read('all') || ''); fd.close(); }
		let pr = null;
		try { pr = json(out || ''); } catch (e) { pr = null; }
		if (pr && pr.result) {
			res.rule = { source: resource, node: 'zapret-out' };
			note(res, 'Rule set: ' + resource + ' → Zapret.');
		} else {
			note(res, 'The rule was NOT changed: ' + ((pr && pr.error) || 'preset apply failed') +
				' — the strategy still applies (it may not serve the resource without its rule).');
		}
	}

	/* 4. APPLY — server snapshot first (same file Restore reads), then
	 * write through the uci module (no shell metachar risk) and restart. */
	res.stage = 'apply';
	wstat(res);
	const c = cursor();
	const snap = {
		ts: time(),
		zapret: {
			cmd_opts: '' + (c.get('homeproxy', 'config', 'zapret_cmd_opts') || ''),
			enabled: (c.get('homeproxy', 'config', 'zapret_enabled') === '1')
		},
		byedpi: {
			cmd_opts: '' + (c.get('homeproxy', 'config', 'byedpi_cmd_opts') || ''),
			enabled: (c.get('homeproxy', 'config', 'byedpi_enabled') === '1')
		}
	};
	system('mkdir -p /etc/homeproxy/backups');
	writefile(BAK + '.tmp', sprintf("%.J\n", snap));
	system(`mv -f ${sq(BAK + '.tmp')} ${sq(BAK)}`);
	c.set('homeproxy', 'config', 'zapret_cmd_opts', res.chosen.args);
	c.set('homeproxy', 'config', 'zapret_enabled', '1');
	c.commit('homeproxy');
	/* Light apply when the zapret instance already runs: the launcher
	 * (dpi_engine.sh) re-reads UCI on the procd respawn, so the strategy
	 * swap is a kill — the core keeps running and tunneled sessions (the
	 * user report: a Minecraft session) are NOT kicked by an auto-pick.
	 * The verify stage below polls the CORE pid; with the light path the
	 * core never disappears, so `seen` fills in immediately. */
	const zq = '' + (c.get('homeproxy', 'config', 'zapret_qnum') || '200');
	const z_alive = system(`ps w | grep '[n]fqws2' | grep -q "qnum=${zq}"`) === 0;
	if (z_alive) {
		system('/etc/init.d/homeproxy engine_restart >/dev/null 2>&1 &');
		note(res, 'Strategy applied with a light engine restart (the core stays up).');
	} else {
		system('/etc/init.d/homeproxy restart >/dev/null 2>&1 &');
		note(res, 'Strategy applied — the service restarts.');
	}

	/* 5. VERIFY — wait for the core, then the configured-path probe. */
	res.stage = 'verify';
	wstat(res);
	let seen = 0;
	const t0 = time();
	if (!z_alive) {
		while ((time() - t0) < CORE_WAIT_MAX) {
			sleep(5000);
			const fd = popen('pidof hiddify-core 2>/dev/null');
			let pid = '';
			if (fd) { pid = trim(fd.read('all') || ''); fd.close(); }
			if (length(pid)) {
				seen++;
				if (seen >= 2) break;
			} else {
				seen = 0;
			}
		}
		if (seen < 2)
			note(res, 'The core did not come back within 90 s — check it on the Overview page.');
		sleep(3000);
	} else {
		/* Light path: the core never went away — give the engine respawn (~1 s)
		 * and the firewall re-render a moment, then verify. */
		sleep(5000);
	}
	res.verify = (resource === 'general')
		? probe_live('http://www.gstatic.com/generate_204', 'gstatic generate_204')
		: probe_live('https://' + meta.host, meta.host);
	if (res.verify.ok)
		note(res, 'Live check: ' + res.verify.host + ' → ' + res.verify.code +
			((res.verify.tsec != null) ? (' in ' + res.verify.tsec + ' s') : ''));
	else
		note(res, 'Live check FAILED (' + res.verify.code + ') — the rule/mode may not route the resource through Zapret, or this strategy does not hold under real traffic. Restore stays available.');

	res.running = false;
	res.stage = 'done';
	wstat(res);
	system(`rm -f ${sq(REQ)}`);
}

main();
