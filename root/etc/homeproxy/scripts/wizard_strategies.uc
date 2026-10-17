#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Routing Wizard: strategy corpus tools (Ф3).
 *
 * One-shot background worker spawned by the rpcd methods
 * wizard_strategy_update (import) / wizard_fuzz_generate (generate). The
 * mode comes from a control FILE (never ARGV — ARGV indexing differs
 * between ucode builds on this platform, lesson 8):
 *
 *   wizard_strategy_update  → mode file contains "import"
 *     1. download the StressOzz/Zapret-Manager catalogs (Strategies.md +
 *        Strategies_For_Youtube.md, nfqws-1 syntax);
 *     2. parse fenced strategy blocks;
 *     3. CONVERT nfqws1 args → nfqws2 --lua-desync args (hostlists are
 *        dropped by design — the routing rules already select the traffic;
 *        unmappable options/methods skip the whole strategy, never guess);
 *     4. smoke-test every converted strategy: spawn nfqws2 on the TEMP
 *        queue 209 for ~1 s and keep only candidates that stay alive
 *        (a dead-on-args process would just pollute the corpus);
 *     5. write the PREVIEW (new / changed / exists / dropped vs the
 *        current corpus). Nothing is applied until wizard_strategy_apply.
 *
 *   wizard_fuzz_generate    → mode file contains "generate"
 *     1. read the last fuzz result (or the recommended corpus) and take
 *        up to 3 seed strategies;
 *     2. derive deterministic mutations of each seed's TLS profile
 *        (positions / repeats / fake / method swap / badseq / tls_mod /
 *        seqovl — the blockcheck2 idea in miniature), ≤30 unique;
 *     3. smoke-test every mutation the same way;
 *     4. REPLACE the previous 'generated' corpus group with the survivors
 *        and start a FULL fuzz (zapret_fuzz.sh) over the whole corpus.
 *
 * Status  → /var/run/homeproxy/wizard_strategies.json          {running,stage,…}
 * Preview → /var/run/homeproxy/wizard_strategies_preview.json  (import only)
 * Both files are written atomically (temp + mv — automation.atomic_write).
 *
 * ucode constraints honored: no `typeof` (type() only), push()/splice()/
 * sort() as functions, for-in over an array yields ELEMENTS (never index
 * an array with a for-in variable), match() with regex literals only and
 * POSIX-safe classes (no \s/\d), index() for substring checks, json()
 * parses but never serializes (sprintf('%.J')), join(sep, arr) argument
 * order, no function hoisting (every helper declared before first use),
 * no filter() with inner arrows (lesson ч.63), no fs.remove (system rm).
 */

'use strict';

import { access, readfile, writefile, popen, lstat } from 'fs';

const RUN_DIR = '/var/run/homeproxy';
const STATUS = RUN_DIR + '/wizard_strategies.json';
const PREVIEW = RUN_DIR + '/wizard_strategies_preview.json';
const MODEF = RUN_DIR + '/wizard_strat_mode';
const CAND = '/etc/homeproxy/zapret_candidates.json';
const BACKUP = '/etc/homeproxy/backups/zapret_candidates.prev.json';
const TMP = '/tmp/wizard_strategies';

const NFQWS = '/opt/zapret2/nfq2/nfqws2';
const FAKE_DIR = '/opt/zapret2/files/fake';
const LUA_ARGS = '--lua-init=@/opt/zapret2/lua/zapret-lib.lua --lua-init=@/opt/zapret2/lua/zapret-antidpi.lua --lua-init=@/opt/zapret2/lua/zapret-auto.lua';
const SMOKE_QNUM = '209';   /* the same temp queue zapret_test.sh uses */

const SRC_MAIN = 'https://raw.githubusercontent.com/StressOzz/Zapret-Manager/main/Strategies.md';
const SRC_YT = 'https://raw.githubusercontent.com/StressOzz/Zapret-Manager/main/Strategies_For_Youtube.md';

/* ── Small helpers (NO hoisting: declared before first use) ────────────── */

function sq(s) {
	return `'${replace('' + s, "'", "'\\''")}'`;
}

function wstat(o) {
	o.ts = time();
	writefile(STATUS + '.tmp', sprintf("%.J\n", o));
	system(`mv -f ${sq(STATUS + '.tmp')} ${sq(STATUS)}`);
}

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

/* GitHub raw download with the optional local mirror as a fallback. */
function fetch_url(url, dest) {
	let rc = system(`wget -qO ${sq(dest)} --timeout=25 ${sq(url)} 2>/dev/null`);
	if (rc !== 0) {
		const fd = popen('uci -q get homeproxy.config.github_mirror 2>/dev/null');
		let base = null;
		if (fd) { base = trim(fd.read('all')); fd.close(); }
		if (base && length(base)) {
			const m = match(url, /^https:\/\/raw\.githubusercontent\.com\/([^\/]+\/[^\/]+)\/(.*)$/);
			if (m) {
				/* Mirror layouts vary; try the two shapes we know, ignore failures. */
				rc = system(`wget -qO ${sq(dest)} --timeout=25 ${sq(replace(base, /\/+$/, '') + '/https://raw.githubusercontent.com/' + m[1] + '/' + m[2])} 2>/dev/null`);
				if (rc !== 0)
					rc = system(`wget -qO ${sq(dest)} --timeout=25 ${sq(replace(base, /\/+$/, '') + '/gh/' + m[1] + '/' + m[2])} 2>/dev/null`);
			}
		}
	}
	return rc;
}

/* ═══════════════════════ nfqws1 → nfqws2 converter ════════════════════ */

/* Every emitted token must fit this: no shell metacharacter can ever reach
 * system()/eval from a catalog string. POSIX-safe class: no \s, no escapes
 * inside the brackets, hyphen last. '=' is needed by --filter-tcp=443 and
 * friends. */
const TOKEN_OK = /^[A-Za-z0-9_.:@,+=\/-]+$/;

function base_name(p) {
	const parts = split('' + p, '/');
	return parts[length(parts) - 1];
}

/* Map a fake-payload file from the catalog (nfqws1 paths) onto the zapret2
 * fake dir; a missing file falls back to the built-in named blobs for TCP
 * profiles and fails the strategy for UDP ones (a wrong UDP fake is worse
 * than no candidate). Returns a blob spec or null. */
function fake_blob(path, kind) {
	let f = trim('' + path);
	if (!length(f) || f === 'null') return null;
	let target = f;
	if (index(f, '/opt/zapret/') === 0)
		target = '/opt/zapret2/' + substr(f, 12);
	if (access(target))
		return '@' + target;
	const b = base_name(f);
	if (access(FAKE_DIR + '/' + b))
		return '@' + FAKE_DIR + '/' + b;
	if (kind === 'tls') return 'fake_default_tls';
	if (kind === 'http') return 'fake_default_http';
	return null;
}

/* Register a catalog file as a named --blob (nfqws2 references blobs by
 * name); built-in names pass through unchanged. Returns the name or null. */
let blob_seq = 0;
function register_blob(path, kind, blobs, notes) {
	const b = fake_blob(path, kind);
	if (b == null) {
		push(notes, 'fake file missing: ' + base_name(path));
		return null;
	}
	if (substr(b, 0, 1) === '@') {
		blob_seq++;
		const name = 'cat' + blob_seq;
		push(blobs, '--blob=' + name + ':' + b);
		return name;
	}
	return b;
}

/* Surgery on one --lua-desync=METHOD:p1:p2 token. */
function desync_params(tok) {
	const rest = substr(tok, length('--lua-desync='));
	const c = index(rest, ':');
	if (c < 0) return { method: rest, params: [] };
	return { method: substr(rest, 0, c), params: split(substr(rest, c + 1), ':') };
}

function rebuild_desync(meth, params) {
	let t = '--lua-desync=' + meth;
	if (length(params)) t += ':' + join(':', params);
	return t;
}

function set_param(params, key, value) {
	const out = [];
	let found = false;
	for (let p in params) {
		if (index(p, key + '=') === 0) {
			push(out, key + '=' + value);
			found = true;
		} else
			push(out, p);
	}
	if (!found)
		push(out, key + '=' + value);
	return out;
}

function get_param(params, key) {
	for (let p in params)
		if (index(p, key + '=') === 0)
			return substr(p, length(key) + 1);
	return null;
}

/* Convert one parsed block (array of option lines) to nfqws2 args.
 * Returns { ok:true, args, notes:[…] } or { ok:false, error }. */
function convert_strategy(lines) {
	const blobs = [];
	const notes = [];
	const out = [];
	/* per-profile state (reset on --new) */
	let st = null;
	const reset = () => {
		st = {
			filter_tcp: null, filter_udp: null, filter_l7: null, payload: null,
			methods: [],            /* ordered mapped method names */
			split_pos: null, seqovl: null, svl_pattern: null,
			fake_src: null, fake_http: null,
			fake_udp: null, fake_quic: null,
			tls_mod: null, repeats: null, fooling: null, badseq: null,
			hf_host: null, wsize: null, wscale: null
		};
	};
	reset();

	const profile_kind = () => {
		if (st.filter_udp != null) return 'udp';
		if (st.filter_tcp === '443' || index(st.filter_l7 || '', 'tls') >= 0) return 'tls';
		return 'http';
	};

	const emit_profile = () => {
		if (!length(st.methods)) {
			reset();
			return;
		}
		const prof = [];
		if (st.filter_tcp != null) push(prof, '--filter-tcp=' + st.filter_tcp);
		if (st.filter_udp != null) push(prof, '--filter-udp=' + st.filter_udp);
		if (st.filter_l7 != null) push(prof, '--filter-l7=' + st.filter_l7);
		if (st.payload != null) push(prof, '--payload=' + st.payload);
		else if (index(st.filter_l7 || '', 'tls') >= 0) push(prof, '--payload=tls_client_hello');
		else if (index(st.filter_l7 || '', 'http') >= 0) push(prof, '--payload=http_req');
		else if (index(st.filter_l7 || '', 'quic') >= 0) push(prof, '--payload=quic_initial');
		const kind = profile_kind();

		for (let meth in st.methods) {
			if (meth === 'fake') {
				/* Blob priority: explicit hex > protocol-specific file. */
				let blob = null;
				if (st.fake_src != null && st.fake_src.hex != null)
					blob = st.fake_src.hex;
				else if (kind === 'udp') {
					if (st.fake_udp != null) blob = register_blob(st.fake_udp, 'udp', blobs, notes);
					if (blob == null && st.fake_quic != null) blob = register_blob(st.fake_quic, 'udp', blobs, notes);
					if (blob == null) {
						push(notes, 'UDP fake without a mappable payload');
						continue;
					}
				} else {
					if (st.fake_src != null && st.fake_src.file != null)
						blob = register_blob(st.fake_src.file, kind, blobs, notes);
					if (blob == null && st.fake_http != null) blob = register_blob(st.fake_http, kind, blobs, notes);
					if (blob == null) blob = (kind === 'tls') ? 'fake_default_tls' : 'fake_default_http';
				}
				const params = [ 'blob=' + blob ];
				if (kind === 'tls' && st.tls_mod != null)
					push(params, 'tls_mod=' + st.tls_mod);
				if (st.fooling != null) {
					for (let f in split(st.fooling, ',')) {
						if (f === 'ts') push(params, 'tcp_ts');
						else if (f === 'badsum') push(params, 'badsum');
						else if (f === 'md5sig') push(params, 'tcp_md5');
						else if (f === 'badseq') {
							const inc = st.badseq;
							if (inc != null && int(inc) !== 0)
								push(params, 'tcp_seq=' + inc);
							else if (inc == null)
								push(params, 'tcp_seq=-2');
						}
						/* other fooling kinds — not applicable in nfqws2 */
					}
				} else if (st.badseq != null && int(st.badseq) !== 0) {
					push(params, 'tcp_seq=' + st.badseq);
				}
				if (st.repeats != null)
					push(params, 'repeats=' + st.repeats);
				push(prof, rebuild_desync('fake', params));
			} else if (meth === 'multisplit' || meth === 'multidisorder') {
				let params = [ 'pos=' + (st.split_pos || ((meth === 'multisplit') ? '2' : '1')) ];
				if (st.seqovl != null)
					push(params, 'seqovl=' + st.seqovl);
				if (st.svl_pattern != null) {
					const name = register_blob(st.svl_pattern, kind, blobs, notes);
					if (name != null)
						push(params, 'seqovl_pattern=' + name);
				}
				push(prof, rebuild_desync(meth, params));
			} else if (meth === 'hostfakesplit') {
				const params = [];
				if (st.hf_host != null)
					push(params, 'host=' + st.hf_host);
				if (st.repeats != null)
					push(params, 'repeats=' + st.repeats);
				if (st.fooling != null && index(st.fooling, 'ts') >= 0)
					push(params, 'tcp_ts=-1000');
				push(prof, rebuild_desync('hostfakesplit', params));
			} else if (meth === 'wssize') {
				const params = [];
				if (st.wsize != null) push(params, 'wsize=' + st.wsize);
				if (st.wscale != null) push(params, 'scale=' + st.wscale);
				push(prof, rebuild_desync('wssize', params));
			} else {
				push(prof, '--lua-desync=' + meth);
			}
		}
		for (let t in prof)
			push(out, t);       /* for-in element IS the token (lesson 20/31) */
		reset();
	};

	for (let raw in lines) {
		const line = trim(raw);
		if (!length(line) || index(line, '#') === 0)
			continue;
		/* Catalog lines use BOTH shapes: `--opt value` (rare) and the
		 * common `--opt=value` (value may itself contain '=', e.g.
		 * fake-tls-mod=rnd,dupsid,sni=host — the FIRST '=' splits). */
		const sp = split(line, /[ \t]+/);
		let opt, val;
		if (length(sp) > 1) {
			opt = sp[0];
			val = sp[1];
		} else {
			const eq = index(line, '=');
			if (eq > 0) {
				opt = substr(line, 0, eq);
				val = substr(line, eq + 1);
			} else {
				opt = line;
				val = null;
			}
		}
		if (opt === '--new') {
			emit_profile();
			continue;
		}
		if (opt === '--filter-tcp' || opt === '--filter-udp' || opt === '--filter-l7' ||
		    opt === '--payload') {
			if (val == null) return { ok: false, error: 'missing value for ' + opt };
			if (!match(val, TOKEN_OK)) return { ok: false, error: 'unsafe value for ' + opt };
			if (opt === '--filter-tcp') st.filter_tcp = val;
			else if (opt === '--filter-udp') st.filter_udp = val;
			else if (opt === '--filter-l7') st.filter_l7 = val;
			else st.payload = val;
			continue;
		}
		if (opt === '--dpi-desync') {
			if (val == null) return { ok: false, error: 'missing desync list' };
			for (let d in split(val, ',')) {
				d = trim(d);
				let mapped = null;
				const m = match(d, /^(split|disorder)([0-9]+)$/);
				if (d === 'fake' || d === 'multisplit' || d === 'multidisorder' ||
				    d === 'hostfakesplit' || d === 'wssize' || d === 'syndata')
					mapped = d;
				else if (m)
					mapped = (m[1] === 'split') ? 'multisplit' : 'multidisorder';
				if (mapped == null) {
					if (d === 'fakedsplit' || d === 'fakeddisorder') {
						push(notes, 'dropped ' + d + ' (not in nfqws2)');
						continue;
					}
					return { ok: false, error: 'unknown desync method: ' + d };
				}
				if (index(st.methods, mapped) < 0)
					push(st.methods, mapped);
			}
			continue;
		}
		if (opt === '--dpi-desync-split-pos') {
			if (val == null) return { ok: false, error: 'missing split-pos' };
			if (!match(val, TOKEN_OK)) return { ok: false, error: 'unsafe split-pos' };
			st.split_pos = val;
			continue;
		}
		if (opt === '--dpi-desync-split-seqovl') {
			if (val == null) return { ok: false, error: 'missing seqovl' };
			st.seqovl = val;
			continue;
		}
		if (opt === '--dpi-desync-split-seqovl-pattern') {
			if (val == null) return { ok: false, error: 'missing seqovl-pattern' };
			st.svl_pattern = val;
			continue;
		}
		if (opt === '--dpi-desync-fake-tls') {
			if (val == null) return { ok: false, error: 'missing fake-tls' };
			/* nfqws1 semantics: the LAST --dpi-desync-fake-tls on the line
			 * wins (hex and file forms overwrite each other). */
			st.fake_src = (substr(val, 0, 2) === '0x') ? { hex: val } : { file: val };
			continue;
		}
		if (opt === '--dpi-desync-fake-http') { if (val != null) st.fake_http = val; continue; }
		if (opt === '--dpi-desync-fake-unknown-udp' || opt === '--dpi-desync-fake-discord' ||
		    opt === '--dpi-desync-fake-stun') { if (val != null) st.fake_udp = val; continue; }
		if (opt === '--dpi-desync-fake-quic') { if (val != null) st.fake_quic = val; continue; }
		if (opt === '--dpi-desync-fake-tls-mod') {
			if (val != null && val !== 'none') st.tls_mod = val;
			continue;
		}
		if (opt === '--dpi-desync-repeats') { st.repeats = val; continue; }
		if (opt === '--dpi-desync-fooling') { st.fooling = val; continue; }
		if (opt === '--dpi-desync-badseq-increment') { st.badseq = val; continue; }
		if (opt === '--dpi-desync-hostfakesplit-mod') {
			/* keep host=…, ignore the rest (altorder etc have no nfqws2 twin) */
			if (val != null)
				for (let kv in split(val, ',')) {
					const km = match(kv, /^host=(.+)$/);
					if (km) st.hf_host = km[1];
				}
			continue;
		}
		if (opt === '--dpi-desync-wsize') { st.wsize = val; continue; }
		if (opt === '--dpi-desync-wscale') { st.wscale = val; continue; }
		if (index(opt, '--hostlist') === 0) {
			push(notes, 'hostlists dropped (rules select the traffic)');
			continue;
		}
		/* Everything else nfqws1-specific: drop the option with a note, but
		 * only options whose ABSENCE cannot change the desync semantics
		 * silently into something dangerous. Truly unknown prefixes fail
		 * the strategy — never guess. */
		if (index(opt, '--ip-id') === 0 || index(opt, '--dup') === 0 ||
		    index(opt, '--dpi-desync-autottl') === 0 || index(opt, '--dpi-desync-cutoff') === 0 ||
		    index(opt, '--dpi-desync-any-protocol') === 0 || index(opt, '--dpi-desync-fakedsplit') === 0 ||
		    index(opt, '--dpi-desync-fakeddisorder') === 0 || index(opt, '--dpi-desync-syndata') === 0 ||
		    index(opt, '--dpi-desync-hostfakesplit') === 0 || index(opt, '--dpi-desync-split') === 0 ||
		    index(opt, '--dpi-desync-fake') === 0 || index(opt, '--dpi-desync-bad') === 0 ||
		    index(opt, '--dpi-desync-md5') === 0 || index(opt, '--dpi-desync-tcp') === 0) {
			push(notes, 'dropped ' + opt);
			continue;
		}
		return { ok: false, error: 'unknown option: ' + opt };
	}
	/* flush the last profile */
	if (length(st.methods) || st.filter_tcp != null || st.filter_udp != null || st.filter_l7 != null)
		emit_profile();

	if (!length(out))
		return { ok: false, error: 'no mappable desync profile' };

	/* token safety: every token must be shell-clean */
	for (let t in out)
		if (!match(t, TOKEN_OK))
			return { ok: false, error: 'unsafe token: ' + t };
	for (let b in blobs)
		if (!match(b, TOKEN_OK))
			return { ok: false, error: 'unsafe blob token' };

	const all = [];
	for (let b in blobs) push(all, b);
	for (let t in out) push(all, t);
	return { ok: true, args: join(' ', all), notes: notes };
}

/* ═══════════════════════ catalog parsing ══════════════════════════════ */

/* Heading → short latin name (the corpus keys are display-only, but keep
 * them stable and ASCII-safe). Declared BEFORE parse_md_blocks — ucode has
 * no function hoisting. */
function catalog_name(heading, seq) {
	if (!heading || !length(heading))
		return 's' + seq;
	const h = lc(heading);
	if (index(h, 'игр') >= 0) return 'Games';
	if (index(h, 'discord') >= 0) return 'Discord';
	const vm = match(heading, /^v[0-9]+$/);
	if (vm) return heading;
	return 's' + seq;
}

/* Extract fenced code blocks; names come from a "#YvNN" marker line inside
 * the block or from the nearest preceding markdown heading. The upstream
 * YouTube file has a missing closing fence between Yv21/Yv22 — a marker
 * line inside an open block starts a new strategy. */
function parse_md_blocks(text, prefix) {
	const blocks = [];
	const parts = split('' + text, '```');
	let heading = null;
	let seq = 0;
	/* even indices = outside the fences, odd = inside */
	for (let i, seg in parts) {
		if ((i % 2) === 0) {
			for (let l in split(seg, '\n')) {
				const h = match(trim(l), /^#+[ \t]*(.+)$/);
				if (h) heading = trim(h[1]);
			}
			continue;
		}
		let cur = null, cur_name = null;
		const flush = () => {
			if (cur && length(cur)) {
				seq++;
				push(blocks, { name: prefix + (cur_name || catalog_name(heading, seq)), lines: cur });
			}
			cur = null;
			cur_name = null;
		};
		for (let l in split(seg, '\n')) {
			const t = trim(l);
			const mk = match(t, /^#([A-Za-z]+[0-9]+)[ \t]*$/);
			if (mk) {
				flush();
				cur_name = mk[1];
				cur = [];
				continue;
			}
			/* Empty lines carry no options; keeping them would make the
			 * leading blank before a "#YvNN" marker flush a phantom block. */
			if (!t)
				continue;
			if (cur == null) cur = [];
			push(cur, t);
		}
		flush();
	}
	return blocks;
}

/* ═══════════════════════ nfqws2 smoke validation ══════════════════════ */

function kill_temp_nfqws() {
	const fd = popen('pgrep nfqws2 2>/dev/null');
	if (!fd) return;
	const out = trim(fd.read('all'));
	fd.close();
	for (let pid in split(out, /[ \n]+/)) {
		if (!length('' + pid)) continue;
		const cf = popen(`tr '\\0' ' ' < /proc/${pid}/cmdline 2>/dev/null`);
		if (!cf) continue;
		const cl = cf.read('all');
		cf.close();
		if (index(cl, 'qnum=' + SMOKE_QNUM) >= 0)
			system(`kill ${pid} 2>/dev/null`);
	}
}

/* Spawn nfqws2 on the temp queue for ~1 s: a strategy whose args the binary
 * rejects dies instantly and is dropped BEFORE it can pollute the corpus.
 * No firewall is touched — the queue simply receives nothing. */
function smoke_ok(args) {
	if (!access(NFQWS))
		return { ok: false, error: 'zapret2 not installed' };
	kill_temp_nfqws();
	system(`${NFQWS} --qnum=${SMOKE_QNUM} --user=daemon --fwmark=0x40000000 ${LUA_ARGS} ${args} >/dev/null 2>&1 &`);
	system('sleep 1');
	let alive = false;
	const fd = popen(`pgrep -f 'qnum=${SMOKE_QNUM}' >/dev/null 2>&1 && echo y`);
	if (fd) {
		alive = (trim(fd.read('all')) === 'y');
		fd.close();
	}
	kill_temp_nfqws();
	return { ok: alive };
}

/* ═══════════════════════ IMPORT mode ══════════════════════════════════ */

function count_state(arr, st) {
	let n = 0;
	for (let c in arr)
		if (c.state === st) n++;
	return n;
}

function do_import() {
	wstat({ running: true, mode: 'import', stage: 'download' });
	system('rm -rf ' + sq(TMP) + ' 2>/dev/null; mkdir -p ' + sq(TMP));
	if (fetch_url(SRC_MAIN, TMP + '/main.md') !== 0) {
		wstat({ running: false, mode: 'import', stage: 'error', error: 'catalog download failed (Strategies.md)' });
		return;
	}
	fetch_url(SRC_YT, TMP + '/yt.md');   /* optional */

	wstat({ running: true, mode: 'import', stage: 'parse' });
	const blocks = [];
	for (let b in parse_md_blocks(readfile(TMP + '/main.md') || '', 'StressOzz '))
		push(blocks, b);
	if (access(TMP + '/yt.md'))
		for (let b in parse_md_blocks(readfile(TMP + '/yt.md') || '', 'StressOzz '))
			push(blocks, b);
	if (!length(blocks)) {
		wstat({ running: false, mode: 'import', stage: 'error', error: 'no strategy blocks found in the catalog' });
		return;
	}

	wstat({ running: true, mode: 'import', stage: 'convert', done: 0, total: length(blocks) });
	const corpus = read_json(CAND) || { candidates: [] };
	const existing_args = {}, existing_names = {};
	for (let x in corpus.candidates)
		if (type(x) === 'object') {
			existing_args[x.args] = true;
			existing_names[x.name] = true;
		}

	const candidates = [];
	const dropped = [];
	const seen_batch_args = {};
	let n = 0;
	for (let b in blocks) {
		n++;
		const r = convert_strategy(b.lines);
		if (!r.ok) {
			push(dropped, { name: b.name, reason: r.error });
		} else {
			let state;
			if (existing_args[r.args]) state = 'exists';
			else if (seen_batch_args[r.args]) state = 'dup';
			else if (existing_names[b.name]) state = 'changed';
			else state = 'new';
			seen_batch_args[r.args] = true;
			if (state === 'dup')
				push(dropped, { name: b.name, reason: 'duplicate of another catalog entry' });
			else
				push(candidates, { name: b.name, args: r.args, group: 'imported', state: state,
					notes: (r.notes && length(r.notes)) ? join('; ', r.notes) : null });
		}
		if ((n % 5) === 0)
			wstat({ running: true, mode: 'import', stage: 'convert', done: n, total: length(blocks) });
	}

	/* Smoke validation: only strategies that may enter the corpus. */
	const keep = [];
	let v = 0;
	for (let c in candidates) {
		v++;
		wstat({ running: true, mode: 'import', stage: 'validate', done: v, total: length(candidates),
			current: c.name });
		const s = smoke_ok(c.args);
		if (s.ok)
			push(keep, c);
		else
			push(dropped, { name: c.name, reason: 'nfqws2 rejected the converted args' });
	}

	writefile(PREVIEW + '.tmp', sprintf("%.J\n", {
		running: false, source: 'stressozz', ts: time(),
		parsed: length(blocks), valid: length(keep),
		added_new: count_state(keep, 'new'),
		added_changed: count_state(keep, 'changed'),
		exists: count_state(keep, 'exists'),
		dropped: dropped,
		candidates: keep
	}));
	system(`mv -f ${sq(PREVIEW + '.tmp')} ${sq(PREVIEW)}`);
	wstat({ running: false, mode: 'import', stage: 'done', parsed: length(blocks),
		valid: length(keep), dropped: length(dropped) });
	system('rm -rf ' + sq(TMP) + ' 2>/dev/null');
}

/* ═══════════════════════ GENERATE mode ════════════════════════════════ */

function split_profiles(args) {
	const profs = [];
	for (let p in split('' + args, /--new/)) {
		const t = trim(p);
		if (length(t)) push(profs, t);
	}
	return profs;
}

function tls_profile_index(profs) {
	for (let i, p in profs)
		if (index(p, '--filter-tcp=443') >= 0)
			return i;
	return -1;
}

function mutate_profile(prof, kind, value) {
	const toks = split(prof, ' ');
	const out = [];
	let applied = false;
	let split_tok = -1, fake_tok = -1, payload_tok = -1;
	for (let i, t in toks) {
		const d = match(t, /^--lua-desync=([a-z]+)/);
		if (d) {
			if (d[1] === 'multisplit' || d[1] === 'multidisorder') split_tok = i;
			if (d[1] === 'fake') fake_tok = i;
		}
		if (index(t, '--payload=') === 0) payload_tok = i;
	}
	if (kind === 'swap') {
		if (split_tok < 0) return null;
		for (let t in toks) {
			if (index(t, '--lua-desync=multisplit') === 0) {
				push(out, replace(t, /^--lua-desync=multisplit/, '--lua-desync=multidisorder'));
				applied = true;
			} else if (index(t, '--lua-desync=multidisorder') === 0) {
				push(out, replace(t, /^--lua-desync=multidisorder/, '--lua-desync=multisplit'));
				applied = true;
			} else push(out, t);
		}
	} else if (kind === 'pos') {
		if (split_tok < 0) return null;
		for (let i, t in toks) {
			if (i === split_tok) {
				const d = desync_params(t);
				push(out, rebuild_desync(d.method, set_param(d.params, 'pos', value)));
				applied = true;
			} else push(out, t);
		}
	} else if (kind === 'repeats' || kind === 'badseq' || kind === 'tls_mod') {
		if (fake_tok < 0) return null;
		const key = (kind === 'repeats') ? 'repeats' : (kind === 'badseq' ? 'tcp_seq' : 'tls_mod');
		for (let i, t in toks) {
			if (i === fake_tok) {
				const d = desync_params(t);
				const params = set_param(d.params, key, value);
				push(out, rebuild_desync(d.method, params));
				applied = true;
			} else push(out, t);
		}
	} else if (kind === 'add_fake') {
		if (fake_tok >= 0) return null;
		for (let i, t in toks) {
			push(out, t);
			if (i === payload_tok || (payload_tok < 0 && i === (length(toks) - 1))) {
				push(out, '--lua-desync=fake:blob=fake_default_tls:tcp_md5');
				applied = true;
			}
		}
		if (!applied) return null;
	} else if (kind === 'seqovl') {
		if (split_tok < 0) return null;
		for (let i, t in toks) {
			if (i === split_tok) {
				const d = desync_params(t);
				let params = set_param(d.params, 'seqovl', value);
				params = set_param(params, 'seqovl_pattern', 'fake_default_tls');
				push(out, rebuild_desync(d.method, params));
				applied = true;
			} else push(out, t);
		}
	}
	if (!applied) return null;
	return join(' ', out);
}

function do_generate() {
	wstat({ running: true, mode: 'generate', stage: 'seeds' });
	const corpus = read_json(CAND) || { candidates: [] };

	/* Seeds: the top of the LAST fuzz ranking (mutations can rescue near-
	 * misses), else the first recommended strategies. */
	const seeds = [];
	const fr = read_json(RUN_DIR + '/zapret_fuzz_result.json');
	if (fr && type(fr.strategies) === 'array')
		for (let s in fr.strategies) {
			if (type(s) === 'object' && length(s.args) && index(seeds, s.args) < 0)
				push(seeds, s.args);
			if (length(seeds) >= 3) break;
		}
	if (length(seeds) < 3)
		for (let x in corpus.candidates)
			if (type(x) === 'object' && x.group === 'recommended' && index(seeds, x.args) < 0) {
				push(seeds, x.args);
				if (length(seeds) >= 3) break;
			}
	if (!length(seeds)) {
		wstat({ running: false, mode: 'generate', stage: 'error', error: 'no seed strategies' });
		return;
	}

	wstat({ running: true, mode: 'generate', stage: 'mutate', seeds: length(seeds) });
	const MUT = [
		[ 'pos', '1,sniext+1' ],
		[ 'pos', 'midsld' ],
		[ 'pos', 'midsld+2' ],
		[ 'repeats', '6' ],
		[ 'repeats', '11' ],
		[ 'add_fake', null ],
		[ 'swap', null ],
		[ 'badseq', '-3000' ],
		[ 'tls_mod', 'rnd,dupsid' ],
		[ 'seqovl', '679' ]
	];
	const corpus_args = {};
	for (let x in corpus.candidates)
		if (type(x) === 'object') corpus_args[x.args] = true;

	const fresh = [];
	const seen = {};
	let si = 0;
	for (let sargs in seeds) {
		si++;
		const profs = split_profiles(sargs);
		const ti = tls_profile_index(profs);
		if (ti < 0) continue;
		for (let mi, mv in MUT) {
			const kind = mv[0], val = mv[1];
			const np = mutate_profile(profs[ti], kind, val);
			if (np == null) continue;
			const new_profs = [...profs];
			new_profs[ti] = np;
			const args = join(' --new ', new_profs);
			if (corpus_args[args] || seen[args]) continue;
			seen[args] = true;
			push(fresh, { name: 'Gen s' + si + '-m' + (mi + 1), args: args, group: 'generated' });
			if (length(fresh) >= 30) break;
		}
		if (length(fresh) >= 30) break;
	}

	wstat({ running: true, mode: 'generate', stage: 'validate', total: length(fresh), done: 0 });
	const keep = [];
	let v = 0;
	for (let c in fresh) {
		v++;
		wstat({ running: true, mode: 'generate', stage: 'validate', total: length(fresh), done: v, current: c.name });
		const s = smoke_ok(c.args);
		if (s.ok) push(keep, c);
	}

	/* Replace the previous 'generated' group entirely (mutations of stale
	 * seeds have no value), keep everything else untouched. */
	const kept_old = [];
	for (let x in corpus.candidates)
		if (!(type(x) === 'object' && x.group === 'generated'))
			push(kept_old, x);
	for (let k in keep)
		push(kept_old, k);   /* element, not keep[k] (lesson 20/31) */

	if (length(keep)) {
		system(`cp ${sq(CAND)} ${sq(BACKUP)} 2>/dev/null; true`);
		writefile(CAND + '.tmp', sprintf("%.J\n", { candidates: kept_old }));
		system(`mv -f ${sq(CAND + '.tmp')} ${sq(CAND)}`);
	}

	wstat({ running: false, mode: 'generate', stage: 'done', seeds: length(seeds),
		generated: length(fresh), valid: length(keep), fuzz_started: (length(keep) > 0) });
	if (length(keep))
		system('sh /etc/homeproxy/scripts/zapret_fuzz.sh full >/dev/null 2>&1 &');
	system('rm -rf ' + sq(TMP) + ' 2>/dev/null');
}

/* ═══════════════════════ entry point ══════════════════════════════════ */

let mode = 'import';
if (access(MODEF)) {
	const m = lc(trim(readfile(MODEF) || ''));
	if (m === 'generate') mode = 'generate';
}
system('rm -f ' + sq(MODEF));

if (mode === 'generate')
	do_generate();
else
	do_import();
