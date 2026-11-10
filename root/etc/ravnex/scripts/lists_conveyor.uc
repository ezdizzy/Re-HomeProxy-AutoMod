#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * lists_conveyor.uc — the LISTS CONVEYOR (док 26, seance 178). Fetches the
 * per-category rule lists described by rulesets_catalog.uc with a sha256
 * gate, writes a MANIFEST (sha256 + origin + license + freshness) and
 * replaces files ATOMICALLY (a poisoned/broken download never blanks the
 * previous copy). Engines are never mixed: this module only feeds the
 * sing-box rule-set plane; nfqws2/byedpi strategies arrive through the
 * strategy-import door below (they are verified by MEASUREMENT in the
 * Strategy Lab before use, not by faith).
 *
 * Usage:
 *   ucode lists_conveyor.uc update <op_id|-|selftest_op> <scope> [force]
 *       scope: 'all' (everything), 'default' (catalog default_on) or an
 *       exact category id. Runs as an opman operation (kind lists_update)
 *       when <op_id> names a real op, otherwise stand-alone.
 *   ucode lists_conveyor.uc strategies-check
 *       detached freshness refresh of the per-provider strategy index
 *       (zemidala/nfqws2-strategies) into RUN_DIR/zemidala_index.json.
 *   ucode lists_conveyor.uc strategy-import <op_id|-|selftest_op> <asn>
 *       fetches data/AS<asn>.json, merges the strategies into the corpus
 *       (group 'recommended', traceable names zmd-AS<asn>-<id>) and writes
 *       the attribution doc. Strategies without a license are consumed
 *       over the network with attribution — never embedded.
 *   ucode lists_conveyor.uc selftest
 *       offline checks (catalog schema, digest format, txt conversion,
 *       manifest round-trip). Prints { ok, checks[] }.
 *
 * Honesty contract (the same one as list_import): a broken mirror must not
 * blank the routing — every failure keeps the previous file and reports the
 * status per category. Release-kind sources verify the per-asset digest
 * from the GitHub API (the same gate as the core installs, ch.265); raw and
 * site sources have no upstream digest — the computed sha256 is recorded in
 * the manifest and re-checked on subsequent runs. Zip sources need
 * /usr/bin/unzip and are honestly skipped without it.
 */

'use strict';

import { access, readfile, writefile, rename, mkdir, stat, unlink, popen } from 'fs';
import { cursor } from 'uci';
import { emit as ev_emit } from 'eventbus';
import {
	atomic_write as ss_atomic_write, wjson as ss_wjson, rjson as ss_rjson,
	write_state as ss_write_state, read_state as ss_read_state
} from '/etc/ravnex/scripts/statestore.uc';
import {
	get_op as op_get, heartbeat as op_heartbeat, stage as op_stage, finish as op_finish
} from '/etc/ravnex/scripts/opman.uc';
import { classify_entry, HP_DIR as HPD } from '/etc/ravnex/scripts/homeproxy.uc';
import {
	CATALOG as LS_CATALOG, ATTRIBUTION as LS_ATTRIBUTION, hub_source_for
} from '/etc/ravnex/scripts/rulesets_catalog.uc';

/* The lists HUB (ezdizzy/ravnex-lists): CI aggregates + validates + publishes
 * small per-category files with a full-provenance manifest. The hub-primary
 * source is constructed per entry by hub_source_for() (catalog accessors) —
 * upstream URLs below stay as the fallback ladder. A hub release asset also
 * carries a GitHub-API sha256 digest, so the same per-asset gate as the
 * ch.265 core installs applies to hub files. */
const HUB_NOTE = 'hub: ezdizzy/ravnex-lists (validated aggregate; provenance in its manifest.json)';

const RUN_DIR = '/var/run/ravnex';
const ST_FILE = RUN_DIR + '/lists_conveyor.json';
const IDX_CACHE = RUN_DIR + '/zemidala_index.json';
const IDX_FRESH_TTL = 6 * 3600;
/* The lists HUB — the primary transport for strategy JSONs too (raw
 * upstream paths are the reserve; raw.githubusercontent is TSPU-flaky). */
const HUB_REPO = 'ezdizzy/ravnex-lists';
/* Wizard diagnostic inbound that forces the main exit (same as the seeder). */
const MAIN_SOCKS = '127.0.0.1:5337';
const DL_TIMEOUT = 90;
/* BIG transfers (zip archives, heavy archives) need both a bigger clock and
 * a bigger RAM pocket: /tmp is tmpfs, so a 30 MB zip IS 30 MB of RAM while
 * it downloads. Weak-router guard: the pre-flight gate below refuses the
 * work honestly (and keeps the previous file) instead of OOM-ing the box. */
const DL_TIMEOUT_BIG = 420;
/* Resource gates (weak routers): /tmp free space must hold the download
 * (kB), MemAvailable must hold it again, and the persistent overlay must
 * hold the final file + margin before anything is placed on flash. */
const TMP_MARGIN_KB = 8192;
const MEM_MARGIN_KB = 16384;
const FLASH_MARGIN_KB = 1024;
/* Text→JSON conversion guard: lists above this many accepted entries are
 * honest-skipped (memory budget of the box beats completeness). */
const MAX_CONVERT = 150000;

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function wstatus(o) {
	mkdir(RUN_DIR);
	ss_wjson(ST_FILE, o);
}

/* Directory for the rule-set files (same knob as the cold-start seeder). */
function local_dir() {
	const c = cursor();
	c.load('ravnex');
	const d = trim('' + (c.get('ravnex', 'config', 'ruleset_local_path') || ''));
	if (!length(d) || substr(d, 0, 1) !== '/' || index(d, '..') >= 0)
		return '/etc/ravnex/rulesets';
	return d;
}

/* ── weak-router resource gates (weak boxes must get honest skips, not OOM) ─
 * /tmp is tmpfs = RAM; the persistent overlay is flash. Downloads land in
 * /tmp first (RAM, streams through external tools only — ucode never holds
 * a big list in memory), then the FLASH gate runs BEFORE anything is copied
 * onto the overlay, and only then a same-directory temp+rename makes the
 * placement atomic. */

function tmpfs_free_kb() {
	const fd = popen(`df -k /tmp 2>/dev/null | tail -n 1 | awk '{print $4}'`);
	if (!fd)
		return -1;
	const out = trim(fd.read('all'));
	fd.close();
	const n = int(out);
	return (n > 0) ? n : -1;
}

function flash_free_kb() {
	const fd = popen(`df -k /etc/ravnex 2>/dev/null | tail -n 1 | awk '{print $4}'`);
	if (!fd)
		return -1;
	const out = trim(fd.read('all'));
	fd.close();
	const n = int(out);
	return (n > 0) ? n : -1;
}

function mem_available_kb() {
	const raw = readfile('/proc/meminfo');
	if (raw == null)
		return -1;
	const m = match(raw, /MemAvailable:\s+([0-9]+)\skB/);
	if (m)
		return int(m[1]);
	/* old kernels: rough estimate of free+reclaimable */
	const f = match(raw, /MemFree:\s+([0-9]+)\skB/);
	const c = match(raw, /Cached:\s+([0-9]+)\skB/);
	return (f && c) ? (int(f[1]) + int(c[1])) : -1;
}

/* 0 = ok, otherwise a human-readable refusal. want_bytes = the RAM-pool
 * footprint of the download; flash_bytes = the size that will be persisted. */
function resources_gate(want_bytes, flash_bytes) {
	const want_kb = int(want_bytes / 1024) + TMP_MARGIN_KB;
	const t = tmpfs_free_kb();
	if (t >= 0 && t < want_kb)
		return sprintf('/tmp too small for the download (%d kB free, need ~%d kB)', t, want_kb);
	const m = mem_available_kb();
	if (m >= 0 && m < (want_kb + MEM_MARGIN_KB))
		return sprintf('not enough RAM for the download (%d kB available, need ~%d kB)',
			m, want_kb + MEM_MARGIN_KB);
	if (flash_bytes) {
		const fl = flash_free_kb();
		const need_fl = int(flash_bytes / 1024) + FLASH_MARGIN_KB;
		if (fl >= 0 && fl < need_fl)
			return sprintf('not enough flash for the list file (%d kB free, need ~%d kB)', fl, need_fl);
	}
	return null;
}

/* ── low-level helpers (order matters: no hoisting reliance) ─────────────── */

/* sha256 hex of a file via the busybox tool (the byedpi-install pattern). */
function sha256_of(path) {
	const fd = popen(`sha256sum ${shellquote(path)} 2>/dev/null`);
	if (!fd)
		return '';
	const out = fd.read('all');
	fd.close();
	const m = match(trim(out || ''), /^([0-9a-f]{64})/);
	return m ? m[1] : '';
}

/* The sing-box binary rule-set starts with the ASCII magic "SRS". */
function srs_sane(path) {
	const st = stat(path);
	if (!st || st.size < 64)
		return false;
	const fd = popen(`head -c 3 ${shellquote(path)} 2>/dev/null`);
	if (!fd)
		return false;
	const magic = fd.read('all');
	fd.close();
	return substr(magic, 0, 3) === 'SRS';
}

/* A text list must not be an HTML error page and must carry at least one
 * non-comment line (the list_import honesty gate, reused). */
function txt_sane(path) {
	const st = stat(path);
	if (!st || st.size < 8)
		return false;
	const raw = readfile(path);
	if (raw == null)
		return false;
	const head = lc(substr(raw, 0, 512));
	if (index(head, '<html') >= 0 || index(head, '<!doctype') >= 0)
		return false;
	for (let l in split(raw, /[\r\n]/)) {
		l = trim(l);
		if (length(l) && substr(l, 0, 1) !== '#')
			return true;
	}
	return false;
}

/* True when an opman operation with this id actually exists (the RPC-created
 * op). Direct CLI runs pass '-' and skip op journaling. */
function op_id_real(id) {
	return id && id !== '-' && access(RUN_DIR + '/ops/op-' + id + '.json');
}

function gh_token() {
	const fd = popen('uci -q get ravnex.config.github_token 2>/dev/null');
	if (!fd)
		return '';
	const tok = trim(fd.read('all'));
	fd.close();
	return tok;
}

/* GitHub API JSON, curl-first with the token (the TSPU-hardened channel of
 * core_mgmt.gh_api, mirrored — NOT imported: core_mgmt is a backend script
 * without exports). Null on any failure. */
function gh_api_json(url) {
	const tok = gh_token();
	let raw = null;
	const auth = length(tok) ? ` -H 'Authorization: token ${tok}'` : '';
	const fd = popen(`curl -fsSL --connect-timeout 6 --max-time 8${auth} '${url}' 2>/dev/null`);
	if (fd) {
		raw = fd.read('all');
		fd.close();
	}
	if (raw == null || !length(trim(raw))) {
		const fd2 = popen(`wget -qO- --timeout=8${auth} '${url}' 2>/dev/null`);
		if (fd2) {
			raw = fd2.read('all');
			fd2.close();
		}
	}
	if (raw == null || !length(trim(raw)))
		return null;
	try { return json(raw); } catch (e) { return null; }
}

/* One HTTP fetch to a temp file: curl direct → curl via proxy → wget
 * direct → wget via proxy. Returns true on success (rc 0 AND the file
 * appeared); the CALLER owns the sanity check. */
function fetch_to(url, dest, timeout) {
	const proxy = ` --proxy socks5h://${MAIN_SOCKS}`;
	const attempts = [
		/* -f: a 404/error body must FAIL the fetch, never be saved as the
		 * payload (the strategy-JSON path parses the file directly). */
		`curl -fsSL --connect-timeout 8 -m ${timeout} -o ${shellquote(dest)} ${shellquote(url)} 2>/dev/null`,
		`curl -fsSL --connect-timeout 8 -m ${timeout}${proxy} -o ${shellquote(dest)} ${shellquote(url)} 2>/dev/null`,
		`wget -qO ${shellquote(dest)} --timeout=30 ${shellquote(url)} 2>/dev/null`,
		`wget -qO ${shellquote(dest)} --timeout=30${proxy} ${shellquote(url)} 2>/dev/null`
	];
	for (let cmd in attempts) {
		const rc = system(cmd, (timeout + 15) * 1000);
		if (rc === 0 && access(dest))
			return true;
		system(`rm -f ${shellquote(dest)} 2>/dev/null`);
	}
	return false;
}

/* Extract one member of a zip archive (junk paths). True on success. */
function unzip_member(zip, member, dir) {
	if (!access('/usr/bin/unzip'))
		return false;
	const rc = system(`unzip -o -q -j ${shellquote(zip)} ${shellquote(member)} -d ${shellquote(dir)} 2>/dev/null`);
	if (rc !== 0)
		return false;
	let base = member;
	const slash = rindex(base, '/');
	if (slash >= 0)
		base = substr(base, slash + 1);
	return access(dir + '/' + base);
}

/* Convert a downloaded text list into a sing-box source rule-set JSON.
 * Mirrors sync_user_list semantics: classify_entry decides, junk is dropped
 * and COUNTED, output sorted. Returns {accepted, dropped, error?}. */
function convert_txt(src_path, dest_json, fmt) {
	const raw = readfile(src_path);
	if (raw == null)
		return { accepted: 0, dropped: 0, error: 'unreadable' };
	let vals = {}, drops = 0;
	for (let l in split(raw, /[\r\n]/)) {
		l = trim(l);
		if (!length(l) || substr(l, 0, 1) === '#')
			continue;
		const c = classify_entry(l);
		if (!c) { drops++; continue; }
		if (fmt === 'txt-ips') {
			if (c.kind === 'domain') { drops++; continue; }
			vals[c.value] = true;
		} else {
			if (c.kind !== 'domain') { drops++; continue; }
			vals[c.value] = true;
		}
		if (length(keys(vals)) > MAX_CONVERT)
			return { accepted: 0, dropped: drops, error: 'too_many_entries' };
	}
	let arr = [];
	for (let v in keys(vals))
		push(arr, v);
	sort(arr, (a, b) => (a < b) ? -1 : (a > b) ? 1 : 0);
	if (length(arr) > MAX_CONVERT)
		return { accepted: 0, dropped: drops, error: 'too_many_entries' };
	const rules = [];
	if (length(arr))
		push(rules, (fmt === 'txt-ips') ? { ip_cidr: arr } : { domain_suffix: arr });
	ss_atomic_write(dest_json, sprintf('%.J', { version: 1, rules: rules }) + '\n');
	return { accepted: length(arr), dropped: drops };
}

/* Fresh release info for ONE asset: {tag, published_at, digest, size} or
 * null when the API is blind (the sha gate then degrades to computed-only,
 * the same honest degradation as the ch.265 core installs). */
function release_asset(rel, file) {
	if (!rel || rel.message || type(rel.assets) !== 'array')
		return null;
	for (let a in rel.assets) {
		if (('' + (a.name || '')) === file) {
			const d = ('' + (a.digest || ''));
			const m = match(d, /^sha256:([0-9a-f]{64})$/);
			return {
				tag: ('' + (rel.tag_name || '')) || null,
				published_at: ('' + (rel.published_at || '')) || null,
				digest: m ? m[1] : '',
				size: a.size ? int(a.size) : null
			};
		}
	}
	return null;
}

/* ── one catalog entry ───────────────────────────────────────────────────── */

/* ctx carries per-run caches: { dir, force, rel: {repo: release}, zip: {url: path}, ts } */
function entry_produce(e, s, ctx) {
	/* release freshness first (one API call per repo per run) */
	let rel = null, info = null;
	if (s.kind === 'release' || s.kind === 'release-zip') {
		if (!ctx.rel[s.repo])
			ctx.rel[s.repo] = gh_api_json('https://api.github.com/repos/' + s.repo + '/releases/latest');
		rel = ctx.rel[s.repo];
		info = release_asset(rel, s.file);
	}
	const fname = (s.kind === 'release-zip')
		? substr(s.zip_member, rindex(s.zip_member, '/') + 1)
		: substr(s.url, rindex(s.url, '/') + 1);
	const dest = ctx.dir + '/' + e.tag +
		(e.format === 'srs' ? '.srs' : (e.format === 'txt-raw' ? '.lst' : ''));
	const dest_json = (e.consumption === 'local-json') ? (ctx.dir + '/' + e.tag + '.json') : null;

	/* kept short-circuit: same upstream tag (release) or young enough
	 * (raw/site), file present AND its sha matches the manifest. */
	const man = ctx.man;
	const prev = (man && man.entries) ? man.entries[e.id] : null;
	if (!ctx.force && prev && prev.sha && access(dest)) {
		let fresh_enough = false;
		if (prev.published_tag && info && info.tag === prev.published_tag)
			fresh_enough = true;
		else if (!prev.published_tag && prev.fetched_ts &&
		         (time() - int(prev.fetched_ts)) < 4 * 3600)
			fresh_enough = true;
		if (fresh_enough) {
			const cur = sha256_of(dest);
			if (cur && cur === prev.sha)
				return { status: 'kept', sha: cur, bytes: (stat(dest) || {}).size };
		}
	}

	/* ч.274 audit: the resource gate finally RUNS — before any download. A
	 * weak box (little /tmp or little available RAM) gets an honest per-entry
	 * refusal instead of a mid-download OOM or a full /tmp. Release kinds
	 * know the announced size (the ZIP asset itself for release-zip members —
	 * the whole archive lands in /tmp); raw/site kinds have no announced size
	 * — the margins-only check still applies. */
	const zgate_asset = (s.kind === 'release-zip' && rel && type(rel.assets) === 'array')
		? release_asset(rel, substr(s.url, rindex(s.url, '/') + 1)) : null;
	const gate_want = (zgate_asset && zgate_asset.size) ? int(zgate_asset.size)
		: ((info && info.size) ? int(info.size) : 0);
	const gerr = resources_gate(gate_want, gate_want);
	if (gerr != null)
		return { status: 'failed', error: gerr };

	/* obtain the payload into a temp file */
	const tmp = ctx.dir + '/.tmp-' + e.id + '-' + sprintf('%d', ctx.ts);
	let payload = tmp;
	if (s.kind === 'release-zip') {
		const zpath = ctx.zip[s.url];
		if (zpath === 'failed')
			return { status: 'failed', error: 'zip download failed' };
		if (!zpath) {
			const ztmp = '/tmp/hp_lists_zip_' + sprintf('%d', ctx.ts) + '_' + sprintf('%d', length(keys(ctx.zip))) + '.zip';
			if (!fetch_to(s.url, ztmp, DL_TIMEOUT)) {
				ctx.zip[s.url] = 'failed';
				return { status: 'failed', error: 'zip download failed' };
			}
			/* the zip itself carries the per-asset digest */
			const zinfo = release_asset(rel, s.file);
			const zip_asset = (rel && type(rel.assets) === 'array')
				? release_asset(rel, substr(s.url, rindex(s.url, '/') + 1)) : null;
			const zdig = (zip_asset && zip_asset.digest) ? zip_asset.digest : '';
			const zsha = sha256_of(ztmp);
			if (length(zdig) && zsha !== zdig) {
				system(`rm -f ${shellquote(ztmp)} 2>/dev/null`);
				ctx.zip[s.url] = 'failed';
				return { status: 'sha_mismatch', error: 'zip sha256 mismatch' };
			}
			ctx.zip[s.url] = ztmp;
			ctx.zsha = (zsha && !length(zdig)) ? zsha : null;
		}
		if (!unzip_member(ctx.zip[s.url], s.zip_member, ctx.dir))
			return { status: 'failed', error: 'unzip failed (member missing or no unzip)' };
		payload = ctx.dir + '/' + fname;
	} else {
		if (!fetch_to(s.url, tmp, DL_TIMEOUT)) {
			system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
			return { status: 'failed', error: 'download failed (direct+proxy)' };
		}
	}

	/* verify */
	const sha = sha256_of(payload);
	if (!length(sha)) {
		system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
		return { status: 'failed', error: 'sha256 unavailable' };
	}
	const expect = (info && info.digest) ? info.digest : '';
	if (length(expect) && sha !== expect) {
		system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
		return { status: 'sha_mismatch', error: 'sha256 mismatch vs GitHub API digest' };
	}
	const st = stat(payload);
	if (info && info.size && st && st.size != info.size) {
		system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
		return { status: 'sha_mismatch', error: 'size mismatch vs GitHub API asset' };
	}
	if (e.format === 'srs' && !srs_sane(payload)) {
		system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
		return { status: 'failed', error: 'not a valid .srs payload' };
	}
	if ((e.format === 'txt-domains' || e.format === 'txt-ips') && !txt_sane(payload)) {
		system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
		return { status: 'failed', error: 'not a valid text list' };
	}

	/* convert or place. 'source-json' (hub-converted rule-set or a raw text
	 * reserve): a JSON artifact is placed as-is; raw text is converted locally. */
	let converted = null;
	if (e.consumption === 'local-json') {
		const hfd = popen(`head -c 32 ${shellquote(payload)} 2>/dev/null`);
		let head = '';
		if (hfd) { head = hfd.read('all'); hfd.close(); }
		const is_json = (substr(trim(head), 0, 1) === '{') && (index(head, 'version') >= 0);
		if (is_json) {
			ss_atomic_write(dest_json, readfile(payload));
			system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
			converted = { passthrough: true };
		} else {
			if (!txt_sane(payload)) {
				system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
				return { status: 'failed', error: 'not a valid text list (reserve path)' };
			}
			converted = convert_txt(payload, dest_json,
				(e.convert === 'ips') ? 'txt-ips' : 'txt-domains');
			if (converted.error) {
				system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
				return { status: (converted.error === 'too_many_entries') ? 'too_large' : 'failed',
					error: converted.error };
			}
			system(`rm -f ${shellquote(tmp)} 2>/dev/null; rm -f ${shellquote(payload)} 2>/dev/null`);
			converted.sha = sha256_of(dest_json);
		}
	} else if (payload !== dest) {
		rename(payload, dest);
	}
	system(`rm -f ${shellquote(tmp)} 2>/dev/null`);

	return {
		status: 'ok', sha: sha,
		bytes: (e.format === 'srs') ? (stat(dest) || {}).size : (st ? st.size : null),
		origin: s.url, source_kind: s.kind, repo: s.repo || '',
		published_tag: (info && info.tag) || null,
		published_at: (info && info.published_at) || null,
		digest_source: (info && info.digest) ? 'api' : 'computed',
		zip_sha: (s.kind === 'release-zip') ? ctx.zsha : null,
		converted: converted
	};
}

/* Obtain the payload into a temp file. sources[] = hub primary first (when
 * the hub publishes the category), then the catalog's upstream ladder. */
function entry_update(e, ctx) {
	if (e.consumption === 'inline')
		return { status: 'inline_skip' };
	if (e.consumption === 'archive' && e.heavy && !ctx.force && ctx.scope !== 'all')
		return { status: 'skipped', error: 'heavy archive not in scope' };
	const ladder = [];
	const hs = hub_source_for(e);
	if (hs)
		push(ladder, hs);
	for (let s in e.sources)
		push(ladder, s);
	let last_err = null;
	for (let s in ladder) {
		if (op_id_real(ctx.op_id)) {
			op_heartbeat(ctx.op_id);
			op_stage(ctx.op_id, 'running');
		}
		const r = entry_produce(e, s, ctx);
		if (r.status === 'ok' || r.status === 'kept') {
			r.origin = r.origin || s.url;
			r.via_hub = (s.repo === HUB_REPO);
			return r;
		}
		last_err = r;
	}
	return last_err || { status: 'failed', error: 'no source attempted' };
}

/* ── main: update run ────────────────────────────────────────────────────── */

function run_update(op_id, scope, force) {	const dir = local_dir();
	mkdir(dir);
	const ctx = { dir: dir, force: !!force, rel: {}, zip: {}, ts: time(), op_id: op_id, scope: scope };
	let man = null;
	const mp = dir + '/manifest.json';
	const mdoc = ss_read_state(mp);
	man = (mdoc && mdoc.data) ? mdoc.data : { entries: {}, summary: null };
	ctx.man = man;

	/* Which sources the LIVE routing actually consumes — the dynamic part of
	 * the 'default' scope (precision-first: precise layer by default, plus
	 * anything an enabled proxy_ru_rule really needs, even a mass-layer one). */
	let referenced = {};
	{
		const c = cursor();
		c.load('ravnex');
		c.foreach('ravnex', 'proxy_ru_rule', (s) => {
			const src = '' + (s.source || '');
			if (length(src))
				referenced[src] = true;
			return null;
		});
	}

	/* scope selection */
	let chosen = [];
	for (let e in LS_CATALOG) {
		if (scope === 'all')
			push(chosen, e);
		else if (scope === 'default') {
			if (e.default_on || (e.layer || 'precise') === 'precise' ||
			    referenced[e.id] || (e.role === 'ip' && e.of && referenced[e.of]))
				push(chosen, e);
		} else if (scope === e.id)
			push(chosen, e);
	}
	if (scope !== 'all' && scope !== 'default') {
		/* an explicit id brings its IP companion along (one click = coherent pair) */
		for (let e in LS_CATALOG)
			if (e.of === scope && (e.default_on || scope !== 'all'))
				push(chosen, e);
	}

	wstatus({ running: true, ts: time(), scope: scope, done: 0, total: length(chosen), results: [] });

	let ok = 0, failed = 0, skipped = 0;
	const entries = man.entries || {};
	const results = [];
	for (let e in chosen) {
		if (op_id_real(op_id)) {
			op_heartbeat(op_id);
			op_stage(op_id, 'running');
		}
		const r = entry_update(e, ctx);
		const rec = {
			id: e.id, group: e.group, tag: e.tag, name: e.name,
			layer: e.layer || 'precise',
			license: e.license, coverage: e.coverage || 'direct',
			surrogate_note: e.surrogate_note || null,
			format: e.format, consumption: e.consumption,
			via_hub: (r && r.via_hub === true) || false,
			sha256: (r && r.sha) || (entries[e.id] ? entries[e.id].sha256 : null),
			origin: (r && r.origin) || (entries[e.id] ? entries[e.id].origin : null),
			source_kind: (r && r.source_kind) || (entries[e.id] ? entries[e.id].source_kind : null),
			repo: (r && r.repo) || (entries[e.id] ? entries[e.id].repo : e.repo),
			license_note: LS_ATTRIBUTION[e.repo] || LS_ATTRIBUTION[(entries[e.id] ? entries[e.id].repo : '')] || null,
			published_tag: (r && r.published_tag) || (entries[e.id] ? entries[e.id].published_tag : null),
			published_at: (r && r.published_at) || (entries[e.id] ? entries[e.id].published_at : null),
			digest_source: (r && r.digest_source) || (entries[e.id] ? entries[e.id].digest_source : null),
			fetched_ts: (r && (r.status === 'ok')) ? time() : (entries[e.id] ? entries[e.id].fetched_ts : null),
			bytes: (r && r.bytes) || (entries[e.id] ? entries[e.id].bytes : null),
			converted: (r && r.converted) || null,
			zip_sha: (r && r.zip_sha) || null,
			status: r.status, error: r.error || null
		};
		entries[e.id] = rec;
		push(results, { id: e.id, status: r.status, error: r.error || null });
		if (r.status === 'ok' || r.status === 'kept') ok++;
		else if (r.status === 'skipped' || r.status === 'inline_skip') skipped++;
		else failed++;
		wstatus({ running: true, ts: time(), scope: scope, done: length(results),
			total: length(chosen), ok: ok, failed: failed, skipped: skipped, results: results });
	}

	/* clean up cached zips of this run */
	for (let u in ctx.zip) {
		if (length(ctx.zip[u]) > 4)
			system(`rm -f ${shellquote(ctx.zip[u])} 2>/dev/null`);
	}

	/* manifest (persistent, atomic, statestore envelope) */
	man.entries = entries;
	man.summary = { ts: time(), scope: scope, ok: ok, failed: failed, skipped: skipped };
	ss_write_state(dir + '/manifest.json', man);

	wstatus({ running: false, ts: time(), scope: scope, ok: (failed === 0), failed: failed,
		done: length(results), total: length(chosen), ok_count: ok, skipped: skipped, results: results });

	try {
		ev_emit('rulesets', failed ? 'conveyor_failed' : 'conveyor_done', '',
			sprintf('конвейер списков (%s): %d ок, %d ошибок, %d пропущено', scope, ok, failed, skipped));
	} catch (e2) { /* best effort */ }

	if (op_id_real(op_id))
		op_finish(op_id, failed === 0, failed === 0,
			sprintf('scope %s: ok %d, failed %d, skipped %d', scope, ok, failed, skipped));
	return failed === 0;
}

/* Fetch ONE release asset of a repo with the per-asset sha256 gate (the
 * ch.265 pattern). Returns the temp path on success (the caller owns the
 * file) or null. The digest gate degrades gracefully when the API is blind. */
function fetch_release_asset(repo, file, dest) {
	const rel = gh_api_json('https://api.github.com/repos/' + repo + '/releases/latest');
	const info = release_asset(rel, file);
	if (!fetch_to('https://github.com/' + repo + '/releases/latest/download/' + file, dest, DL_TIMEOUT))
		return null;
	const sha = sha256_of(dest);
	if (info && length(info.digest) && sha !== info.digest) {
		system(`rm -f ${shellquote(dest)} 2>/dev/null`);
		return null;
	}
	return dest;
}

/* ── strategies (zemidala per-ASN, the lab_fuzz linkage) ─────────────────── */

const ZEMI_REPO = 'zemidala/nfqws2-strategies';
const ZEMI_INDEX = 'https://raw.githubusercontent.com/zemidala/nfqws2-strategies/main/index.json';
const ZEMI_DATA = 'https://raw.githubusercontent.com/zemidala/nfqws2-strategies/main/data/AS';
const ZEMI_LICENSE = 'zemidala/nfqws2-strategies — no license; data consumed over the network with attribution, not embedded.';

function strategies_check() {
	const tmp = '/tmp/hp_zemi_index.json';
	let ok = false;
	if (fetch_release_asset(HUB_REPO, 'index.json', tmp))
		ok = true;
	else if (fetch_to(ZEMI_INDEX, tmp, 30))
		ok = true;
	if (!ok) {
		system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
		return false;
	}
	const j = ss_rjson(tmp);
	system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
	if (!j || type(j.providers) !== 'array')
		return false;
	ss_wjson(IDX_CACHE, { ts: time(), license: ZEMI_LICENSE, index: j });
	return true;
}

function strategy_index() {
	const doc = ss_rjson(IDX_CACHE);
	if (!doc || !doc.index)
		return null;
	doc.stale = (time() - int(doc.ts || 0)) > IDX_FRESH_TTL;
	return doc;
}

/* Merge the fetched ASN strategies into the corpus: replace the previous
 * zmd-AS<asn>-* entries (the .prev.json rollback copy survives), append the
 * new ones into group 'recommended' (so the quick fuzz measures them), and
 * record the attribution. */
function strategy_import_run(op_id, asn) {
	asn = '' + int(asn);
	if (!length(asn) || asn === '0')
		return false;
	const asetmp = '/tmp/hp_zemi_AS' + asn + '.json';
	/* hub first (validated republish with a digest gate), raw upstream as the reserve */
	if (!fetch_release_asset(HUB_REPO, 'AS' + asn + '.json', asetmp) &&
	    !fetch_to(ZEMI_DATA + asn + '.json', asetmp, 30)) {
		system(`rm -f ${shellquote(asetmp)} 2>/dev/null`);
		if (op_id_real(op_id))
			op_finish(op_id, false, false, 'index/data download failed');
		return false;
	}
	const data = ss_rjson(asetmp);
	if (!data || type(data.items) !== 'array' || !length(data.items)) {
		system(`rm -f ${shellquote(asetmp)} 2>/dev/null`);
		if (op_id_real(op_id))
			op_finish(op_id, false, false, 'no strategies in the dataset');
		return false;
	}

	const cand = HPD + '/zapret_candidates.json';
	const corpus = ss_rjson(cand) || { candidates: [] };
	if (type(corpus.candidates) !== 'array')
		corpus.candidates = [];
	system(`mkdir -p ${shellquote(HPD + '/backups')}; cp ${shellquote(cand)} ${shellquote(HPD + '/backups/zapret_candidates.prev.json')} 2>/dev/null; true`);

	const prefix = 'zmd-AS' + asn + '-';
	let kept = [], added = 0, names = [];
	for (let c in corpus.candidates) {
		const nm = '' + (c.name || '');
		if (index(nm, prefix) !== 0)
			push(kept, c);
	}
	for (let it in data.items) {
		const steps = (type(it.steps) === 'array') ? it.steps : [];
		if (!length(steps) || !length('' + (it.id || '')))
			continue;
		const name = prefix + it.id;
		push(kept, {
			name: name,
			group: 'recommended',
			args: join(steps, ' ')
		});
		push(names, name);
		added++;
	}
	if (!added) {
		system(`rm -f ${shellquote(asetmp)} 2>/dev/null`);
		if (op_id_real(op_id))
			op_finish(op_id, false, false, 'no valid strategy entries');
		return false;
	}
	corpus.candidates = kept;
	ss_atomic_write(cand, sprintf('%.J', corpus) + '\n');
	system(`rm -f ${shellquote(asetmp)} 2>/dev/null`);

	/* attribution doc (network consumption + attribution; nothing embedded) */
	const src = ss_rjson(HPD + '/strategy_sources.json') || { asns: {} };
	src.asns[asn] = {
		provider: '' + (data.provider || ''),
		index_updated: '' + (data.updated || ''),
		fetched_ts: time(),
		count: added,
		names: names,
		license: ZEMI_LICENSE,
		repo: ZEMI_REPO,
		data_url: ZEMI_DATA + asn + '.json'
	};
	ss_wjson(HPD + '/strategy_sources.json', src);

	try {
		ev_emit('rulesets', 'strategies_imported', '',
			sprintf('стратегии AS%s (%s): +%d в корпус лаборатории', asn, '' + (data.provider || ''), added));
	} catch (e) { /* best effort */ }

	if (op_id_real(op_id))
		op_finish(op_id, true, true, sprintf('AS%s: +%d strategies (group recommended)', asn, added));
	return true;
}

/* ── selftest (offline; the {ok, checks[]} shape) ────────────────────────── */

function selftest() {
	const checks = [];
	const add = (name, ok, note) => push(checks, { name: name, ok: ok === true, note: note || null });
	let ok = true;

	/* catalog schema */
	const ids = {}, tags = {};
	for (let e in LS_CATALOG) {
		const eid = '' + (e.id || '');
		add('id:' + eid, match(eid, /^[a-z0-9_-]{2,48}$/) != null && !ids[eid], 'id shape/uniqueness');
		ids[eid] = true;
		const tag = '' + (e.tag || '');
		add('tag:' + eid, match(tag, /^hp-ru-[a-z0-9_-]{2,64}$/) != null && !tags[tag], 'tag shape/uniqueness');
		tags[tag] = true;
		add('license:' + eid, length('' + (e.license || '')) > 0, 'license recorded');
		add('covers:' + eid, length('' + (e.covers || '')) > 0, 'coverage description present');
		if ((e.coverage || '') === 'surrogate')
			add('surrogate-note:' + eid, length('' + (e.surrogate_note || '')) > 0, 'surrogate must carry a note');
		if (e.consumption === 'remote' || e.consumption === 'local-json' || e.consumption === 'archive') {
			let any_url = false;
			for (let s in e.sources) {
				any_url = any_url || (length('' + (s.url || '')) > 8);
				if ((s.kind || '') === 'release-zip')
					add('zip-member:' + eid, length('' + (s.zip_member || '')) > 0, 'zip sources need zip_member');
			}
			add('sources:' + eid, any_url, 'at least one source url');
		}
	}
	add('refilter-pair', !!ids['refilter-domain'] && !!ids['refilter-ip'], 'generator pair present');
	add('zip-capability-note', access('/usr/bin/unzip'), 'unzip available for zip sources (informational)');

	/* txt conversion round-trip on a temp file */
	const tf = '/tmp/hp_lists_selftest.txt';
	ss_atomic_write(tf, '# comment\nexample.com\nsub.example.com\n1.2.3.4\nnot a domain!!\n');
	const conv = convert_txt(tf, '/tmp/hp_lists_selftest.json', 'txt-domains');
	add('convert-basic', conv.accepted === 2 && conv.dropped === 2, '2 domains accepted, the bare IP and junk dropped');
	const jdoc = ss_rjson('/tmp/hp_lists_selftest.json');
	add('convert-shape', !!jdoc && jdoc.version === 1 && length(jdoc.rules) === 1 &&
		length(jdoc.rules[0].domain_suffix) === 2, 'rule-set JSON shape');
	system('rm -f /tmp/hp_lists_selftest.txt /tmp/hp_lists_selftest.json 2>/dev/null');

	/* manifest round-trip */
	const mf = '/tmp/hp_lists_selftest_manifest.json';
	const HEX64 = 'abababababababababababababababababababababababababababababababab';
	ss_write_state(mf, { entries: { x: { sha256: HEX64 } }, summary: { ok: 1 } });
	const mr = ss_read_state(mf);
	add('manifest-roundtrip', !!mr && !!mr.meta && mr.data.summary.ok === 1, 'statestore envelope');
	system('rm -f /tmp/hp_lists_selftest_manifest.json 2>/dev/null');

	/* corpus merge prefix semantics */
	add('prefix-semantics', index('zmd-AS12389-abc', 'zmd-AS12389-') === 0 &&
		index('zmd-AS1238-abc', 'zmd-AS12389-') !== 0, 're-import prefix must not cross ASNs');

	/* digest format: a real 64-hex and a wrong-length neighbor */
	add('digest-format',
		match('a3b1c2d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef', /^[0-9a-f]{64}$/) != null,
		'sha256 hex regex');
	add('digest-format-neg', match('zz', /^[0-9a-f]{64}$/) == null, 'non-hex rejected');

	for (let c in checks)
		if (!c.ok)
			ok = false;
	return { ok: ok, checks: checks };
}

/* ── dispatch ────────────────────────────────────────────────────────────── */

const act = ARGV[0] || '';

if (act === 'update') {
	const ok = run_update(ARGV[1] || '-', ARGV[2] || 'default', ARGV[3] === 'force');
	exit(ok ? 0 : 1);
} else if (act === 'strategies-check') {
	exit(strategies_check() ? 0 : 1);
} else if (act === 'strategy-import') {
	exit(strategy_import_run(ARGV[1] || '-', ARGV[2] || '') ? 0 : 1);
} else if (act === 'selftest') {
	const r = selftest();
	print(sprintf('%.J\n', r));
	exit(r.ok ? 0 : 1);
} else {
	print('usage: lists_conveyor.uc update <op_id|-> <scope> [force] | strategies-check | strategy-import <op_id|-> <asn> | selftest\n');
	exit(2);
}
