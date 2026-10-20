#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — Routing Wizard: multi-profile composition builder (Ф8-W3).
 *
 * Builds a combined nfqws2 strategy from per-resource profiles and runs the
 * isolated smoke test (zapret_test.sh, temp queue 209) on the composed args.
 *
 * Input:  /var/run/homeproxy/wizard_compose_req.json
 *         { profiles: [ { resource: "yt", strategy: "<corpus name|raw args>",
 *                         domains: ["youtube.com", ...] }, ... ] }
 * Output: /var/run/homeproxy/wizard_compose_result.json
 *         { running: bool, stage: "build"|"test"|"done"|"error",
 *           args: "...", profiles: N, test: {...} }
 *
 * Profile semantics (validated live, session 13):
 *   - the FIRST profile must be implicit: a leading --new creates an empty
 *     catch-all profile that swallows all packets with no desync (probe T11);
 *   - --blob args are global and may sit before the first profile (T8);
 *   - --name inside a profile block is allowed (T12) but not required;
 *   - --hostlist-domains is a per-profile option: the builder appends it to
 *     EVERY profile of a resource-scoped strategy so the whole strategy is
 *     limited to the resource, and unscoped (general) profiles stay catch-all.
 */

import { readfile, access, writefile } from 'fs';

const RUN_DIR = '/var/run/homeproxy';
const REQ = RUN_DIR + '/wizard_compose_req.json';
const OUT = RUN_DIR + '/wizard_compose_result.json';
const TEST_OUT = RUN_DIR + '/wizard_compose_test.json';

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

/* Split a strategy string into profile blocks by '--new'. */
function split_profiles(args) {
	const raw = split('' + args, '--new');
	const blocks = [];
	for (let i = 0; i < length(raw); i++) {
		const b = trim(raw[i]);
		if (length(b))
			push(blocks, b);
	}
	return blocks;
}

/* Extract global --blob args from a block; returns [clean_block, blob_args]. */
function extract_blobs(block) {
	const toks = split(block, ' ');
	const rest = [];
	const blobs = [];
	for (let i = 0; i < length(toks); i++) {
		const t = trim(toks[i]);
		if (!length(t))
			continue;
		if (index(t, '--blob=') === 0)
			push(blobs, t);
		else
			push(rest, t);
	}
	return [ join(' ', rest), blobs ];
}

/* Resolve a profile's strategy (corpus name or raw args) to its arg string. */
function resolve_strategy(p, corpus) {
	const s = trim('' + (p.strategy || ''));
	if (!length(s))
		return null;
	if (index(s, '--') === 0)
		return s;
	for (let ci = 0; ci < length(corpus.candidates); ci++) {
		const c = corpus.candidates[ci];
		if (type(c) === 'object' && c.name === s)
			return '' + c.args;
	}
	return null;
}

function build_composition(profiles, corpus) {
	const blob_map = {};
	const blocks = [];
	for (let pi = 0; pi < length(profiles); pi++) {
		const p = profiles[pi];
		const strat_args = resolve_strategy(p, corpus);
		if (strat_args == null)
			continue;
		const parts = split_profiles(strat_args);
		const domains = (type(p.domains) === 'array') ? p.domains : [];
		const hl = length(domains) ? ' --hostlist-domains=' + join(',', domains) : '';
		for (let bi = 0; bi < length(parts); bi++) {
			const res = extract_blobs(parts[bi]);
			const cleaned = res[0];
			const bl = res[1];
			for (let b in bl)
				blob_map[b] = true;
			if (length(cleaned) || length(hl))
				push(blocks, cleaned + hl);
		}
	}
	const blob_arr = [];
	for (let k in blob_map)
		push(blob_arr, k);
	let final = join(' ', blob_arr);
	for (let i = 0; i < length(blocks); i++) {
		if (i === 0)
			final += (length(final) ? ' ' : '') + blocks[i];
		else
			final += ' --new ' + blocks[i];
	}
	/* safety: never allow a leading --new (empty catch-all profile = broken) */
	while (length(final) > 6 && substr(final, 0, 6) === '--new ')
		final = trim(substr(final, 6));
	return final;
}

function main() {
	const req = read_json(REQ);
	if (req == null || type(req.profiles) !== 'array' || !length(req.profiles)) {
		wstat({ running: false, stage: 'error', error: 'no profiles in request' });
		return;
	}
	const corpus = read_json('/etc/homeproxy/zapret_candidates.json') || { candidates: [] };

	wstat({ running: true, stage: 'build', profiles: length(req.profiles) });
	const args = build_composition(req.profiles, corpus);
	if (!length(args)) {
		wstat({ running: false, stage: 'error', error: 'empty composition' });
		system(`rm -f ${sq(REQ)}`);
		return;
	}

	wstat({ running: true, stage: 'test', args: args, profiles: length(req.profiles) });
	system(sprintf('sh /etc/homeproxy/scripts/zapret_test.sh %s > %s 2>/dev/null', sq(args), sq(TEST_OUT)), 60000);
	const test = read_json(TEST_OUT);

	wstat({ running: false, stage: 'done', args: args, profiles: length(req.profiles), test: test });
	system(`rm -f ${sq(REQ)} ${sq(TEST_OUT)}`);
}

main();
