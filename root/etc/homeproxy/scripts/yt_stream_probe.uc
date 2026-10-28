#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Re:HomeProxy AutoMod — real YouTube video-stream URL helper (ч.116).
 *
 * WHY: a TLS handshake and a tiny fetch (page/thumbnail/404-edge) cannot
 * see what the user actually complains about — TSPU lets the handshake
 * through and then THROTTLES the sustained googlevideo stream (preview
 * images and videos crawl). The honest metric is a multi-MB ranged
 * download from a REAL videoplayback URL, measured in bytes/second.
 * This helper produces that URL once and shares it (cached) with every
 * consumer: the Strategy Lab deep battery (zapret_fuzz.sh/zapret_test.sh),
 * the auto-pick verify (wizard_autopick.uc), the auto-pilot health
 * (zapret_autopilot.uc) and the wizard_dpi_probe RPC.
 *
 * How: the innertube player endpoint (ANDROID, then IOS as the fallback —
 * clients that hand out plain streaming URLs without signature
 * deciphering) for a tiny stable public video (Me at the zoo). On
 * failure the cache carries ok:false for 10 minutes so a broken upstream
 * does not hammer the API, and every consumer degrades honestly (the
 * probe is skipped, the rest of the checks still run).
 *
 * Usage:  ucode /etc/homeproxy/scripts/yt_stream_probe.uc get
 * Output: one JSON line { ok, url, host, note, ts, cached }
 *
 * ucode constraints honored (05-doc): no typeof (type()); match() only
 * with /regex/ literals; json() is a parser (serialize via sprintf('%.J'));
 * sleep() in ms; atomic writes (tmp + mv -f); no optional chaining.
 */

import { readfile, writefile, access } from 'fs';

const RUN_DIR = '/var/run/homeproxy';
const CACHE = RUN_DIR + '/yt_stream.json';
const OK_TTL = 1800;     /* reuse a stream URL for 30 min (valid ~6 h)  */
const FAIL_TTL = 600;    /* a failure is cached for 10 min              */
/* ч.123: several tiny stable public videos — the innertube bot-gate is
 * per-request/per-video; rotating (client × video) triples the chance a
 * plain streaming URL is handed out (the yts probe is honest-absent without
 * one, and the real-stream speed is the metric the user actually feels). */
const VIDEO_IDS = [ 'jNQXAC9IVRw', 'dQw4w9WgXcQ', '9bZkp7q19f0' ];
const TMO = 20;          /* per-request curl --max-time                 */

/* Public innertube clients that return PLAIN stream URLs (no cipher).
 * The muxed 18 (360p) is the fallback; video-only high-itag formats are
 * preferred (bigger files make the throughput window honest). Each client
 * carries its long-stable public innertube API key — without it the
 * endpoint answers 400 FAILED_PRECONDITION (caught live, ч.116). */
const CLIENTS = [
	{
		name: 'android',
		url: 'https://www.youtube.com/youtubei/v1/player?key=AIzaSyA8eiZmM1FaDVjRy-dfac2NfvGNXzMyFxA&prettyPrint=false',
		ua: 'com.google.android.youtube/19.09.37 (Linux; U; Android 11) gzip',
		body: { context: { client: { clientName: 'ANDROID', clientVersion: '19.09.37',
			androidSdkVersion: 30, hl: 'en', gl: 'US' } },
			videoId: VIDEO_ID, contentCheckOk: true, racyCheckOk: true }
	},
	{
		name: 'ios',
		url: 'https://www.youtube.com/youtubei/v1/player?key=AIzaSyB-63vPrdThhKuerbB2N_l7Kwwcxj6yUAc&prettyPrint=false',
		ua: 'com.google.ios.youtube/19.29.1 (iPhone14,3; U; iOS 15.6) gzip',
		body: { context: { client: { clientName: 'IOS', clientVersion: '19.29.1',
			deviceMake: 'Apple', deviceModel: 'iPhone14,3', osName: 'iPhone',
			osVersion: '15.6.1', hl: 'en', gl: 'US' } },
			videoId: VIDEO_ID, contentCheckOk: true, racyCheckOk: true }
	}
];

function read_json(path) {
	if (!access(path)) return null;
	try { return json(readfile(path) || ''); } catch (e) { return null; }
}

function wcache(o) {
	o.ts = time();
	writefile(CACHE + '.tmp', sprintf("%.J\n", o));
	system(`mv -f '${CACHE}.tmp' '${CACHE}'`);
}

function emit(o, cached) {
	o.cached = cached ? 1 : 0;
	print(sprintf("%.J\n", o));
}

/* POST the player request through the CONFIGURED path (router-origin
 * curl rides the app's own interception, exactly like LAN clients). */
function player_request(cl, body_file) {
	const of = '/tmp/yt_player.' + cl.name + '.json';
	system(`rm -f '${of}' 2>/dev/null`);
	const cmd = `curl -s --max-time ${TMO} -A '${cl.ua}' ` +
		`-H 'Content-Type: application/json' --data-binary @'${body_file}' ` +
		`'${cl.url}' -o '${of}' 2>/dev/null`;
	const rc = system(cmd, TMO * 1000 + 4000);
	const raw = (rc == 0) ? readfile(of) : null;
	system(`rm -f '${of}' '${body_file}' 2>/dev/null`);
	if (raw == null || !length(raw))
		return null;
	try { return json(raw); } catch (e) { return null; }
}

/* Pick a stream URL from the player response: plain `url` only (a
 * signatureCipher entry is undecipherable here), video-only formats
 * preferred (larger files → the ranged window measures throughput, not
 * the whole file), higher itag preferred among equals. */
function extract_stream(j) {
	if (j == null || type(j) !== 'object')
		return null;
	const ps = j.playabilityStatus;
	if (ps == null || ps.status !== 'OK')
		return null;
	const sd = j.streamingData;
	if (sd == null || type(sd) !== 'object')
		return null;
	const fmts = [];
	if (type(sd.formats) === 'array')
		for (let f in sd.formats)
			push(fmts, f);
	if (type(sd.adaptiveFormats) === 'array')
		for (let f in sd.adaptiveFormats)
			push(fmts, f);
	let pick = null, pick_score = -1;
	for (let f in fmts) {
		if (type(f) !== 'object' || f.url == null)
			continue;
		const mime = '' + (f.mimeType || '');
		const itag = int(f.itag) || 0;
		const score = ((index(mime, 'video') >= 0) ? 1000 : 0) + itag;
		if (score > pick_score) { pick = f; pick_score = score; }
	}
	if (pick == null)
		return null;
	const url = '' + pick.url;
	const mh = match(url, /^https:\/\/([^\/]+)/);
	return { url: url, host: (mh != null) ? mh[1] : '' };
}

function main() {
	const cached = read_json(CACHE);
	if (cached != null && type(cached) === 'object' && cached.ts != null) {
		const age = time() - int(cached.ts);
		if (cached.ok && age < OK_TTL) { emit(cached, true); return; }
		if (!cached.ok && age < FAIL_TTL) { emit(cached, true); return; }
	}
	let last_note = 'no answer';
	for (let cl in CLIENTS) {
		for (let vid in VIDEO_IDS) {
			const bf = '/tmp/yt_body.json';
			const body = cl.body;
			body.videoId = vid;
			writefile(bf, sprintf("%.J", body));
			const j = player_request(cl, bf);
			const st = extract_stream(j);
			if (st != null && length(st.url) && index(st.url, "'") < 0 &&
				length(st.host)) {
				const out = { ok: true, url: st.url, host: st.host,
					note: cl.name + '/' + vid };
				wcache(out);
				emit(out, false);
				return;
			}
			if (j != null && type(j) === 'object' &&
				j.playabilityStatus != null)
				last_note = cl.name + '/' + vid + ': ' +
					('' + (j.playabilityStatus.status || 'no status'));
			else
				last_note = cl.name + '/' + vid + ': no/bad player response';
		}
	}
	const out = { ok: false, url: '', host: '', note: last_note };
	wcache(out);
	emit(out, false);
}

main();
