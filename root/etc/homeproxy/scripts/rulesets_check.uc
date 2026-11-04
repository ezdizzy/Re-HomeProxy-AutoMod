#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * rulesets_check.uc — Ф5.2: upstream-версии репозиториев remote rule-set'ов.
 * Собирает GitHub-repos из URL всех remote rule-set'ов ЖИВОГО конфига
 * (тот же источник, что у rulesets_seed.uc) и спрашивает у GitHub API
 * последний релиз каждого репозитория, у которого rule-set-URL имеет вид
 * releases/latest/download/<file> (itdoginfo/allow-domains,
 * 1andrevich/Re-filter-lists, Greeg0ry/b4geoip-forkop). URL, указывающие
 * на ВЕТКУ (raw.githubusercontent … /sing/…), честно не версионируются —
 * для них версии нет ни у кого.
 *
 * Спавнится detached RPC app_rulesets_local_status (не чаще раза в 15 мин
 * по гварду RPC + running-флаг), кэш — RUN_DIR/rulesets_upstream.json
 * (атомарно tmp+mv, TTL 6 ч). Сеть: сначала напрямую, при неудаче — через
 * wizard-socks 127.0.0.1:5337 (та же механика сидера).
 */

'use strict';

import { access, readfile, writefile, rename, mkdir, stat, unlink, popen } from 'fs';

const RUN_DIR = '/var/run/homeproxy';
const ST_FILE = RUN_DIR + '/rulesets_upstream.json';
const RUN_FLAG = RUN_DIR + '/rulesets_upstream.running';
/* Wizard diagnostic inbound that forces the main exit (always-on with a
 * configured main node; generate_client.uc emits it). */
const MAIN_SOCKS = '127.0.0.1:5337';
const DL_TIMEOUT = 25;

function shellquote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
}

function wstatus(o) {
	mkdir(RUN_DIR);
	const tmp = ST_FILE + '.tmp';
	writefile(tmp, sprintf('%J\n', o));
	rename(tmp, ST_FILE);
}

/* Remote rule-sets of the live config — the same source as the seed runner. */
function remote_urls() {
	let data = null;
	try { data = json(readfile(RUN_DIR + '/hiddify-c.json') || ''); } catch (e) { data = null; }
	const out = [];
	const rs = (data && data.route && type(data.route.rule_set) === 'array') ? data.route.rule_set : [];
	for (let r in rs) {
		if (r.type !== 'remote' || !length('' + (r.url || '')))
			continue;
		push(out, '' + r.url);
	}
	return out;
}

/* Repos whose rule-set URLs come from a RELEASE (not a branch). */
function release_repos(urls) {
	const repos = {};
	for (let u in urls) {
		const m = match(u, /^https?:\/\/[^/]*github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/releases\//);
		if (m)
			repos[m[1] + '/' + m[2]] = true;
	}
	return repos;
}

function curl_json(url, via_proxy) {
	const proxy = via_proxy ? ` --proxy socks5h://${MAIN_SOCKS}` : '';
	const tmp = '/tmp/rulesets_check.json';
	system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
	const rc = system(
		`curl -fsSL --connect-timeout 8 -m ${DL_TIMEOUT}${proxy} -H 'Accept: application/vnd.github+json' -o ${shellquote(tmp)} ${shellquote(url)} 2>/dev/null`,
		(DL_TIMEOUT + 15) * 1000
	);
	if (rc !== 0 || !access(tmp))
		return null;
	let j = null;
	try { j = json(readfile(tmp) || ''); } catch (e) { j = null; }
	system(`rm -f ${shellquote(tmp)} 2>/dev/null`);
	return j;
}

function fetch_release(repo) {
	const j = curl_json('https://api.github.com/repos/' + repo + '/releases/latest', false) ||
	          curl_json('https://api.github.com/repos/' + repo + '/releases/latest', true);
	if (!j || j.message || !j.tag_name)
		return { error: 'GitHub API недоступен или ответ не распознан' };
	return { tag: '' + j.tag_name, published_at: '' + (j.published_at || '') };
}

/* ── main ────────────────────────────────────────────────────────────────── */

mkdir(RUN_DIR);
writefile(RUN_FLAG, sprintf('%d\n', time()));

const urls = remote_urls();
const repos = release_repos(urls);
const out = {};
for (let repo in repos)
	out[repo] = fetch_release(repo);

wstatus({ ts: time(), repos: out });

try { unlink(RUN_FLAG); } catch (e) { /* best effort */ }
