/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 ImmortalWrt.org
 */

import { open, readfile, writefile, access } from 'fs';
import { urldecode_params } from 'luci.http';

/* Global variables start */
export const HP_DIR = '/etc/homeproxy';
export const RUN_DIR = '/var/run/homeproxy';
/* Global variables end */

/* Utilities start */
/* Kanged from luci-app-commands */
export function shellQuote(s) {
	return `'${replace(s, "'", "'\\''")}'`;
};

export function isBinary(str) {
	for (let off = 0, byte = ord(str); off < length(str); byte = ord(str, ++off))
		if (byte <= 8 || (byte >= 14 && byte <= 31))
			return true;

	return false;
};

let exec_seq = 0;
export function executeCommand(...args) {
	/* Named temp files instead of mkstemp(): mkstemp streams never expose their
	 * path and older ucode lacks fs.remove, so those files leaked into /tmp on
	 * every invocation. Unique per-call names via a sequence counter + rm after
	 * reading keep this leak-free and re-entrant. */
	const uniq = `${time()}.${++exec_seq}`;
	const outf = RUN_DIR + '/exec.' + uniq + '.out';
	const errf = RUN_DIR + '/exec.' + uniq + '.err';

	const exitcode = system(`${join(' ', args)} > ${shellQuote(outf)} 2> ${shellQuote(errf)}`);

	/* Read to EOF, not a fixed 512KB cap: subscription bodies beyond the old cap
	 * were silently truncated mid-line — the parser then dropped the tail nodes
	 * and the removal phase DELETED them from the config as "disappeared". */
	let stdout = '', stderr = '', chunk;
	let outfd = open(outf, 'r');
	if (outfd) {
		while ((chunk = outfd.read(65536)) && length(chunk))
			stdout += chunk;
		outfd.close();
	}
	let errfd = open(errf, 'r');
	if (errfd) {
		while ((chunk = errfd.read(65536)) && length(chunk))
			stderr += chunk;
		errfd.close();
	}

	system(`rm -f ${shellQuote(outf)} ${shellQuote(errf)} 2>/dev/null`);

	const binary = isBinary(stdout);

	return {
		command: join(' ', args),
		stdout: binary ? null : stdout,
		stderr,
		exitcode,
		binary
	};
};

export function getTime(epoch) {
	const local_time = localtime(epoch);
	return replace(replace(sprintf(
		'%d-%2d-%2d@%2d:%2d:%2d',
		local_time.year,
		local_time.mon,
		local_time.mday,
		local_time.hour,
		local_time.min,
		local_time.sec
	), ' ', '0'), '@', ' ');

};

export function wGET(url, ua) {
	if (!url || type(url) !== 'string')
		return null;

	if (!ua)
		ua = 'Wget/1.21 (HomeProxy, like v2rayN)';

	const output = executeCommand(`/usr/bin/wget -qO- --user-agent ${shellQuote(ua)} --timeout=10 ${shellQuote(url)}`) || {};
	return trim(output.stdout);
};
/* Write a rule-set file atomically (temp + rename) so the core's file watcher never
 * reads a half-written JSON: fsnotify can fire mid-write, and a truncated parse error
 * would keep the previous (stale) rules until the next event. rename(2) is atomic on the
 * overlayfs upper layer, and sing-box (>=1.10.0) correctly tracks a file replaced via
 * rename (mv), so the watcher keeps working after the swap. */
function write_ruleset_file(path, obj) {
	let tmp = path + '.tmp';
	writefile(tmp, sprintf('%.J\n', obj));
	system('mv -f ' + shellQuote(tmp) + ' ' + shellQuote(path));
}

/* Learned-list hot reload:
 * Write the auto-detected blocked-site lists as sing-box RuleSet source JSON files so the
 * core can hot-reload them via its LOCAL rule-set file watcher — no service restart, no
 * dropped connections. Both hiddify-core and sing-box-extended are sing-box forks that
 * auto-reload a `type: local` rule-set when its file changes (since sing-box 1.10.0).
 *
 *   resources/proxy_domain.json  = static proxy_list.txt  +  learned auto_proxy_list.txt
 *                                   (domain_keyword)  -> referenced by the 'proxy-domain' ruleset
 *   resources/auto_ip.json       = learned auto_proxy_ip.txt (ip_cidr)
 *                                   -> referenced by the 'auto-ip' ruleset
 *
 * Called by generate_client.uc (so the files always exist when the core starts) and by
 * automation.uc on every learn (the hot path — rewrite the file, the core picks it up). */
export function sync_learned_rulesets() {
	let res = HP_DIR + '/resources';
	system('mkdir -p ' + res);
	/* Static list keeps its upstream KEYWORD semantics (substring match, curated by
	 * the user). Learned entries are EXACT hosts discovered automatically — they must
	 * go out as domain_suffix (suffix-with-dot-boundary match): a keyword like "t.co"
	 * would also match "reddit.com" and silently reroute unrelated sites via proxy. */
	let domains = [], learned_domains = [], ips = [];

	if (access(res + '/proxy_list.txt')) {
		let raw = readfile(res + '/proxy_list.txt');
		if (raw)
			domains = filter(split(trim(raw), /[\r\n]/), (d) => {
				d = trim(d);
				return length(d) && !match(d, /^\s*#/);
			});
	}
	if (access(res + '/auto_proxy_list.txt')) {
		let raw = readfile(res + '/auto_proxy_list.txt');
		if (raw)
			for (let i, d in filter(split(trim(raw), /[\r\n]/), (x) => {
				x = trim(x);
				return length(x) && !match(x, /^\s*#/);
			}))
				push(learned_domains, d);
	}
	if (access(res + '/auto_proxy_ip.txt')) {
		let raw = readfile(res + '/auto_proxy_ip.txt');
		if (raw)
			ips = filter(split(trim(raw), /[\r\n]/), (x) => {
				x = trim(x);
				return length(x) && !match(x, /^\s*#/) &&
				       (match(x, /^[0-9.]+\/[0-9]+$/) || match(x, /^[0-9a-fA-F:]+(\/[0-9]+)?$/));
			});
	}

	/* Both rules live in ONE watched rule-set file so a single hot-reload applies
	 * static and learned entries together. */
	let rules = [];
	if (length(domains))
		push(rules, { domain_keyword: domains });
	if (length(learned_domains))
		push(rules, { domain_suffix: learned_domains });
	write_ruleset_file(res + '/proxy_domain.json', {
		version: 1,
		rules: rules
	});
	write_ruleset_file(res + '/auto_ip.json', {
		version: 1,
		rules: length(ips) ? [ { ip_cidr: ips } ] : []
	});

	return { domains: length(domains) + length(learned_domains), ips: length(ips) };
};

/* Utilities end */

/* String helper start */
export function isEmpty(res) {
	return !res || res === 'nil' || (type(res) in ['array', 'object'] && length(res) === 0);
};

export function strToBool(str) {
	return (str === '1') || null;
};

export function strToInt(str) {
	return !isEmpty(str) ? (int(str) || null) : null;
};

export function strToTime(str) {
	if (isEmpty(str))
		return null;
	str = '' + str;
	/* A subscription may already deliver a unit-bearing duration (e.g. sing-box
	 * "10s", "1m30s"); only append 's' to a bare number so we never emit "10ss". */
	return match(str, /[a-zA-Z]$/) ? str : (str + 's');
};

export function removeBlankAttrs(res) {
	let content;

	if (type(res) === 'object') {
		content = {};
		map(keys(res), (k) => {
			if (type(res[k]) in ['array', 'object'])
				content[k] = removeBlankAttrs(res[k]);
			else if (res[k] !== null && res[k] !== '')
				content[k] = res[k];
		});
	} else if (type(res) === 'array') {
		content = [];
		map(res, (k, i) => {
			if (type(k) in ['array', 'object'])
				push(content, removeBlankAttrs(k));
			else if (k !== null && k !== '')
				push(content, k);
		});
	} else
		return res;

	return content;
};

export function validateHostname(hostname) {
	return (match(hostname, /^[a-zA-Z0-9_]+$/) != null ||
		(match(hostname, /^[a-zA-Z0-9_][a-zA-Z0-9_%-.]*[a-zA-Z0-9]$/) &&
			match(hostname, /[^0-9.]/)));
};

export function validation(datatype, data) {
	if (!datatype || !data)
		return null;

	const ret = system(`/sbin/validate_data ${shellQuote(datatype)} ${shellQuote(data)} 2>/dev/null`);
	return (ret === 0);
};
/* String helper end */

/* String parser start */
export function decodeBase64Str(str) {
	if (isEmpty(str))
		return null;

	str = trim(str);
	str = replace(str, '_', '/');
	str = replace(str, '-', '+');

	const padding = length(str) % 4;
	if (padding)
		str = str + substr('====', padding);

	return b64dec(str);
};

export function parseURL(url) {
	if (type(url) !== 'string')
		return null;

	const services = {
		http: '80',
		https: '443'
	};

	const objurl = {};

	objurl.href = url;

	url = replace(url, /#(.+)$/, (_, val) => {
		objurl.hash = val;
		return '';
	});

	url = replace(url, /^(\w[A-Za-z0-9\+\-\.]+):/, (_, val) => {
		objurl.protocol = val;
		return '';
	});

	url = replace(url, /\?(.+)/, (_, val) => {
		objurl.search = val;
		objurl.searchParams = urldecode_params(val);
		return '';
	});

	url = replace(url, /^\/\/([^\/]+)/, (_, val) => {
		val = replace(val, /^([^@]+)@/, (_, val) => {
			objurl.userinfo = val;
			return '';
		});

		val = replace(val, /:(\d+)$/, (_, val) => {
			objurl.port = val;
			return '';
		});

		if (validation('ip4addr', val) ||
		    validation('ip6addr', replace(val, /\[|\]/g, '')) ||
		    validation('hostname', val))
			objurl.hostname = val;

		return '';
	});

	objurl.pathname = url || '/';

	if (!objurl.protocol || !objurl.hostname)
		return null;

	if (objurl.userinfo) {
		objurl.userinfo = replace(objurl.userinfo, /:(.+)$/, (_, val) => {
			objurl.password = val;
			return '';
		});

		if (match(objurl.userinfo, /^[A-Za-z0-9\+\-\_\.]+$/)) {
			objurl.username = objurl.userinfo;
			delete objurl.userinfo;
		} else {
			delete objurl.userinfo;
			delete objurl.password;
		}
	};

	if (!objurl.port)
		objurl.port = services[objurl.protocol];

	objurl.host = objurl.hostname + (objurl.port ? `:${objurl.port}` : '');
	objurl.origin = `${objurl.protocol}://${objurl.host}`;

	return objurl;
};
/* String parser end */
