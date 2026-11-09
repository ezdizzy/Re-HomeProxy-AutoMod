/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * rulesets_catalog.uc — the SOURCES CATALOG of the lists conveyor (док 26;
 * seance 178). One authoritative registry of external rule-list sources:
 * primary URL + reserves/mirrors, format, license, coverage honesty
 * (direct vs SURROGATE), origin repo for the GitHub-API freshness/digest
 * checks. NOTHING else in the app hardcodes a list URL: the generator
 * (generate_client.uc) and the conveyor (lists_conveyor.uc) read THIS file.
 *
 * Principles (док 26 «Архитектурные принципы»):
 *   - per-category rule-sets, never merged into one file;
 *   - a category may carry several sources — membership/origin is preserved
 *     in the manifest (lists_conveyor.uc writes it);
 *   - CDN/IP layers live as their own entries, separate from domain lists;
 *   - sources WITHOUT a license are consumed over the network with
 *     attribution — never embedded into the distribution package;
 *   - white spots are honest SURROGATE entries (approximation, stated).
 *
 * sources[] is a FALLBACK LADDER: first entry = primary, the rest are
 * reserves. kinds:
 *   release  — https://github.com/<repo>/releases/latest/download/<file>
 *              (conveyor verifies the per-asset sha256 digest from the
 *              GitHub API — the same gate as the core installs);
 *   release-zip — the release publishes a ZIP archive; zip_member names
 *              the file to extract (needs /usr/bin/unzip, checked live);
 *   raw      — raw.githubusercontent.com/<repo>/<branch>/<path>;
 *   site     — a plain non-GitHub HTTP(S) file.
 *
 * consumption: how the routing engine may use the category —
 *   remote     — a binary .srs the generator may declare as a remote
 *                rule-set (the core downloads and refreshes it daily);
 *   local-json — a text list the conveyor converts into a local sing-box
 *                source rule-set (JSON); the generator declares it as a
 *                LOCAL rule-set when the converted file exists;
 *   archive    — fetched and pinned for provenance only (huge aggregates);
 *   inline     — shipped with the package as an inline domain list
 *                (rule_<id>.txt); the conveyor does not fetch it.
 */

'use strict';

export const CATALOG = [
	/* ── ru-core: массовые списки блокировок (док 26 §F) ─────────────────── */

	{
		id: 'refilter-domain', tag: 'hp-ru-refilter-domain', group: 'ru-core', layer: 'mass',
		name: 'Re-filter — blocked domains (refilter_domains)',
		covers: 'Mass RKN-blocked domains, refilter build',
		consumption: 'remote', format: 'srs', seed: true, default_on: false, heavy: false,
		license: 'MIT', repo: '1andrevich/Re-filter-lists',
		sources: [
			{ url: 'https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs', kind: 'release', file: 'ruleset-domain-refilter_domains.srs' }
		]
	},
	{
		id: 'refilter-ip', tag: 'hp-ru-refilter-ip', group: 'ru-core', layer: 'mass',
		name: 'Re-filter — blocked networks (refilter_ipsum)',
		covers: 'RKN-blocked IP networks (ipsum build)',
		consumption: 'remote', format: 'srs', seed: true, default_on: false, heavy: false,
		license: 'MIT', repo: '1andrevich/Re-filter-lists',
		sources: [
			{ url: 'https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs', kind: 'release', file: 'ruleset-ip-refilter_ipsum.srs' }
		]
	},
	{
		id: 'rublocked', tag: 'hp-ru-rublocked', group: 'ru-core', layer: 'mass',
		name: 'RunetFreedom — ru-blocked (geosite)',
		covers: 'RKN-blocked domains aggregated from antifilter/itdog/refilter (700k+ full list is a separate heavy entry)',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geosite/geosite-ru-blocked.srs', zip_member: 'rule-set-geosite/geosite-ru-blocked.srs' }
		]
	},
	{
		id: 'rublocked-all', tag: 'hp-ru-rublocked-all', group: 'ru-core', layer: 'mass',
		name: 'RunetFreedom — antifilter download (full, 700k+)',
		covers: 'The FULL antifilter download list (700k+ domains) as srs',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: true,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geosite/geosite-antifilter-download.srs', zip_member: 'rule-set-geosite/geosite-antifilter-download.srs' }
		]
	},
	{
		id: 'antifilter-community', tag: 'hp-ru-antifilter-community', group: 'ru-core',
		name: 'Antifilter community (user-reported)',
		covers: 'Community-reported restricted sites (antifilter.download community layer)',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geosite/geosite-antifilter-download-community.srs', zip_member: 'rule-set-geosite/geosite-antifilter-download-community.srs' }
		]
	},
	{
		id: 'antifilter-domains', tag: 'hp-ru-antifilter-domains', group: 'ru-core',
		name: 'Antifilter domains.lst (raw)',
		covers: 'antifilter.download raw domain list, converted at the hub (or locally as a reserve)',
		consumption: 'local-json', format: 'source-json', convert: 'domains', seed: false, default_on: false, heavy: false,
		license: 'none', repo: null,
		sources: [
			{ url: 'https://antifilter.download/list/domains.lst', kind: 'site' },
			{ url: 'https://antifilter.community/list/domains.lst', kind: 'site' }
		]
	},
	{
		id: 'antifilter-ip', tag: 'hp-ru-antifilter-ip', group: 'ru-core',
		name: 'Antifilter ipsum.lst (raw IP)',
		covers: 'antifilter.download raw IP/subnet list (BGP AS65412), converted at the hub (or locally as a reserve)',
		consumption: 'local-json', format: 'source-json', convert: 'ips', seed: false, default_on: false, heavy: false,
		license: 'none', repo: null,
		sources: [
			{ url: 'https://antifilter.download/list/ipsum.lst', kind: 'site' },
			{ url: 'https://antifilter.download/list/subnet.lst', kind: 'site' }
		]
	},
	{
		id: 'rublocked-ip-agg', tag: 'hp-ru-rublocked-ip-agg', group: 'ru-core', layer: 'mass',
		name: 'eduard256 — aggregated blocked IPs (~146 sources)',
		covers: 'Aggregated RKN-blocked CIDR list (IPv4+IPv6, ~146 sources, manifest with sha256)',
		consumption: 'local-json', format: 'source-json', convert: 'ips', seed: false, default_on: false, heavy: false,
		license: 'MIT', repo: 'eduard256/russia-blocked-ips',
		sources: [
			{ url: 'https://raw.githubusercontent.com/eduard256/russia-blocked-ips/main/ip.txt', kind: 'raw' }
		]
	},
	{
		id: 'rublocked-full', tag: 'hp-ru-rublocked-full', group: 'ru-core', layer: 'mass', hub: false,
		name: 'RussiaFancyLists — full.lst (33 MB archive)',
		covers: 'Archive of the biggest aggregated RU-blocked domain list (antifilter+community+refilter+itdog); provenance only, not routed',
		consumption: 'archive', format: 'txt-raw', seed: false, default_on: false, heavy: true,
		license: 'MIT', repo: 'Noktomezo/RussiaFancyLists',
		sources: [
			{ url: 'https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/blacklist/domains/full.lst', kind: 'raw' }
		]
	},

	/* ── video/streaming (док 26 §A) ─────────────────────────────────────── */

	{
		id: 'youtube', tag: 'hp-ru-youtube', group: 'video',
		name: 'YouTube (domains)',
		covers: 'YouTube domains',
		consumption: 'remote', format: 'srs', seed: true, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/youtube.srs', kind: 'release', file: 'youtube.srs' },
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geosite/geosite-youtube.srs', zip_member: 'rule-set-geosite/geosite-youtube.srs' }
		]
	},
	{
		id: 'netflix', tag: 'hp-ru-netflix', group: 'video',
		name: 'Netflix (domains)',
		covers: 'Netflix domains',
		coverage: 'surrogate',
		surrogate_note: 'RKN does not block Netflix and aggregators do not track a dedicated RU list — the global service list is the honest approximation',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs', kind: 'raw' }
		]
	},
	{
		id: 'netflix-ip', tag: 'hp-ru-netflix-ip', group: 'cdn', role: 'ip', of: 'netflix',
		name: 'Netflix networks (geoip)',
		covers: 'Netflix IP networks (companion of netflix)',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geoip/geoip-netflix.srs', zip_member: 'rule-set-geoip/geoip-netflix.srs' }
		]
	},
	{
		id: 'spotify', tag: 'hp-ru-spotify', group: 'video',
		name: 'Spotify (domains)',
		covers: 'Spotify domains',
		coverage: 'surrogate',
		surrogate_note: 'No RU-specific Spotify list exists anywhere — the global service list is the honest approximation',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/spotify.srs', kind: 'raw' }
		]
	},
	{
		id: 'hdrezka', tag: 'hp-ru-hdrezka', group: 'video',
		name: 'HDRezka (domains)',
		covers: 'HDRezka mirrors',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/hdrezka.srs', kind: 'release', file: 'hdrezka.srs' }
		]
	},

	/* ── messengers (док 26 §C) ──────────────────────────────────────────── */

	{
		id: 'telegram', tag: 'hp-ru-telegram', group: 'messengers',
		name: 'Telegram (domains)',
		covers: 'Telegram web/app domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/telegram.srs', kind: 'release', file: 'telegram.srs' }
		]
	},
	{
		id: 'telegram-ip', tag: 'hp-ru-telegram-ip', group: 'messengers', role: 'ip', of: 'telegram',
		name: 'Telegram networks (geoip)',
		covers: 'Telegram DC IP networks (MTProto companions)',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/telegram.srs', kind: 'raw' }
		]
	},
	{
		id: 'discord', tag: 'hp-ru-discord', group: 'messengers',
		name: 'Discord (domains)',
		covers: 'Discord app/voice gateway domains',
		consumption: 'remote', format: 'srs', seed: true, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/discord.srs', kind: 'release', file: 'discord.srs' }
		]
	},
	{
		id: 'whatsapp', tag: 'hp-ru-whatsapp', group: 'messengers',
		name: 'WhatsApp (domains)',
		covers: 'WhatsApp domains',
		coverage: 'surrogate',
		surrogate_note: 'Voice-call IP endpoints are published nowhere — domains only; voice calls are NOT covered',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/whatsapp.srs', kind: 'raw' }
		]
	},
	{
		id: 'signal', tag: 'hp-ru-signal', group: 'messengers',
		name: 'Signal (domains)',
		covers: 'Signal messenger domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/signal.srs', kind: 'raw' }
		]
	},
	{
		id: 'twitter', tag: 'hp-ru-twitter', group: 'messengers',
		name: 'Twitter/X (domains)',
		covers: 'Twitter/X domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/twitter.srs', kind: 'release', file: 'twitter.srs' }
		]
	},

	/* ── social/locked platforms (док 26 §E) ─────────────────────────────── */

	{
		id: 'meta', tag: 'hp-ru-meta', group: 'social',
		name: 'Meta platforms (domains)',
		covers: 'Facebook/Instagram/Meta domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/meta.srs', kind: 'release', file: 'meta.srs' }
		]
	},
	{
		id: 'tiktok', tag: 'hp-ru-tiktok', group: 'social',
		name: 'TikTok (domains)',
		covers: 'TikTok domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/tiktok.srs', kind: 'release', file: 'tiktok.srs' }
		]
	},
	{
		id: 'linkedin', tag: 'hp-ru-linkedin', group: 'social',
		name: 'LinkedIn (domains)',
		covers: 'LinkedIn domains (blocked in RU since 2016)',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/linkedin.srs', kind: 'raw' }
		]
	},
	{
		id: 'rutracker', tag: 'hp-ru-rutracker', group: 'social',
		name: 'RuTracker (domains)',
		covers: 'RuTracker domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/rutracker.srs', kind: 'raw' }
		]
	},
	{
		id: 'vk', tag: 'hp-ru-vk', group: 'social',
		name: 'VK (domains)',
		covers: 'VK domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/vk.srs', kind: 'raw' }
		]
	},
	{
		id: 'ok', tag: 'hp-ru-ok', group: 'social',
		name: 'OK (domains)',
		covers: 'Odnoklassniki domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/ok.srs', kind: 'raw' }
		]
	},
	{
		id: 'mailru', tag: 'hp-ru-mailru', group: 'social',
		name: 'Mail.ru (domains)',
		covers: 'Mail.ru group domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/mailru.srs', kind: 'raw' }
		]
	},
	{
		id: 'dzen', tag: 'hp-ru-dzen', group: 'social',
		name: 'Dzen (domains)',
		covers: 'Dzen domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/dzen.srs', kind: 'raw' }
		]
	},

	/* ── AI services (док 26 §D) ─────────────────────────────────────────── */

	{
		id: 'openai', tag: 'hp-ru-openai', group: 'ai',
		name: 'OpenAI (domains)',
		covers: 'OpenAI/ChatGPT domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs', kind: 'raw' }
		]
	},
	{
		id: 'anthropic', tag: 'hp-ru-anthropic', group: 'ai',
		name: 'Anthropic/Claude (domains)',
		covers: 'Anthropic/Claude domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/anthropic.srs', kind: 'raw' },
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/anthropic.srs', kind: 'release', file: 'anthropic.srs' }
		]
	},
	{
		id: 'gemini', tag: 'hp-ru-gemini', group: 'ai',
		name: 'Google Gemini (domains)',
		covers: 'Gemini/Google AI Studio domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google-gemini.srs', kind: 'raw' }
		]
	},
	{
		id: 'deepseek', tag: 'hp-ru-deepseek', group: 'ai',
		name: 'DeepSeek (domains)',
		covers: 'DeepSeek domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/deepseek.srs', kind: 'raw' }
		]
	},
	{
		id: 'perplexity', tag: 'hp-ru-perplexity', group: 'ai',
		name: 'Perplexity (domains)',
		covers: 'Perplexity domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/perplexity.srs', kind: 'raw' }
		]
	},
	{
		id: 'huggingface', tag: 'hp-ru-huggingface', group: 'ai',
		name: 'Hugging Face (domains)',
		covers: 'Hugging Face domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/huggingface.srs', kind: 'raw' }
		]
	},
	{
		id: 'ai-chat', tag: 'hp-ru-ai-chat', group: 'ai',
		name: 'AI chatbots (aggregated, !cn)',
		covers: 'Aggregate AI-chat category (OpenAI/Anthropic/Gemini/… non-CN)',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-chat-!cn.srs', kind: 'raw' }
		]
	},
	{
		id: 'ai-ru', tag: 'hp-ru-ai-ru', group: 'ai',
		name: 'AI services RU-relevant (RunetFreedom category)',
		covers: 'AI services relevant for RU users (community category)',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geosite/geosite-category-ai-ru.srs', zip_member: 'rule-set-geosite/geosite-category-ai-ru.srs' }
		]
	},

	/* ── games (док 26 §B) ───────────────────────────────────────────────── */

	{
		id: 'valve', tag: 'hp-ru-valve', group: 'games',
		name: 'Valve/Steam gaming networks',
		covers: 'Steam/Valve game server networks (IP)',
		consumption: 'remote', format: 'srs', seed: true, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/valve.srs', kind: 'release', file: 'valve.srs' }
		]
	},
	{
		id: 'steam', tag: 'hp-ru-steam', group: 'games',
		name: 'Steam (domains)',
		covers: 'Steam store/client domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/steam.srs', kind: 'raw' }
		]
	},
	{
		id: 'epicgames', tag: 'hp-ru-epicgames', group: 'games',
		name: 'Epic Games',
		covers: 'Epic Games domains/networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/epicgames.srs', kind: 'release', file: 'epicgames.srs' }
		]
	},
	{
		id: 'roblox', tag: 'hp-ru-roblox', group: 'games',
		name: 'Roblox (domains)',
		covers: 'Roblox domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/roblox.srs', kind: 'release', file: 'roblox.srs' }
		]
	},
	{
		id: 'roblox-ip', tag: 'hp-ru-roblox-ip', group: 'games', role: 'ip', of: 'roblox',
		name: 'Roblox networks (geoip)',
		covers: 'Roblox IP networks (companion of roblox)',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/roblox.srs', kind: 'release', file: 'roblox.srs' }
		]
	},
	{
		id: 'riot', tag: 'hp-ru-riot', group: 'games',
		name: 'Riot Games',
		covers: 'Riot Games networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/riot.srs', kind: 'release', file: 'riot.srs' }
		]
	},
	{
		id: 'sony', tag: 'hp-ru-sony', group: 'games',
		name: 'Sony/PlayStation',
		covers: 'PlayStation networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/sony.srs', kind: 'release', file: 'sony.srs' }
		]
	},
	{
		id: 'electronicarts', tag: 'hp-ru-electronicarts', group: 'games',
		name: 'Electronic Arts',
		covers: 'EA networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/electronicarts.srs', kind: 'release', file: 'electronicarts.srs' }
		]
	},
	{
		id: 'ubisoft', tag: 'hp-ru-ubisoft', group: 'games',
		name: 'Ubisoft',
		covers: 'Ubisoft networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/ubisoft.srs', kind: 'release', file: 'ubisoft.srs' }
		]
	},
	{
		id: 'blizzard', tag: 'hp-ru-blizzard', group: 'games',
		name: 'Blizzard',
		covers: 'Blizzard networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/blizzard.srs', kind: 'release', file: 'blizzard.srs' }
		]
	},
	{
		id: 'nintendo', tag: 'hp-ru-nintendo', group: 'games',
		name: 'Nintendo',
		covers: 'Nintendo networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/nintendo.srs', kind: 'release', file: 'nintendo.srs' }
		]
	},
	{
		id: 'wargaming', tag: 'hp-ru-wargaming', group: 'games',
		name: 'Wargaming',
		covers: 'Wargaming networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/wargaming.srs', kind: 'release', file: 'wargaming.srs' }
		]
	},
	{
		id: 'xbox', tag: 'hp-ru-xbox', group: 'games',
		name: 'Xbox',
		covers: 'Xbox networks',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/xbox.srs', kind: 'release', file: 'xbox.srs' }
		]
	},

	/* ── CDN/anycast layers (док 26 §G) — ОТДЕЛЬНО от доменных ───────────── */

	{
		id: 'cloudflare', tag: 'hp-ru-cloudflare', group: 'cdn',
		name: 'Cloudflare (domains)',
		covers: 'Cloudflare-owned domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/cloudflare.srs', kind: 'release', file: 'cloudflare.srs' }
		]
	},
	{
		id: 'cloudflare-ip', tag: 'hp-ru-cloudflare-ip', group: 'cdn', role: 'ip', of: 'cloudflare',
		name: 'Cloudflare networks (geoip)',
		covers: 'Cloudflare anycast ranges — captures many legitimate sites behind CF; keep OFF unless needed',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geoip/geoip-cloudflare.srs', zip_member: 'rule-set-geoip/geoip-cloudflare.srs' }
		]
	},
	{
		id: 'cloudfront', tag: 'hp-ru-cloudfront', group: 'cdn',
		name: 'CloudFront (domains)',
		covers: 'AWS CloudFront domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/cloudfront.srs', kind: 'release', file: 'cloudfront.srs' }
		]
	},
	{
		id: 'cloudfront-ip', tag: 'hp-ru-cloudfront-ip', group: 'cdn', role: 'ip', of: 'cloudfront',
		name: 'CloudFront networks (geoip)',
		covers: 'AWS CloudFront ranges',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geoip/geoip-cloudfront.srs', zip_member: 'rule-set-geoip/geoip-cloudfront.srs' }
		]
	},
	{
		id: 'fastly-ip', tag: 'hp-ru-fastly-ip', group: 'cdn', role: 'ip',
		name: 'Fastly networks (geoip)',
		covers: 'Fastly anycast ranges',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geoip/geoip-fastly.srs', zip_member: 'rule-set-geoip/geoip-fastly.srs' }
		]
	},
	{
		id: 'ddos-guard-ip', tag: 'hp-ru-ddos-guard-ip', group: 'cdn', role: 'ip',
		name: 'DDoS-Guard networks (geoip)',
		covers: 'DDoS-Guard ranges',
		consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geoip/geoip-ddos-guard.srs', zip_member: 'rule-set-geoip/geoip-ddos-guard.srs' }
		]
	},
	{
		id: 'digitalocean', tag: 'hp-ru-digitalocean', group: 'cdn',
		name: 'DigitalOcean (domains)',
		covers: 'DigitalOcean domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/digitalocean.srs', kind: 'release', file: 'digitalocean.srs' }
		]
	},
	{
		id: 'hetzner', tag: 'hp-ru-hetzner', group: 'cdn',
		name: 'Hetzner',
		covers: 'Hetzner domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/hetzner.srs', kind: 'release', file: 'hetzner.srs' }
		]
	},
	{
		id: 'ovh', tag: 'hp-ru-ovh', group: 'cdn',
		name: 'OVH',
		covers: 'OVH domains',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/ovh.srs', kind: 'release', file: 'ovh.srs' }
		]
	},
	{
		id: 'hodca', tag: 'hp-ru-hodca', group: 'cdn',
		name: 'H.O.D.C.A (Hetzner/OVH/DO/CF/AWS)',
		covers: 'Hosting providers commonly hosting blocked services',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [
			{ url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/hodca.srs', kind: 'release', file: 'hodca.srs' }
		]
	},

	/* ── misc utility categories (existing whitelist sources) ────────────── */

	{ id: 'block', tag: 'hp-ru-block', group: 'misc', name: 'Ad/track block layer (itdog block)',
		covers: 'Ad/tracking domains', consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/block.srs', kind: 'release', file: 'block.srs' } ] },
	{ id: 'porn', tag: 'hp-ru-porn', group: 'misc', name: 'Porn (itdog)',
		covers: 'Adult-content domains', consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/porn.srs', kind: 'release', file: 'porn.srs' } ] },
	{ id: 'news', tag: 'hp-ru-news', group: 'misc', name: 'News (itdog)',
		covers: 'Blocked-in-RU media domains', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/news.srs', kind: 'release', file: 'news.srs' } ] },
	{ id: 'anime', tag: 'hp-ru-anime', group: 'misc', name: 'Anime (itdog)',
		covers: 'Anime streaming domains', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/anime.srs', kind: 'release', file: 'anime.srs' } ] },
	{ id: 'geoblock', tag: 'hp-ru-geoblock', group: 'misc', name: 'Geoblock (itdog)',
		covers: 'Services that geoblock RU users', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/geoblock.srs', kind: 'release', file: 'geoblock.srs' } ] },
	{ id: 'google-meet', tag: 'hp-ru-google-meet', group: 'misc', name: 'Google Meet',
		covers: 'Google Meet domains+networks', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/google_meet.srs', kind: 'release', file: 'google_meet.srs' } ] },
	{ id: 'google_play', tag: 'hp-ru-google_play', group: 'misc', name: 'Google Play',
		covers: 'Google Play domains', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/google_play.srs', kind: 'release', file: 'google_play.srs' } ] },
	{ id: 'russia-inside', tag: 'hp-ru-russia-inside', group: 'reverse', name: 'Inside-RU services (itdog)',
		covers: 'Domains working ONLY from RU (reverse-routing companion)', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/russia_inside.srs', kind: 'release', file: 'russia_inside.srs' } ] },
	{ id: 'russia-outside', tag: 'hp-ru-russia-outside', group: 'reverse', name: 'Outside-RU routing base (itdog)',
		covers: 'Base for routing decisions relative to RU', consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/russia_outside.srs', kind: 'release', file: 'russia_outside.srs' } ] },
	{ id: 'ukraine-inside', tag: 'hp-ru-ukraine-inside', group: 'reverse', name: 'Inside-UA services (itdog)',
		covers: 'Domains working only from UA', consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains',
		sources: [ { url: 'https://github.com/itdoginfo/allow-domains/releases/latest/download/ukraine_inside.srs', kind: 'release', file: 'ukraine_inside.srs' } ] },
	{ id: 'google_ai', tag: 'hp-ru-google_ai', group: 'ai', name: 'Google AI (shipped inline list)',
		covers: 'Google AI endpoints — shipped inline (lesson 355), conveyor skips it',
		consumption: 'inline', format: 'inline', seed: false, default_on: true, heavy: false,
		license: 'none', repo: 'itdoginfo/allow-domains', sources: [] },
	{ id: 'twitch', tag: 'hp-ru-twitch', group: 'video', name: 'Twitch (domains)',
		covers: 'Twitch domains',
		coverage: 'surrogate',
		surrogate_note: 'No dedicated Twitch RU list exists — global service list + measured nfqws2 strategy; stream edges ride the IP twin',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'MetaCubeX/meta-rules-dat',
		sources: [
			{ url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/twitch.srs', kind: 'raw' },
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/twitch.srs', kind: 'release', file: 'twitch.srs' }
		] },
	{ id: 'twitch-ip', tag: 'hp-ru-twitch-ip', group: 'cdn', role: 'ip', of: 'twitch',
		name: 'Twitch stream-edge networks (geoip)',
		covers: 'Twitch stream edge IP networks (companion of twitch)',
		consumption: 'remote', format: 'srs', seed: false, default_on: true, heavy: false,
		license: 'unknown', repo: 'Greeg0ry/b4geoip-forkop',
		sources: [
			{ url: 'https://github.com/Greeg0ry/b4geoip-forkop/releases/latest/download/twitch.srs', kind: 'release', file: 'twitch.srs' }
		] },
	{ id: 'win-spy', tag: 'hp-ru-win-spy', group: 'misc', name: 'Windows telemetry/spy (RunetFreedom)',
		covers: 'Microsoft telemetry domains', consumption: 'remote', format: 'srs', seed: false, default_on: false, heavy: false,
		license: 'GPL-3.0', repo: 'runetfreedom/russia-v2ray-rules-dat',
		sources: [
			{ url: 'https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/sing-box.zip', kind: 'release-zip', file: 'rule-set-geosite/geosite-win-spy.srs', zip_member: 'rule-set-geosite/geosite-win-spy.srs' }
		] }
];

/* Attribution lines (license honesty, док 26 §4): repos publishing data
 * WITHOUT a license file are consumed over the network and attributed —
 * nothing is embedded into the distribution package. The UI shows these
 * strings verbatim in the conveyor card and in the strategy import block. */
export const ATTRIBUTION = {
	'itdoginfo/allow-domains': 'itdoginfo/allow-domains — no license file; data consumed over the network with attribution, not embedded.',
	'runetfreedom/russia-v2ray-rules-dat': 'runetfreedom/russia-v2ray-rules-dat — GPL-3.0.',
	'1andrevich/Re-filter-lists': '1andrevich/Re-filter-lists — MIT.',
	'MetaCubeX/meta-rules-dat': 'MetaCubeX/meta-rules-dat — built on the MIT-licensed v2fly/domain-list-community data; repack license unstated, consumed over the network with attribution.',
	'Greeg0ry/b4geoip-forkop': 'Greeg0ry/b4geoip-forkop — license unstated; consumed over the network with attribution.',
	'eduard256/russia-blocked-ips': 'eduard256/russia-blocked-ips — MIT.',
	'Noktomezo/RussiaFancyLists': 'Noktomezo/RussiaFancyLists — MIT.',
	'antifilter.download': 'antifilter.download / antifilter.community — no license; data consumed over the network with attribution.',
	'zemidala/nfqws2-strategies': 'zemidala/nfqws2-strategies — no license; data consumed over the network with attribution, not embedded.'
};

/* ── accessors (declared AFTER the data — no hoisting reliance) ──────────── */

/* The lists HUB: CI-validated aggregates published by ezdizzy/ravnex-lists
 * (the precision-first delivery transport; upstream sources[] stay as the
 * fallback ladder). Hub release assets carry GitHub-API sha256 digests, so
 * the per-asset gate applies to hub files too. Plain const — ucode on this
 * build mis-compiles a MIX of export-const + export-function in one module
 * (isolated live: each form alone compiles, both together fail at the next
 * export); importers get the hub via hub_source_for()/catalog_url(). */
const HUB_REPO = 'ezdizzy/ravnex-lists';

function hub_ext(e) {
	return (e.format === 'srs') ? '.srs' : '.json';
}

/* The hub source record for an entry, or null when the hub does not publish
 * the category (inline lists, heavy archives marked hub:false). */
export function hub_source_for(e) {
	if (!e || e.consumption === 'inline' || e.consumption === 'archive' || e.hub === false)
		return null;
	const f = 'cat-' + e.id + hub_ext(e);
	return {
		url: 'https://github.com/' + HUB_REPO + '/releases/latest/download/' + f,
		kind: 'release', repo: HUB_REPO, file: f, hub: true
	};
};

export function catalog_find(id) {
	for (let e in CATALOG)
		if (e.id === id)
			return e;
	return null;
};

/* Primary URL of a category (the generator's remote rule-set URL):
 * the hub file when the hub delivers it, else the upstream primary. */
export function catalog_url(id) {
	const e = catalog_find(id);
	if (!e)
		return null;
	const hs = hub_source_for(e);
	if (hs)
		return hs.url;
	if (!length(e.sources) || !length(e.sources[0].url))
		return null;
	return e.sources[0].url;
};

/* IP-twin URL of a category (null when the category has no IP companion). */
export function catalog_ip_url(id) {
	for (let e in CATALOG) {
		if (e.role === 'ip' && e.of === id) {
			const hs = hub_source_for(e);
			if (hs)
				return hs.url;
			if (length(e.sources) && length(e.sources[0].url))
				return e.sources[0].url;
		}
	}
	return null;
};

/* The refilter PAIR tags (the generator declares both rule-sets for the
 * 'refilter' source). Returns [domain_tag, ip_tag] or the classic defaults. */
export function catalog_pair(prefix) {
	const d = catalog_find(prefix + '-domain');
	const i = catalog_find(prefix + '-ip');
	return [ d ? d.tag : 'hp-ru-' + prefix + '-domain',
		i ? i.tag : 'hp-ru-' + prefix + '-ip' ];
};

/* Routable ids for the rules-page whitelist (remote/local-json, no roles).
 * 'refilter' is the PAIR alias the rules page has always used (the generator
 * expands it to the refilter-domain/refilter-ip rule-sets). */
export function catalog_routable() {
	const out = {};
	for (let e in CATALOG) {
		if (e.role === 'ip')
			continue;
		if (e.consumption === 'remote' || e.consumption === 'local-json')
			out[e.id] = true;
	}
	out['refilter'] = true;
	return out;
};

/* Groups for the conveyor card, in display order. */
export const GROUPS = [
	'ru-core', 'video', 'messengers', 'social', 'ai', 'games', 'cdn', 'misc', 'reverse'
];
