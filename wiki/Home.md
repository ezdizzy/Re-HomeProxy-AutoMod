# Ravnex Wiki

**Own the Route.**

Многоядерная прокси-платформа для OpenWrt: VPN-подписки, обход DPI без VPN, автоматизация,
мониторинг и диагностика — всё из веб-интерфейса LuCI, всё локально на роутере.

| | |
|---|---|
| ![Overview](https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/docs/img/overview.png) | ![Routing Master](https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/docs/img/wizard_dpi.png) |
| ![Automation engine](https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/docs/img/automation_engine.png) | ![Advanced rules](https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/docs/img/wizard_advanced.png) |

---

## 🇬🇧 English

| Page | Description |
|------|-------------|
| [Getting Started](Getting-Started-en) | From a fresh install to a working connection, step by step |
| [Installation & Updates](Installation-and-Updates-en) | The one-command installer, mirrors, manual packages, self-update and the signed feed |
| [Overview](Overview-en) | The home screen: subsystem cards, local SVG charts, quick actions |
| [Core Management](Core-Management-en) | Choosing hiddify-core vs sing-box-extended, the smart installer, rule-sets safety net |
| [Supported Protocols](Supported-Protocols-en) | All supported proxy protocols, build requirements, transport options |
| [Subscriptions & Node Import](Subscriptions-en) | Share links, .conf, Amnezia vpn:// (AmneziaWG/Xray), subscriptions, base64 |
| [Routing Master](Routing-Master-en) | The Blocking bypass hub: provider diagnostics, Strategy Lab, auto-pick, composition; Service rules — per-service exits with live checks |
| [Routing & Access Control](Routing-and-Access-Control-en) | Routing modes, the exit engine (URLTest / Hot Swap), UDP exit, OAuth resilience |
| [Hot Swap & Reliability](Hot-Swap-and-Reliability-en) | Hot standby, anti-flap, the RU-internet invariant, last-known-good, watchdogs |
| [Monitoring & Connections](Monitoring-and-Connections-en) | The node dashboard, live connections, daemon resources and the Health center |
| [Access Control](Access-Control-en) | Per-device proxy modes, site rules, schedules, Wi-Fi — and the same from Telegram |
| [Phone Control (Telegram)](Telegram-en) | The bot: commands, subscriptions, arbitrary commands, push notifications |
| [Auto-bypass](Automation-Status-en) | The self-learning engine: sources, block-type verdicts, RU protection; the DPI autopilot |
| [DNS Settings](DNS-Settings-en) | Server pools, reserve DNS and MultiDNS with a live quality monitor |
| [DNS & Diagnostics](DNS-and-Diagnostics-en) | Clean vs secure DNS, IPv6 leaks, the live checks and the support report |
| [ByeDPI](ByeDPI-en) | SOCKS-level DPI-bypass — un-throttle sites without a VPN, 47 presets and the tester |
| [Zapret](Zapret-en) | Packet-level (nfqws2) DPI-bypass — strategies, the Lab, multi-strategies, TSPU |
| [Advanced Rules (Expert)](Custom-Routing-en) | Routing nodes and raw sing-box rules with the highest priority |
| [Custom JSON Config](Custom-JSON-Config-en) | Removed in v3 — what to use instead |
| [Server Mode](Server-Settings-en) | Run the router as a proxy server — inbounds, types, TLS/ACME |
| [Troubleshooting](Troubleshooting-en) | Common errors and how to fix them |

---

## 🇷🇺 Русский

| Страница | Описание |
|----------|----------|
| [Первая настройка](Getting-Started-ru) | От свежей установки до рабочего соединения, по шагам |
| [Установка и обновление](Installation-and-Updates-ru) | Установщик одной командой, зеркала, ручные пакеты, самообновление и подписанный фид |
| [Обзор](Overview-ru) | Главный экран: карточки подсистем, локальные SVG-графики, быстрые действия |
| [Управление ядром](Core-Management-ru) | Выбор hiddify-core или sing-box-extended, умный установщик, страховка rule-set'ов |
| [Поддерживаемые протоколы](Supported-Protocols-ru) | Все поддерживаемые протоколы, требования к сборке, варианты транспорта |
| [Подписки и импорт узлов](Subscriptions-ru) | Share-ссылки, .conf, Amnezia vpn:// (AmneziaWG/Xray), подписки, base64 |
| [Мастер маршрутизации](Routing-Master-ru) | «Обход блокировок»: диагностика провайдера, Стратегия-лаборатория, автоподбор, композиция; «Правила для сервисов» — выходы с живой проверкой |
| [Маршрутизация и контроль доступа](Routing-and-Access-Control-ru) | Режимы маршрутизации, выход-движок (URLTest / Hot Swap), UDP-выход, OAuth-устойчивость |
| [Hot Swap и надёжность](Hot-Swap-and-Reliability-ru) | Горячий резерв, анти-флап, инвариант RU-интернета, last-known-good, сторожа |
| [Мониторинг и соединения](Monitoring-and-Connections-ru) | Дашборд узлов, живые соединения, ресурсы демонов и Центр здоровья |
| [Контроль доступа](Access-Control-ru) | Режимы прокси на карточке устройства, правила сайтов, расписания, Wi-Fi — и то же из Telegram |
| [Управление с телефона](Telegram-ru) | Бот: команды, подписки, произвольные команды, пуш-уведомления |
| [Автообход блокировок](Automation-Status-ru) | Движок самообучения: источники, вердикты типов блокировки, RU-защита; автопилот DPI |
| [Настройки DNS](DNS-Settings-ru) | Пулы серверов, резервный DNS и MultiDNS с живым монитором качества |
| [DNS и диагностика](DNS-and-Diagnostics-ru) | Чистый и защищённый DNS, утечки IPv6, живые проверки и отчёт для поддержки |
| [ByeDPI](ByeDPI-ru) | Обход DPI на уровне SOCKS — разблокировка без VPN, 47 пресетов и тестер |
| [Zapret](Zapret-ru) | Обход DPI на уровне пакетов (nfqws2) — стратегии, Лаборатория, мультистратегии, ТСПУ |
| [Расширенные правила (эксперт)](Custom-Routing-ru) | Узлы маршрутизации и сырые sing-box-правила с наивысшим приоритетом |
| [Пользовательский JSON конфиг](Custom-JSON-Config-ru) | Удалён в v3 — что использовать вместо него |
| [Режим сервера](Server-Settings-ru) | Роутер как прокси-сервер — inbound-ы, типы, TLS/ACME |
| [Устранение неполадок](Troubleshooting-ru) | Типичные ошибки и способы их устранения |
