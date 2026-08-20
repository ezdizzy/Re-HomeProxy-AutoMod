[**Русский 🇷🇺**](README_ru.md) / [**English**](README.md)

<p align="center">
  <a href="https://t.me/one_andrevich"><img src="https://img.shields.io/badge/Telegram-Join-2CA5E0?style=flat-square&logo=telegram&logoColor=white" alt="Telegram"></a>
  <a href="https://ko-fi.com/D1D11SQNQD"><img src="https://img.shields.io/badge/Ko--fi-Support-FF5E5B?style=flat-square&logo=ko-fi&logoColor=white" alt="Ko-fi"></a>
  <a href="https://nowpayments.io/donation?api_key=decbeb76-30f8-4c6d-ba40-2d2dec7fd888"><img src="https://img.shields.io/badge/Crypto-Donate-2EBE74?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto donate"></a>
</p>

# Re-HomeProxy AutoMod

Современная многоядерная прокси-платформа на основе [hiddify-core](https://github.com/hiddify/hiddify-core) и
[sing-box-extended](https://github.com/shtorm-7/sing-box-extended).
Форк [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy).

> **Re-HomeProxy AutoMod** — мод Re-HomeProxy от **@ezdizzy**. Этот мод дополняет оригинальное приложение Re-HomeProxy
> доработками AutoMod (см. раздел *Доработки AutoMod* ниже) — прежде всего вкладкой **«Автоматизация»** и
> **самообновлением приложения из веб-интерфейса**. Ядра прокси, ByeDPI и Zapret берутся из собственных релизов вышестоящих
> проектов; здесь собираются только LuCI-приложение и его русская локализация (репозиторий `ezdizzy/re-homeproxy`).

## Обзор

Re-HomeProxy — многофункциональная система управления прокси, новый взгляд на HomeProxy от ImmortalWrt. Работает на выбор
ядра ([hiddify-core](https://github.com/hiddify/hiddify-core) или [sing-box-extended](https://github.com/shtorm-7/sing-box-extended)),
включает встроенный обход DPI на основе [Zapret2](https://github.com/bol-van/zapret2) и [ByeDPI](https://github.com/hufrea/byedpi)
для разблокировки сайтов без VPN, готовые правила маршрутизации для России и установщик ядра в один клик — всё из
веб-интерфейса LuCI.

## Доработки AutoMod

Этот мод добавляет поверх оригинального приложения Re-HomeProxy:

- **Вкладка «Автоматизация»** — автоматическое обнаружение заблокированных сайтов. Фоновый монитор проверяет узлы и
  напрямую, и через прокси; домен, не открывающийся напрямую, но работающий через прокси, запоминается (базовый домен +
  обученные IP) и пускается через прокси/ByeDPI/Zapret. Полностью совместимо с ByeDPI и Zapret — обученные сайты идут тем
  же путём, что выбрал пользователь. Исправлена ошибка отображения `0/0/0` (метод статуса теперь показывает реальные
  счётчики заблокировано / напрямую / неизвестно).
- **Исправление Tun TCP/UDP** — корректная доставка `tun_mark`-потоков в tun-устройство с защитой от зацикливания, так
  что маршрутизация в режиме Tun работает правильно.
- **Самообновление приложения** — на вкладке **«Ядро и службы»** можно проверить наличие новой версии и обновить
  LuCI-приложение (и русскую локализацию) на месте, без SSH-консоли. См. раздел *Обновление приложения*.
- **Форк по умолчанию** — `install.sh` ставит LuCI-приложение и русскую локаль из `ezdizzy/re-homeproxy` по умолчанию
  (ядра / ByeDPI / Zapret по-прежнему берутся из апстрима `1andrevich/*`).
- Полный перевод на русский (ru) всех вкладок, включая «Автоматизацию» и строки DNS-failover.

> ⚠️ Это экспериментальный мод. Устанавливая его, вы понимаете, что некоторые функции могут работать не так, как
> ожидается, — используйте на свой страх и риск.

## Ключевые возможности

- **Многоядерный движок** — работа на **hiddify-core** или **sing-box-extended** на ваш выбор. Встроенная страница
  **«Ядро и службы»** сама установит и обновит ядро и автоматически подберёт подходящую сборку под свободное место
  (включая компактную сборку для устройств с малым объёмом памяти).
- **Широкая поддержка протоколов** — Naive, Mieru, Hysteria, SOCKS, Shadowsocks, ShadowTLS, Trojan, VLESS (XHTTP), VMess,
  WireGuard, **AmneziaWG / WARP** (sing-box-extended), SSH и другие.
- **Два встроенных двига обхода DPI** — разблокировка сайтов и снятие троттлинга (например, YouTube, Discord) **без
  какой-либо VPN-подписки**:
  - **ByeDPI** ([hufrea/byedpi](https://github.com/hufrea/byedpi)) — рассинхронизирующий прокси на уровне SOCKS, 47
    готовых пресетов стратегий и **тестер стратегий** по нескольким сайтам, который показывает, какая настройка реально
    работает у вашего провайдера.
  - **Zapret 2** ([bol-van/zapret2](https://github.com/bol-van/zapret2), nfqws2) — рассинхронизация на уровне пакетов
    через NFQUEUE, искажает рукопожатие «на лету». Назначается в правилах маршрутизации (например, отправить через него
    только YouTube/Discord), с подобранными пресетами, опциональным обходом для голоса Discord и собственным тестером.
- **Автовыбор через URLTest** — автоматически направляет трафик через самый быстрый доступный узел и переключается при сбое.
- **Правила маршрутизации для России** — RU Proxy Rules в один клик (Russia Inside, Re:Filter) с готовыми списками
  доменов/IP, чтобы через прокси шли только заблокированные адреса.
- **Поддержка подписок** — импорт узлов по ссылкам подписок (sing-box JSON / Hiddify, base64 / обычные share-ссылки, а
  также JSON-конфиги Xray/V2Ray) и обновление по требованию.
- **Диагностика** — встроенная страница для проверки состояния ядра/системы, просмотра портов и формирования отчёта.
- **Автоматизация** — автообнаружение заблокированных сайтов и маршрутизация их через прокси/ByeDPI/Zapret (см.
  *Доработки AutoMod*).
- **Самообновление приложения** — обновление LuCI-приложения прямо со вкладки «Ядро и службы».
- **Современный веб-интерфейс** — чистый адаптивный интерфейс LuCI с управлением узлами, маршрутизацией ACL и NFT-правилами.

## Требования

- OpenWRT / ImmortalWrt 24.10 или выше (opkg)
- OpenWRT / ImmortalWrt 25.12 или выше (apk)

Опционально в разделе Releases доступна legacy-сборка для 23.05.

## Установка

*Рекомендуется ~40 Мб свободного места. Мало места? Сначала установите пакет LuCI, затем на вкладке **«Ядро и службы»**
(Службы → Re-HomeProxy AutoMod → Ядро и службы) установите ядро — оно само подберёт подходящую сборку для устройств с
малым объёмом памяти.*

### Быстрая установка (одной строкой)

Ставит LuCI-приложение, затем интерактивно проводит по выбору ядра прокси и опциональных ByeDPI / Zapret. Работает на APK
(25.12+), opkg (24.10) и 23.05 legacy. Выполните по SSH на роутере:

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | sh
```

При заблокированном/замедленном GitHub можно указать зеркало (важно: переменная ставится перед `sh`, а не перед `wget`):

```sh
wget -qO- https://raw.githubusercontent.com/ezdizzy/re-homeproxy/master/install.sh | GH_MIRROR=https://your.mirror sh
```

Хотите вручную? Шаги по версиям — ниже.

### OpenWRT 25.12+ (APK)

#### 1. Установка пакета Re-HomeProxy

```sh
wget -O /tmp/homeproxy-hiddify.pub https://github.com/ezdizzy/re-homeproxy/releases/latest/download/homeproxy-hiddify.pub
cp /tmp/homeproxy-hiddify.pub /etc/apk/keys/
wget -O /tmp/luci-app-re-homeproxy.apk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-app-re-homeproxy[^"]*\.apk' | head -1)"
apk add /tmp/luci-app-re-homeproxy.apk
```

После того как ключ окажется в `/etc/apk/keys/`, он будет доверенным постоянно — флаг указывать при последующих
обновлениях не нужно.

#### 2. Установка компонентов на вкладке **«Ядро и службы»**

Откройте **Службы → Re-HomeProxy AutoMod → Ядро и службы** и установите нужное — установщик сам подберёт сборку под
свободное место:

- **Ядро прокси** *(обязательно, выберите одно)* — [hiddify-core](https://github.com/hiddify/hiddify-core) (по умолчанию)
  или [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) (добавляет AmneziaWG / WARP и самый широкий набор
  протоколов).
- **ByeDPI** *(опционально)* — обход DPI на уровне SOCKS, снимает троттлинг без VPN, 47 пресетов и встроенный тестер
  стратегий.
- **Zapret 2** *(опционально)* — обход DPI на уровне пакетов (nfqws2), назначается в правилах маршрутизации, с подобранными
  пресетами и опциональным обходом для голоса Discord.
- **Re-HomeProxy AutoMod** *(само приложение)* — см. *Обновление приложения*; обновляется на месте из этой же вкладки.

#### 3. Установка языкового пакета RU

```sh
wget -O /tmp/luci-i18n-homeproxy-ru.apk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-i18n-homeproxy-ru[^"]*\.apk' | head -1)"
apk add /tmp/luci-i18n-homeproxy-ru.apk
```

---

### OpenWRT 24.10 (opkg)

#### 1. Установка пакета Re-HomeProxy

```sh
wget -O /tmp/luci-app-re-homeproxy.ipk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-app-re-homeproxy[^"]*\.ipk' | head -1)"
opkg install /tmp/luci-app-re-homeproxy.ipk
```

#### 2. Установка компонентов на вкладке **«Ядро и службы»**

Откройте **Службы → Re-HomeProxy AutoMod → Ядро и службы** и установите нужное — установщик сам подберёт сборку под
свободное место (те же опции, что в разделе APK выше).

#### 3. Установка языкового пакета RU

```sh
wget -O /tmp/luci-i18n-homeproxy-ru.ipk "$(wget -qO- 'https://api.github.com/repos/ezdizzy/re-homeproxy/releases' | grep -o 'https://github\.com/[^"]*luci-i18n-homeproxy-ru[^"]*\.ipk' | head -1)"
opkg install /tmp/luci-i18n-homeproxy-ru.ipk
```

### Ручная установка по SSH (вместо вкладки «Ядро и службы»)

Вкладка **«Ядро и службы»** предпочтительна — она сама определяет железо и подбирает подходящую сборку. Чтобы поставить
то же самое вручную по SSH, сначала определите архитектуру и формат пакетов:

```sh
. /etc/openwrt_release; ARCH="$DISTRIB_ARCH"
command -v apk >/dev/null && EXT=apk || EXT=ipk
echo "$ARCH / $EXT"
```

Пакеты hiddify-core и ByeDPI подписаны ключом `homeproxy-hiddify.pub`, который добавляется в доверенные при установке
приложения выше; если вы пропустили тот шаг — добавьте `--allow-untrusted` к `apk add`.

**Ядро прокси — выберите одно** (плюс необходимые модули ядра):

```sh
if [ "$EXT" = apk ]; then apk add kmod-nft-tproxy kmod-tun; else opkg install kmod-nft-tproxy kmod-tun; fi

# hiddify-core (по умолчанию; для компактной сборки замените 'latest/download' на 'download/upx')
wget -O /tmp/hiddify-core.$EXT "https://github.com/1andrevich/hiddify-core/releases/latest/download/hiddify-core_${ARCH}.${EXT}"
if [ "$EXT" = apk ]; then apk add /tmp/hiddify-core.apk; else opkg install --force-reinstall /tmp/hiddify-core.ipk; fi

# ...или sing-box-extended (AmneziaWG / WARP, самый широкий набор протоколов; без подписи)
URL=$(wget -qO- 'https://api.github.com/repos/shtorm-7/sing-box-extended/releases/latest' | grep -o "https://github\.com/[^\"]*${ARCH}[^\"]*\.${EXT}" | head -1)
wget -O /tmp/sing-box-extended.$EXT "$URL"
if [ "$EXT" = apk ]; then apk add --allow-untrusted /tmp/sing-box-extended.apk; else opkg install /tmp/sing-box-extended.ipk; fi
```

**ByeDPI** *(опционально)* — нужен `curl` (его использует встроенный тестер стратегий):

```sh
if [ "$EXT" = apk ]; then apk add curl; else opkg install curl; fi
URL=$(wget -qO- 'https://api.github.com/repos/1andrevich/ByeDPI-OpenWrt/releases/latest' | grep -o "https://github\.com/[^\"]*byedpi_[^\"]*${ARCH}\.${EXT}" | head -1)
wget -O /tmp/byedpi.$EXT "$URL"
if [ "$EXT" = apk ]; then apk add /tmp/byedpi.apk; else opkg install /tmp/byedpi.ipk; fi
```

**Zapret 2** *(опционально)* — нужен модуль ядра NFQUEUE:

```sh
if [ "$EXT" = apk ]; then apk add kmod-nft-queue; else opkg install kmod-nft-queue; fi
[ "$EXT" = apk ] && wget -O /etc/apk/keys/zapret2-1andrevich.pub "https://github.com/1andrevich/zapret2-openwrt/releases/latest/download/zapret2-1andrevich.pub"
wget -O /tmp/zapret2.$EXT "https://github.com/1andrevich/zapret2-openwrt/releases/latest/download/zapret2_${ARCH}.${EXT}"
if [ "$EXT" = apk ]; then apk add /tmp/zapret2.apk; else opkg install /tmp/zapret2.ipk; fi
```

### 4. Запуск службы

```sh
/etc/init.d/homeproxy start
```

Служба запускается автоматически при загрузке системы. Логи доступны в разделе **Службы → Re-HomeProxy AutoMod →
Ядро и службы**.

## Обновление приложения (самообновление AutoMod)

Для обновления Re-HomeProxy AutoMod **не нужна** SSH-консоль:

1. Откройте **Службы → Re-HomeProxy AutoMod → Ядро и службы**.
2. В карточке **«Application» (Приложение)** нажмите **Check update** (Проверить обновление). Приложение сравнит
   установленную версию (показывается как `Re-HomeProxy AutoMod vX.Y.Z`) с последним релизом `ezdizzy/re-homeproxy` на
   GitHub.
3. Если обновление доступно, нажмите **Update** (Обновить). Приложение скачает новый пакет `luci-app-re-homeproxy` (и
   русскую локализацию) и установит на месте; rpcd перезапустится автоматически и страница перезагрузится.

> Само приложение берёт свои сборки из `ezdizzy/re-homeproxy`. Ядра / ByeDPI / Zapret по-прежнему обновляются через свои
> карточки на той же вкладке (они приходят из апстрима). GitHub-токен (задаётся в **Ядро и службы → GitHub token**)
> повышает лимит обращений к GitHub API, который используется при проверке обновления.

## Версии и релизы

- **Схема версий:** семантическая `X.Y.Z` (например, `1.0.0`).

## Документация

Полные руководства — в **[вики](../../wiki/Home)**:

- **[Первая настройка](../../wiki/Getting-Started-ru)** — от свежей установки до рабочего соединения, по шагам
- **[Управление ядром](../../wiki/Core-Management-ru)** — hiddify-core или sing-box-extended, умный установщик, память и компактная сборка
- **[Поддерживаемые протоколы](../../wiki/Supported-Protocols-ru)** — все протоколы, транспорты и нужные им build-теги
- **[Подписки и импорт узлов](../../wiki/Subscriptions-ru)** — share-ссылки, .conf, Amnezia `vpn://` (AmneziaWG/Xray), подписки, base64
- **[Маршрутизация и контроль доступа](../../wiki/Routing-and-Access-Control-ru)** — режимы маршрутизации, RU Proxy Rules, пер-девайс контроль доступа
- **[Настройки сервера](../../wiki/Server-Settings-ru)** — роутер как прокси-сервер (inbound-ы, типы, TLS/ACME)
- **[DNS и диагностика](../../wiki/DNS-and-Diagnostics-ru)** — чистый и защищённый DNS, утечки IPv6 и страница диагностики
- **[ByeDPI](../../wiki/ByeDPI-ru)** — обход DPI на уровне SOCKS, пресеты стратегий и тестер
- **[Zapret](../../wiki/Zapret-ru)** — обход DPI на уровне пакетов (nfqws2), пресеты, голос Discord и тестер
- **[Пользовательская маршрутизация](../../wiki/Custom-Routing-ru)** — узлы и правила маршрутизации в UI (матч по домену/IP/порту/протоколу/процессу)
- **[Пользовательский JSON конфиг](../../wiki/Custom-JSON-Config-ru)** — режим маршрутизации с «сырым» конфигом hiddify-core
- **[Автоматизация](../../wiki/Automation-Status-ru)** — вкладка AutoMod «Автоматизация» (состояния A–D, риски, TODO)
- **[Устранение неполадок](../../wiki/Troubleshooting-ru)** — типичные ошибки и их решение

## Благодарности и используемые проекты

Re-HomeProxy опирается на работу множества вышестоящих проектов. Приложение LuCI распространяется под GPL; ядра и движки
обхода DPI скачиваются при установке из их собственных релизов и остаются под своими лицензиями.

**Основа и ядра**
- [ImmortalWrt HomeProxy](https://github.com/immortalwrt/homeproxy) — исходное приложение LuCI, форком которого является проект
- [hiddify-core](https://github.com/hiddify/hiddify-core) — ядро прокси по умолчанию (форк sing-box от команды Hiddify)
- [sing-box-extended](https://github.com/shtorm-7/sing-box-extended) — альтернативное ядро с дополнительными build-тегами (AmneziaWG/WARP, самый широкий набор протоколов)
- [sing-box](https://sing-box.sagernet.org) — вышестоящий движок, на котором основаны оба ядра

**Движки обхода DPI**
- [hufrea/byedpi](https://github.com/hufrea/byedpi) — движок рассинхронизации ByeDPI (`ciadpi`); пакеты для OpenWrt — [1andrevich/ByeDPI-OpenWrt](https://github.com/1andrevich/ByeDPI-OpenWrt)
- [bol-van/zapret2](https://github.com/bol-van/zapret2) — движок рассинхронизации пакетов Zapret / nfqws2 / blockcheck2; пакеты для OpenWrt — [1andrevich/zapret2-openwrt](https://github.com/1andrevich/zapret2-openwrt); часть пресетов адаптирована из [flowseal/zapret-discord-youtube](https://github.com/flowseal/zapret-discord-youtube) (MIT)

**Протоколы** — реализованы ядрами выше (см. [Поддерживаемые протоколы](../../wiki/Supported-Protocols-ru)):

Naive, Mieru, Hysteria/Hysteria2, TUIC, SOCKS, Shadowsocks/Shadowsocks 2022, ShadowTLS, AnyTLS, Trojan, VLESS (Reality, XHTTP), VMess, WireGuard, AmneziaWG/WARP, SSH.

**Списки маршрутизации**
- [Re:Filter](https://github.com/1andrevich/re-filter) — список доменов + IP по реестру РКН
- [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) — «Russia Inside» и сервисные списки (YouTube, Telegram, Discord, Meta и др.)
- [itdoginfo](https://github.com/itdoginfo) — HODCA и другие подобранные списки от itdoginfo

Все товарные знаки и названия сервисов принадлежат их владельцам и упоминаются номинативно — для обозначения трафика, к которому относится правило или список.
