# Состояние проекта: автоматическое обнаружение заблокированного (Automation)

> Цель документа — зафиксировать, что уже сделано по списку A–D, что НЕ протестировано на
> устройстве и что осталось сделать, чтобы можно было продолжить в другом чате.

Движок: `root/etc/homeproxy/scripts/automation.uc` (запускается как отдельный procd-инстанс
из `root/etc/init.d/homeproxy` при `automation.enabled=1`). Управление из Lua-UI:
`htdocs/luci-static/resources/view/homeproxy/automation.js`; RPC-методы в
`root/usr/share/rpcd/ucode/luci.homeproxy` (`automation_status`, `automation_list_read/write`,
`automation_clear`, `automation_test_now`, `diag_service_restart`). Генерация конфига ядра:
`root/etc/homeproxy/scripts/generate_client.uc`.

Общий принцип классификации (не менялся): кандидат щупается ДВАЖДЫ — напрямую
(`auto-direct-in` → `direct-out`) и через основной путь (`auto-proxy-in` → `main-out`, который
уже является `byedpi-out`/`zapret-out`). В `auto_proxy_list.txt`/`auto_proxy_ip.txt` попадает
только то, что не работает напрямую, но работает через прокси. Это совместимо с ByeDPI/Zapret.

---

## A. Режим «DNS-гонка» (детект на этапе резолва) + выбор рабочего DNS

**Сделано:**
- Новый режим обнаружения `dns`: демон включает лог dnsmasq (`logqueries=1` +
  `logfacility=/var/log/dnsmasq-q.log`, `enable_dns_log()`), затем читает файл и вытягивает
  домен регуляркой `query\[[Aq]+\]\s+<domain>\s+from`. Домен захватывается ДО установления
  соединения — окно «сайт починится при повторном заходе» сокращается до одной попытки.
- Отслеживается смещение в логе (`dns_log_offset` в `automation_state.json`), чтобы не
  пересканировать с начала после перезапуска; при ротации лога смещение сбрасывается.
- UI (`automation.js`): режимы `dns`, `both` (Clash+DNS), `all` (Clash+DNS+conntrack).
- Выбор рабочего DNS (`client.js`): селектор `dns_preset` (Cloudflare/Google/AdGuard/Quad9/
  OpenDNS). При выборе проставляет основной `dns_server` и «сеет» запасной в
  `alt_dns_servers` (см. C). Под селектором — реальный `DynamicList alt_dns_servers` на
  вкладке Client ▸ DNS.

**Не доделано / риски (нужно проверить на железе):**
- Регулярка под формат именно той сборки dnsmasq, что стоит на роутере (формат строки
  `query[A] ... from` может отличаться). Проверить и поправить, если не матчится.
- Лог dnsmasq глобальный и растёт; нет ротации/тримминга `/var/log/dnsmasq-q.log`. Добавить
  лимит размера или logrotate.
- «Работает с первого захода» достигается комбинацией A (ранний захват) + D (предзагрузка
  популярных). Для совсем нового сайта первый заход при прямом падении всё ещё может не
  пройти — чинится на втором. Это ожидаемое поведение.

---

## B. Обучение по IP:порт через conntrack (игры/приложения без SNI)

**Сделано:**
- Режим `conntrack`: `discover_conntrack()` берёт `dst=` из `conntrack -L` (ESTABLISHED),
  щупает каждый IP напрямую/через прокси, при `direct=fail & proxy=ok` пишет в
  `resources/auto_proxy_ip.txt` (базовый домен не применяется — это IP).
- Управляется флагом `automation.ip_learn` (по умолчанию **0/off**, чтобы не маршрутизировать
  лишний IP-трафик без явной нужды).
- `generate_client.uc`: `auto_proxy_ip.txt` → inline ruleset `auto-ip` (ip_cidr) → `main-out`
  (строки ~1557–1574 и правило ~1682–1695), для routed и tun режимов. ByeDPI/Zapret-совместимо.
- `automation_clear` теперь тоже удаляет `auto_proxy_ip.txt`.

**Риски:**
- `conntrack` выдаёт много CDN-IP — возможна избыточная маршрутизация через прокси. Нужен
  дедуп/кап и, возможно, игнор популярных ASN.
- Проверка IP через `https://<ip>` с `-k` ненадёжна (нет SNI/Host) — часть сайтов отвергает
  запрос по IP даже если работают по домену. Может давать ложные срабатывания. Требует
  натурного теста и, возможно, другой логики пробы для IP.
- UI-монитор показывает только домены; выученные IP в мониторе не видны (только в файле).

---

## C. Failover DNS-серверов при недоступности

**Сделано:**
- `config.dns_failover` (флаг, UI в automation.js) + `config.alt_dns_servers`
  (`DynamicList`, UI на вкладке Client ▸ DNS, туда же «сеет» `dns_preset`).
- `dns_failover_check()` (раз в минуту): если основной `dns_server` недоступен — переключает
  `dns_server` на первый здоровый из `alt_dns_servers`, делает `generate_client.uc` + reload.
- `dns_reachable()` щупает только plain UDP/Do53 (DoH/DoT считаются всегда доступными):
  `curl https://<srv>/dns-query` ИЛИ `dig +short @srv`, иначе `nc -u -z`.

**Риски:**
- `dig` может отсутствовать на целевой системе — тогда здоровье plain-сервера проверяется
  только через `curl` к DoH-эндпоинту, что неточно для чисто UDP-серверов. Заменить на
  реальный UDP-запрос (например, через `nslookup`/`drill` или in-process резолвер ядра).
- Переключение `dns_server` перезаписывает UCI и регенерирует — убедиться, что это не
  конфликтует с другими местами, читающими `dns_server`.

---

## D. Предзагрузка готового списка популярных заблокированных доменов

**Сделано:**
- `automation.preload_enabled` + `automation.preload_url` (по умолчанию — публичный список
  Re-filter `.../publication.txt`).
- `preload()` при старте и раз в 24ч качает plaintext-список (один домен на строку),
  прогоняет через `base_domain()`, сеет как выученные в `auto_proxy_list.txt`, делает reload.
- Скачивание через `wget` (без retry, одна попытка + лог при失败).

**Риски:**
- `wget` должен быть в системе. Добавить fallback на `curl -fsSL` при необходимости.
- Нет кэша при офлайне на старте — при недоступности списка сайты учатся обычным путём.

---

## Что ещё НЕ проверено (критично перед релизом)

1. Сборка и установка: `.\\build-run.sh` → `dist/` → zip в `release/`; `install.sh` ставит на
   роутер. Не запускалось на реальном устройстве в этой сессии.
2. Наличие утилит на цели: `curl`, `dig`/`nc`, `conntrack`, `wget`, и версия `ucode`
   (используются `fd.seek`/`fd.tell`, `stat().size`, `json()`, `index()`, `type()` — проверить
   на целевом ucode).
3. Формат строки лога dnsmasq (см. A) — главный риск для режима `dns`.
4. Поведение `formvalue(section_id, name, value)` (setter) в LuCI при записи `alt_dns_servers`
   из `dns_preset.write` — предполагается, что DynamicList сохранит массив. Проверить на UI.

## Открытые TODO (продолжение)

- Ротация/лимит `/var/log/dnsmasq-q.log`.
- Более точная проверка здоровья DNS (UDP-запрос вместо `curl`-к-DoH).
- Дедуп/кап и фильтрация CDN для conntrack-IP (B).
- Отображение выученных IP в мониторе automation.js.
- Перевод новых строк UI в `po/ru` (сейчас fallback на английский).
- Натурные тесты A/B/C/D на роутере и правка регэкспов/логики по результатам.

## Быстрый чек-лист сборки/теста

```
.\\build-run.sh            # собрать dist/ и release/
# install.sh ставит opkg-пакет на роутер
# Включить в UI: Automation ▸ Enable + Discover = "DNS query log" (или both/all)
# Опцionalно: Client ▸ DNS ▸ DNS preset = Cloudflare + Enable DNS failover
# Лог демона: /var/log/homeproxy/automation.log ; состояние: /var/run/homeproxy/automation_state.json
# Выученное: /etc/homeproxy/resources/auto_proxy_list.txt и auto_proxy_ip.txt
```
