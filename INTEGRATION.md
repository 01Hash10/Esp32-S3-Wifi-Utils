# Integration Manual — App Flutter ↔ Firmware ESP32-S3

Documento vivo. Toda feature nova que toca o protocolo BLE deve atualizar
este manual no mesmo commit do firmware.

> **Status**: em construção (Phase 1 em andamento — transporte BLE).

## Sumário

- [Identificação BLE](#identificação-ble)
- [Conexão e pareamento](#conexão-e-pareamento)
- [Protocolo híbrido](#protocolo-híbrido)
- [Catálogo de comandos JSON (`cmd_ctrl`)](#catálogo-de-comandos-json-cmd_ctrl)
- [Catálogo de eventos TLV (`stream`)](#catálogo-de-eventos-tlv-stream)
- [Exemplos Dart](#exemplos-dart)

---

## Identificação BLE

| Item | Valor |
|---|---|
| Device name (advertising) | `WifiUtils-XXXX` (XXXX = últimos 4 hex do MAC) |
| Service UUID | `e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01` |
| Characteristic `cmd_ctrl` | `e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02` (Write + Notify) |
| Characteristic `stream` | `e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03` (Notify) |

> UUIDs são custom 128-bit, não-alocados pela SIG. Não conflitam com
> services padrão.

## Conexão e pareamento

Sequência completa do app Flutter:

1. **Scan** por nome com prefixo `WifiUtils-` OU pelo Service UUID.
   O device anuncia `WifiUtils-XXXX` onde `XXXX` são os 4 últimos dígitos
   hex do MAC BT.
2. **Connect** ao peripheral. Pareamento é **Just Works** (sem PIN nesta fase).
3. **Request MTU = 247** via `requestMtu(247)`. Confirme no log do firmware:
   `transport-ble: mtu update conn=N mtu=247`.
4. **Discover services + characteristics** dentro do service WifiUtils.
5. **Subscribe (setNotifyValue=true)** em ambas as characteristics
   (`cmd_ctrl` e `stream`). O firmware loga:
   `transport-ble: subscribe attr=N notify=1`.
6. **Validar conexão**: enviar `{"cmd":"hello","seq":1}` em `cmd_ctrl`.
   Resposta esperada via Notify do mesmo `cmd_ctrl`:
   ```json
   {"resp":"hello","seq":1,"fw":"...","idf":"5.4.0","chip":"esp32s3","cores":2,"rev":2}
   ```

> **Nota**: o protocolo JSON em `cmd_ctrl` envia uma mensagem por Write
> (sem framing por newline ou comprimento) — o GATT já delimita o pacote.
> Se mandar 2 JSONs no mesmo Write, o parser vai falhar.

## Protocolo híbrido

Duas characteristics, propósitos distintos:

### `cmd_ctrl` — JSON minificado

Frequência baixa (comandos pontuais). Cada mensagem é um único JSON object,
serializado sem espaços, terminado por `\n` (newline) para framing.

Exemplo de pedido (do app):
```json
{"cmd":"ping","seq":42}
```

Exemplo de resposta (do device):
```json
{"resp":"pong","seq":42,"uptime_ms":12345}
```

Schema base de toda mensagem:
- App → Device: `{"cmd": <string>, "seq": <int>, ...args}`
- Device → App: `{"resp": <string>, "seq": <int>, ...payload}` ou
  `{"err": <string>, "seq": <int>, "msg": <string>}` em caso de erro

### `stream` — TLV binário

Frequência alta (scan results streaming, eventos de defense, pcap chunks).
Frame:

```
+--------+--------+--------+--------+----------------+
|   length (u16 BE) |  type  |  seq   |    payload    |
+-----------------+--------+--------+----------------+
       2 bytes        1 byte   1 byte   length-2 bytes
```

- `length`: total de bytes que seguem (type + seq + payload)
- `type`: identifica o tipo da mensagem (ver enum em `components/protocol/include/protocol.h`)
- `seq`: sequence number incremental por characteristic, permite o app detectar perda
- `payload`: bytes específicos do `type`. Cada `type` define seu próprio layout.

> A negociação de MTU = 247 dá payload útil de ~243 bytes por notify.
> Para mensagens > 240 bytes, fragmentar em múltiplos frames (TBD: design
> de fragmentação será adicionado quando primeiro caso real surgir).

## Catálogo de comandos JSON (`cmd_ctrl`)

| `cmd` | Args | Resposta | Phase |
|---|---|---|---|
| `ping` | `seq` | `{"resp":"pong","seq":N,"uptime_ms":N}` | 1 |
| `hello` | `seq` | `{"resp":"hello","seq":N,"fw":...,"idf":...,"chip":...,"cores":N,"rev":N}` | 1 |
| `status` | `seq` | `{"resp":"status","seq":N,"uptime_ms":N,"free_sram":N,"free_psram":N,"min_free_sram":N}` | 1 |
| `wifi_scan` | `seq` | `{"resp":"wifi_scan","seq":N,"status":"started"}` (ack imediato; resultados via `stream`) | 2 |
| `ble_scan` | `seq`, `duration_sec` (opcional, default 10, max 599; 0 = até `ble_scan_stop`) | `{"resp":"ble_scan","seq":N,"status":"started"}` | 2 |
| `ble_scan_stop` | `seq` | `{"resp":"ble_scan_stop","seq":N,"status":"started"}` (encerra scan em andamento) | 2 |
| `deauth` | `seq`, `bssid` (string), `target` (string, opcional, default broadcast), `channel` (1–14), `count` (opcional, default 10, max 1000), `reason` (opcional, default 7) | `{"resp":"deauth","seq":N,"status":"started"}` (ack imediato; resultado final via TLV `HACK_DEAUTH_DONE` no `stream`). Roda em task assíncrona pra não bloquear BLE. | 3 |
| `beacon_flood` | `seq`, `channel` (1–14), `ssids` (array de strings, 1–32, cada uma ≤32 bytes), `cycles` (opcional, default 50, max 200) | `{"resp":"beacon_flood","seq":N,"status":"started"}` (ack imediato; resultado final via TLV `HACK_BEACON_DONE` no `stream`). Async. | 3 |
| `ble_spam_apple` | `seq`, `cycles` (opcional, default 50, max 500) | `{"resp":"ble_spam_apple","seq":N,"status":"started"}` (ack; resultado final via TLV `HACK_BLE_SPAM_DONE` em `stream`, vendor=0). Pausa adv do GATT. Cada cycle ~100ms. | 4 |
| `ble_spam_samsung` | `seq`, `cycles` (default 50, max 500) | Idem, vendor=1 no DONE. Galaxy Buds popups em phones Samsung. | 4 |
| `ble_spam_google` | `seq`, `cycles` (default 50, max 500) | Idem, vendor=2 no DONE. Pixel Buds popups em Android com Fast Pair. | 4 |
| `ble_spam_multi` | `seq`, `cycles` (default 50, max 500) | Idem, vendor=255 (multi). Cada cycle escolhe Apple/Samsung/Google aleatoriamente. | 4 |
| `wifi_connect` | `seq`, `ssid`, `password` (opcional para abertas), `timeout_ms` (opcional, default 15000, range 1000–60000) | `{"resp":"wifi_connect","seq":N,"status":"connected","ip":"x.x.x.x","gateway":"x.x.x.x","mac":"aa:bb:..."}`. Ou `err: wifi_timeout`/`wifi_failed`. ESP fica como STA até `wifi_disconnect`. | 3 |
| `wifi_disconnect` | `seq` | `{"resp":"wifi_disconnect","seq":N,"status":"disconnected"}`. Para qualquer `arp_cut` ativo também. | 3 |
| `arp_cut` | `seq`, `target_ip` (string IPv4), `target_mac` (string), `gateway_ip`, `gateway_mac`, `interval_ms` (100–5000, default 1000), `duration_sec` (1–600, default 60) | `{"resp":"arp_cut","seq":N,"status":"started",...}`. Roda em task assíncrona. Requer `wifi_connect` antes. Modo "drop": ESP não encaminha tráfego. | 3 |
| `arp_cut_stop` | `seq` | `{"resp":"arp_cut_stop","seq":N,"status":"stopping"}`. | 3 |
| `arp_throttle` | `seq`, `target_ip`, `target_mac`, `gateway_ip`, `gateway_mac`, `on_ms` (200–60000, default 5000), `off_ms` (200–60000, default 5000), `duration_sec` (1–600, default 60) | `{"resp":"arp_throttle","seq":N,"status":"started","on_ms":N,"off_ms":N,"duration_sec":N}`. Alterna ciclos de poison (on_ms) e restore (off_ms) — vítima tem internet intermitente. | 3 |
| `arp_throttle_stop` | `seq` | `{"resp":"arp_throttle_stop","seq":N,"status":"stopping"}`. | 3 |
| `channel_jam` | `seq`, `channel` (1–14), `duration_sec` (opcional, 1–120, default 10) | `{"resp":"channel_jam","seq":N,"status":"started"}` (ack imediato; final via TLV `HACK_JAM_DONE` em `stream`). Spam de RTS broadcast trava NAV no canal — STAs ficam silenciosas. Cap de 120s pra não fritar a placa. | 3 |
| `channel_jam_stop` | `seq` | `{"resp":"channel_jam_stop","seq":N,"status":"started"}`. | 3 |
| `lan_scan` | `seq`, `timeout_ms` (opcional, default 3000, range 500–30000) | `{"resp":"lan_scan","seq":N,"status":"started"}` (ack imediato; hosts via TLV `LAN_HOST` em `stream`, fim via TLV `LAN_SCAN_DONE`). Requer `wifi_connect` antes. ARP scan no /24 do IP atual, ~5–8s típicos. | 3 |
| `probe_sniff` | `seq`, `ch_min` (1–13, default 1), `ch_max` (1–13, default 13, ≥ ch_min), `dwell_ms` (100–5000, default 500), `duration_sec` (1–300, default 30) | `{"resp":"probe_sniff","seq":N,"status":"started"}` (ack imediato; cada probe único via TLV `PROBE_REQ` em `stream`, fim via `PROBE_DONE`). **Requer ESP NÃO conectado** (`wifi_disconnect` antes se preciso). Channel hopping no range, dedup por (mac, ssid) até 256 entradas. | 3 |
| `probe_sniff_stop` | `seq` | `{"resp":"probe_sniff_stop","seq":N,"status":"started"}` (encerra cedo). | 3 |
| `wpa_capture` | `seq`, `bssid` (string MAC), `channel` (1–13), `duration_sec` (opcional, default 60, max 600) | `{"resp":"wpa_capture","seq":N,"status":"started"}` (ack imediato; cada EAPOL via TLV `WPA_EAPOL` em `stream`, fim via `WPA_CAPTURE_DONE`). **Requer ESP NÃO conectado**. Encerra automaticamente se M1..M4 todos vistos. Para forçar handshake, app pode disparar `deauth` em paralelo. | 3 |
| `wpa_capture_stop` | `seq` | `{"resp":"wpa_capture_stop","seq":N,"status":"started"}` (encerra cedo). | 3 |
| `pmkid_capture` | `seq`, `bssid` (string MAC), `channel` (1–13), `duration_sec` (opcional, default 60, max 600) | `{"resp":"pmkid_capture","seq":N,"status":"started"}` (ack imediato; PMKID via TLV `PMKID_FOUND` em `stream`, fim via `PMKID_DONE`). **Requer ESP NÃO conectado**. Encerra automaticamente na 1ª PMKID encontrada. App fornece ESSID separadamente pra montar hash hashcat `WPA*02*pmkid*ap*sta*essid`. | 3 |
| `pmkid_capture_stop` | `seq` | `{"resp":"pmkid_capture_stop","seq":N,"status":"started"}` (encerra cedo). | 3 |

### Erros padronizados

Toda resposta de erro segue o schema:
```json
{"err":"<code>","seq":<N>,"msg":"<detalhe opcional>"}
```

| `err` code | Quando |
|---|---|
| `bad_json` | JSON inválido / não parseável |
| `missing_cmd` | JSON sem campo `cmd` ou tipo inválido |
| `unknown_cmd` | Comando desconhecido (`msg` traz o cmd recebido) |
| `scan_busy` | `wifi_scan`/`ble_scan` solicitado enquanto outro scan rodando |
| `scan_failed` | API de scan retornou erro (`msg` = nome do erro) |
| `scan_idle` | `ble_scan_stop` chamado sem scan em andamento |
| `bad_bssid` | Campo `bssid` ausente ou formato inválido (esperado `aa:bb:cc:dd:ee:ff`) |
| `bad_target` | Campo `target` em formato inválido |
| `bad_channel` | Campo `channel` ausente ou fora de 1–14 |
| `deauth_failed` | Falha ao iniciar a task de deauth (ex: heap baixo, args inválidos). `msg` traz o erro |
| `hack_busy` | `deauth`/`beacon_flood` solicitado enquanto outro job de hacking_wifi roda |
| `bad_ssids` | Campo `ssids` ausente ou tamanho fora de 1–32 |
| `bad_ssid_entry` | Algum item do array `ssids` não é string ou está vazio |
| `beacon_failed` | Falha ao iniciar a task de beacon_flood. `msg` traz o erro |
| `spam_busy` | `ble_spam_apple` solicitado durante outro spam ainda rodando |
| `spam_failed` | Falha ao iniciar a task de apple spam. `msg` traz o erro |
| `bad_ssid` | Campo `ssid` ausente ou vazio em `wifi_connect` |
| `wifi_timeout` | `wifi_connect` não obteve IP via DHCP no tempo dado |
| `wifi_failed` | `esp_wifi_set_config`/`esp_wifi_connect` falhou |
| `wifi_not_connected` | `arp_cut` chamado sem `wifi_connect` prévio |
| `bad_target_ip`/`bad_target_mac`/`bad_gateway_ip`/`bad_gateway_mac` | Formato inválido nos campos do `arp_cut` |
| `cut_busy_or_offline` | Outro `arp_cut` rodando, ou ESP não conectado |
| `cut_failed` | Falha ao iniciar a task do `arp_cut` (ex: heap baixo). `msg` traz detalhe |
| `cut_idle` | `arp_cut_stop` chamado sem cut em andamento |
| `wifi_busy` | `probe_sniff` solicitado enquanto ESP está conectado como STA |
| `sniff_busy` | `probe_sniff` solicitado durante outro sniff em andamento |
| `sniff_failed` | Falha ao iniciar a task de sniff (`msg` traz o erro) |
| `sniff_idle` | `probe_sniff_stop` chamado sem sniff em andamento |

### Exemplos de troca

```jsonc
// app → device (Write em cmd_ctrl)
{"cmd":"ping","seq":42}
// device → app (Notify em cmd_ctrl)
{"resp":"pong","seq":42,"uptime_ms":12345}

// app → device
{"cmd":"hello","seq":1}
// device → app
{"resp":"hello","seq":1,"fw":"1","idf":"5.4.0","chip":"esp32s3","cores":2,"rev":2}

// app → device
{"cmd":"status","seq":7}
// device → app
{"resp":"status","seq":7,"uptime_ms":58210,"free_sram":328540,"free_psram":8386188,"min_free_sram":325120}

// app → device (cmd inexistente)
{"cmd":"foo","seq":99}
// device → app
{"err":"unknown_cmd","seq":99,"msg":"foo"}
```

## Catálogo de eventos TLV (`stream`)

| `type` | Nome | Direção | Payload | Phase |
|---|---|---|---|---|
| `0x00` | `HEARTBEAT` | device → app | uptime + free SRAM/PSRAM, emitido a cada 5s | 1 |
| `0x10` | `WIFI_SCAN_AP` | device → app | 1 AP por frame, schema abaixo | 2 |
| `0x11` | `WIFI_SCAN_DONE` | device → app | resumo final do scan | 2 |
| `0x12` | `BLE_SCAN_DEV` | device → app | 1 device por frame (dedup por MAC) | 2 |
| `0x13` | `BLE_SCAN_DONE` | device → app | resumo final do scan BLE | 2 |
| `0x14` | `LAN_HOST` | device → app | 1 host (IP+MAC) descoberto pelo `lan_scan` | 3 |
| `0x15` | `LAN_SCAN_DONE` | device → app | resumo final do `lan_scan` | 3 |
| `0x16` | `PROBE_REQ` | device → app | 1 probe único (mac, rssi, canal, ssid pedido) | 3 |
| `0x17` | `PROBE_DONE` | device → app | resumo final do `probe_sniff` | 3 |
| `0x18` | `WPA_EAPOL` | device → app | 1 frame 802.11+EAPOL capturado pelo `wpa_capture` | 3 |
| `0x19` | `WPA_CAPTURE_DONE` | device → app | resumo final do `wpa_capture` | 3 |
| `0x1A` | `PMKID_FOUND` | device → app | 1 PMKID extraído de M1 (compacto, 28B) | 3 |
| `0x1B` | `PMKID_DONE` | device → app | resumo final do `pmkid_capture` | 3 |
| `0x20` | `HACK_DEAUTH_DONE` | device → app | resultado final do `deauth` | 3 |
| `0x21` | `HACK_BEACON_DONE` | device → app | resultado final do `beacon_flood` | 3 |
| `0x22` | `HACK_BLE_SPAM_DONE` | device → app | resultado final dos `ble_spam_*` (apple/samsung/google/multi) | 4 |
| `0x23` | `HACK_JAM_DONE` | device → app | resultado final do `channel_jam` | 3 |

### `0x00 HEARTBEAT` — payload (10 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 4 | `uptime_ms` | uint32 BE, ms desde o boot do firmware |
| 4 | 4 | `free_sram` | uint32 BE, bytes livres em SRAM interna |
| 8 | 2 | `free_psram_kb` | uint16 BE, KB livres em PSRAM (KB pra caber em 16 bits) |

> Emitido pelo firmware no `stream` a cada 5s **enquanto há cliente
> conectado e subscribed**. Não há heartbeat enquanto o ESP está sozinho.
> O app deve usar como sinal de liveness — se passar > ~12s sem heartbeat,
> assumir conexão zumbi e reconectar. Para confirmar o reverso (firmware
> sabe que o app está vivo), o app envia `ping` periódico.

### `0x10 WIFI_SCAN_AP` — payload

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `bssid` | MAC do AP, big-endian (byte 0 é o mais significativo do OUI) |
| 6 | 1 | `rssi` | int8, dBm (negativo) |
| 7 | 1 | `channel` | uint8, canal primário (1–13 / 1–14) |
| 8 | 1 | `auth_mode` | uint8, ver tabela abaixo |
| 9 | 1 | `ssid_len` | uint8, comprimento do SSID em bytes (0–32) |
| 10 | `ssid_len` | `ssid` | UTF-8, sem NUL terminador |

**Auth mode** (valor de `wifi_auth_mode_t` do ESP-IDF):

| Valor | Significado |
|---|---|
| 0 | OPEN |
| 1 | WEP |
| 2 | WPA_PSK |
| 3 | WPA2_PSK |
| 4 | WPA_WPA2_PSK |
| 5 | WPA2_ENTERPRISE |
| 6 | WPA3_PSK |
| 7 | WPA2_WPA3_PSK |
| 8 | WAPI_PSK |
| 9 | OWE |
| 10 | WPA3_ENT_192 |

### `0x11 WIFI_SCAN_DONE` — payload (7 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `ap_count` | uint16 BE, total de APs detectados |
| 2 | 4 | `scan_time_ms` | uint32 BE, duração do scan em ms |
| 6 | 1 | `status` | 0 = ok, 1 = erro (envio truncado) |

### `0x12 BLE_SCAN_DEV` — payload

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `mac` | BLE address, big-endian |
| 6 | 1 | `addr_type` | 0=public, 1=random, 2=public_id, 3=random_id |
| 7 | 1 | `rssi` | int8, dBm |
| 8 | 1 | `adv_flags` | uint8 (bit0=LE_LIMITED, bit1=LE_GENERAL, bit2=BR/EDR_NOT_SUPPORTED, ...) |
| 9 | 1 | `name_len` | uint8, max 32 |
| 10 | `name_len` | `name` | UTF-8 do nome anunciado (vazio se ausente) |
| 10+nL | 1 | `mfg_data_len` | uint8, max 30 |
| 11+nL | `mfg_data_len` | `mfg_data` | bytes brutos; primeiros 2 bytes = company ID little-endian (ex: `004c` = Apple, `0075` = Samsung, `00e0` = Google) |

> Apenas a primeira aparição de cada MAC durante um scan é emitida (dedup
> interno). Limite de 64 MACs únicos por scan; ao exceder, o firmware
> emite `BLE_SCAN_DONE` com `status=1` (truncado).

### `0x13 BLE_SCAN_DONE` — payload (7 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `dev_count` | uint16 BE, total de dispositivos únicos |
| 2 | 4 | `scan_time_ms` | uint32 BE |
| 6 | 1 | `status` | 0 = ok, 1 = limite de 64 MACs excedido, 2 = erro |

> Sequência típica: app envia `wifi_scan` em `cmd_ctrl` → recebe ack →
> recebe N frames `WIFI_SCAN_AP` em `stream` (um por AP) → recebe
> `WIFI_SCAN_DONE` indicando fim. Os `seq` do TLV são incrementais por
> characteristic (independente do `seq` do JSON em `cmd_ctrl`).

### `0x14 LAN_HOST` — payload (10 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 4 | `ip` | IPv4 do host (BE, ex: `c0 a8 01 32` = 192.168.1.50) |
| 4 | 6 | `mac` | MAC do host (BE) |

### `0x15 LAN_SCAN_DONE` — payload (7 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `host_count` | uint16 BE, total de hosts descobertos |
| 2 | 4 | `scan_time_ms` | uint32 BE, duração total |
| 6 | 1 | `status` | 0 = ok, 2 = erro (sem netif default) |

> O firmware varre 1..254 do /24 do IP atual (excluindo o ESP), envia
> ARP request pra cada um, aguarda `timeout_ms` pra replies, e itera o
> cache ARP do lwIP emitindo um `LAN_HOST` por entrada presente. O MAC
> retornado é como visto pelo lwIP (geralmente o vendor/OUI real do device).

### `0x16 PROBE_REQ` — payload

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `mac` | source MAC do device (BE) |
| 6 | 1 | `rssi` | int8, dBm |
| 7 | 1 | `channel` | canal em que o probe foi capturado |
| 8 | 1 | `ssid_len` | uint8, 0–32 (0 = probe broadcast / wildcard) |
| 9 | `ssid_len` | `ssid` | UTF-8, sem NUL terminador |

> Probe broadcast (`ssid_len=0`) significa "device procurando qualquer AP";
> probe direcionado revela um SSID que o device tem salvo. Fingerprint útil
> pra montar dossiê (preferred network list / probe history).

### `0x17 PROBE_DONE` — payload (9 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `unique_count` | uint16 BE, total de (mac, ssid) únicos emitidos |
| 2 | 2 | `frames_total` | uint16 BE, probe_req frames totais vistos (inclui dups) |
| 4 | 4 | `scan_time_ms` | uint32 BE |
| 8 | 1 | `status` | 0 = ok, 1 = limite de 256 dedup excedido, 2 = erro |

### `0x18 WPA_EAPOL` — payload

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `bssid` | BSSID do AP (BE) |
| 6 | 6 | `sta_mac` | MAC do cliente (a outra ponta) (BE) |
| 12 | 1 | `msg_index` | 1..4 do 4-way handshake, 0 = não classificado |
| 13 | 1 | `flags` | bit0 = truncated (frame > 227B), bit1+ reservado |
| 14 | 2 | `frame_len` | uint16 BE, tamanho ORIGINAL do frame 802.11 (sem FCS, antes de truncar) |
| 16 | até 227 | `frame` | bytes brutos do frame 802.11 (FC...EAPOL) — pcap-friendly |

> O frame inclui header 802.11 + LLC/SNAP + EAPOL completo (sem o FCS de
> 4 bytes do final). Pode ser concatenado direto num arquivo pcap com
> link-type `LINKTYPE_IEEE802_11` (105). Se `flags` tem bit0 setado, o
> frame foi truncado em 227 bytes — pcap usual aceita isso, mas hashcat
> pode falhar dependendo de qual mensagem.

### `0x19 WPA_CAPTURE_DONE` — payload (13 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `bssid` | BSSID alvo (eco do request) |
| 6 | 1 | `frames_count` | total de frames EAPOL emitidos durante a captura |
| 7 | 1 | `msg_mask` | bitmask: bit0=M1, bit1=M2, bit2=M3, bit3=M4. `0x0F` = 4-way completo |
| 8 | 4 | `elapsed_ms` | uint32 BE, duração total |
| 12 | 1 | `status` | 0 = ok (M1..M4 todos), 1 = parcial / timeout, 2 = erro |

### `0x1A PMKID_FOUND` — payload (28 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `bssid` | BSSID do AP (BE) |
| 6 | 6 | `sta_mac` | MAC do cliente (BE) |
| 12 | 16 | `pmkid` | PMKID extraído do KDE OUI `00:0F:AC` type `0x04` no Key Data do M1 |

> Pra o app montar o hash hashcat: `WPA*02*<pmkid_hex>*<bssid_hex>*<sta_hex>*<essid_hex>`
> onde `essid_hex` é o ESSID do AP em hex (app sabe — typically vem do `wifi_scan`).
> `hashcat -m 22000 hash.hc22000 wordlist.txt`

### `0x1B PMKID_DONE` — payload (12 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 6 | `bssid` | BSSID alvo (eco do request) |
| 6 | 1 | `count` | total de PMKIDs encontrados (geralmente 0 ou 1) |
| 7 | 4 | `elapsed_ms` | uint32 BE |
| 11 | 1 | `status` | 0 = ok (encontrou), 1 = timeout sem PMKID, 2 = erro |

### `0x20 HACK_DEAUTH_DONE` — payload (7 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `sent` | uint16 BE, frames efetivamente aceitos pelo TX |
| 2 | 2 | `requested` | uint16 BE, valor de `count` clampado pelo firmware |
| 4 | 1 | `channel` | canal usado |
| 5 | 2 | `reason` | uint16 BE, reason code 802.11 utilizado |

### `0x21 HACK_BEACON_DONE` — payload (6 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `sent` | uint16 BE, frames aceitos pelo TX |
| 2 | 2 | `cycles` | uint16 BE, cycles efetivamente percorridos |
| 4 | 1 | `channel` | canal usado |
| 5 | 1 | `ssid_count` | número de SSIDs no flood |

### `0x22 HACK_BLE_SPAM_DONE` — payload (5 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 2 | `sent` | uint16 BE, cycles em que adv foi disparado com sucesso |
| 2 | 2 | `requested` | uint16 BE, valor de `cycles` clampado pelo firmware |
| 4 | 1 | `vendor` | 0 = Apple, 1 = Samsung, 2 = Google, 0xFF = multi |

### `0x23 HACK_JAM_DONE` — payload (7 bytes)

| Offset | Tamanho | Campo | Descrição |
|---|---|---|---|
| 0 | 4 | `sent` | uint32 BE, frames RTS efetivamente aceitos pelo TX |
| 4 | 2 | `duration_sec` | uint16 BE, duração configurada |
| 6 | 1 | `channel` | canal usado |

> Comandos `deauth`, `beacon_flood` e `ble_spam_apple` são **assíncronos**:
> o firmware ack'a com `status:"started"` em `cmd_ctrl` e, ao terminar a
> task, emite o TLV correspondente em `stream`. O app deve correlacionar
> pela ordem dos eventos (não há `seq` do JSON original no payload TLV —
> o `seq` do TLV é incrementado independentemente).

### Faixas reservadas de `msg_type`

| Faixa | Categoria |
|---|---|
| `0x00–0x0F` | Controle/sistema (heartbeat, status) |
| `0x10–0x1F` | Scan results (WiFi APs, BLE devices) |
| `0x20–0x2F` | Eventos de hacking (deauth sent, beacon emitted, etc) |
| `0x30–0x3F` | Eventos de defense (deauth detected, evil twin, etc) |
| `0x40–0x4F` | Captura/dados (pcap chunks, handshake) |
| `0x50–0xFF` | Reservado para uso futuro |

## Exemplos Dart

> _Snippets concretos serão adicionados conforme cada feature exporta API
> usável para o app._

### Conexão e ping (Phase 1)

```dart
import 'dart:convert';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';

const svcUuid    = 'e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01';
const cmdUuid    = 'e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c02';
const streamUuid = 'e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c03';

Future<void> connectAndPing() async {
  // 1. Scan
  await FlutterBluePlus.startScan(
    withServices: [Guid(svcUuid)],
    timeout: const Duration(seconds: 5),
  );
  final result = await FlutterBluePlus.scanResults
      .map((rs) => rs.firstWhere((r) => r.device.platformName.startsWith('WifiUtils-')))
      .first;
  await FlutterBluePlus.stopScan();

  // 2. Connect
  final device = result.device;
  await device.connect(autoConnect: false);

  // 3. MTU
  await device.requestMtu(247);

  // 4. Discover
  final svc = (await device.discoverServices())
      .firstWhere((s) => s.uuid == Guid(svcUuid));
  final cmd = svc.characteristics.firstWhere((c) => c.uuid == Guid(cmdUuid));
  final stream = svc.characteristics.firstWhere((c) => c.uuid == Guid(streamUuid));

  // 5. Subscribe
  await cmd.setNotifyValue(true);
  await stream.setNotifyValue(true);

  // Listener para respostas no cmd_ctrl
  cmd.lastValueStream.listen((bytes) {
    final json = utf8.decode(bytes);
    print('cmd_ctrl recv: $json');
  });

  // Listener para frames TLV no stream
  stream.lastValueStream.listen((bytes) {
    if (bytes.length < 4) return;
    final length = (bytes[0] << 8) | bytes[1];
    final type = bytes[2];
    final seq = bytes[3];
    final payload = bytes.sublist(4);

    if (type == 0x10 && payload.length >= 10) {
      // WIFI_SCAN_AP
      final bssid = payload.sublist(0, 6)
          .map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');
      final rssi = payload[6].toSigned(8);
      final channel = payload[7];
      final auth = payload[8];
      final ssidLen = payload[9];
      final ssid = utf8.decode(payload.sublist(10, 10 + ssidLen),
                               allowMalformed: true);
      print('AP: $ssid  bssid=$bssid  rssi=$rssi  ch=$channel  auth=$auth');
    } else if (type == 0x11 && payload.length >= 7) {
      // WIFI_SCAN_DONE
      final apCount = (payload[0] << 8) | payload[1];
      final scanMs = (payload[2] << 24) | (payload[3] << 16) |
                     (payload[4] << 8) | payload[5];
      final status = payload[6];
      print('SCAN_DONE: $apCount APs in ${scanMs}ms, status=$status');
    }
  });

  // 6. Ping
  final ping = jsonEncode({'cmd': 'ping', 'seq': 42});
  await cmd.write(utf8.encode(ping), withoutResponse: false);
}
```

---

## Histórico de mudanças do protocolo

| Data | Phase | Mudança |
|---|---|---|
| 2026-05-04 | Phase 1 | Definição inicial: service UUID, duas characteristics, frame TLV, schema JSON |
| 2026-05-04 | Phase 1 | GATT server + comandos `ping`, `hello`, `status` operacionais; advertising como `WifiUtils-XXXX` |
| 2026-05-04 | Phase 2 | Comando `wifi_scan` + TLV `WIFI_SCAN_AP` (0x10) e `WIFI_SCAN_DONE` (0x11); decode Dart |
| 2026-05-04 | Phase 2 | Comandos `ble_scan` / `ble_scan_stop` + TLV `BLE_SCAN_DEV` (0x12) e `BLE_SCAN_DONE` (0x13); dedup por MAC; mfg_data |
| 2026-05-04 | Phase 3 | Comando `deauth` (raw 802.11 mgmt frame subtype 0x0C); pode requerer patch do filtro Espressif se `esp_wifi_80211_tx` rejeitar |
| 2026-05-04 | Phase 3 | Comando `beacon_flood`: gera beacon (subtype 0x08) com SSIDs do app, BSSID derivado de hash(ssid+idx) com prefixo locally-administered (0x02:..) |
| 2026-05-04 | Phase 4 | Comando `ble_spam_apple`: spam de Apple Continuity Proximity Pairing (subtype 0x07), 5 modelos (AirPods/Pro/Max/Beats/Pro2), random MAC por cycle |
| 2026-05-05 | Phase 3 | Comandos `wifi_connect`/`wifi_disconnect`/`arp_cut`/`arp_cut_stop`: ARP poisoning (NetCut-like) via lwip pbuf + linkoutput, modo "drop" |
| 2026-05-05 | Phase 3/4 | `deauth`/`beacon_flood`/`ble_spam_apple` viraram **assíncronos**: ack `started` em `cmd_ctrl`, resultado final em TLVs novos (`HACK_DEAUTH_DONE 0x20`, `HACK_BEACON_DONE 0x21`, `HACK_BLE_SPAM_DONE 0x22`). Evita supervision timeout do BLE com runs longos. Novo erro `hack_busy` quando há job concorrente. |
| 2026-05-05 | Phase 3 | Comando `lan_scan`: ARP scan no /24 do IP atual (requer `wifi_connect`). Emite TLV `LAN_HOST 0x14` por host descoberto + `LAN_SCAN_DONE 0x15` ao final. |
| 2026-05-05 | Phase 3 | Comandos `probe_sniff` / `probe_sniff_stop`: sniffer de probe requests via WiFi promiscuous mode com channel hopping. Requer ESP não-conectado. Emite TLV `PROBE_REQ 0x16` por (mac, ssid) único + `PROBE_DONE 0x17` ao final. Erros novos: `wifi_busy`, `sniff_busy`, `sniff_failed`, `sniff_idle`. |
| 2026-05-05 | Phase 3 | Comandos `wpa_capture` / `wpa_capture_stop`: captura EAPOL 4-way handshake num BSSID/canal específico. Emite TLV `WPA_EAPOL 0x18` por frame (frame 802.11 bruto, pcap-friendly) + `WPA_CAPTURE_DONE 0x19` com mask M1..M4. Encerra cedo se 4-way completo. App pode emitir `deauth` paralelo pra forçar handshake. |
| 2026-05-05 | Phase 3 | Comandos `pmkid_capture` / `pmkid_capture_stop`: extrai PMKID KDE (OUI `00:0F:AC`/type `0x04`) do EAPOL-Key M1. Compacto: TLV `PMKID_FOUND 0x1A` (28B) + `PMKID_DONE 0x1B`. Encerra na 1ª PMKID. ESSID fornecido pelo app pra montar hash hashcat WPA*02. |
| 2026-05-05 | Phase 3 | Comandos `arp_throttle` / `arp_throttle_stop`: variação do `arp_cut` que alterna ciclos ON (poison) e OFF (restore via ARP corretivo). Vítima fica com internet intermitente. |
| 2026-05-05 | Phase 3 | Comandos `channel_jam` / `channel_jam_stop`: spam de RTS broadcast com duration alto (~33ms NAV) num canal fixo. Trava airtime, vítimas no canal não conseguem TX/RX. Cap 120s. Novo TLV `HACK_JAM_DONE 0x23`. |
| 2026-05-05 | Phase 4 | Comandos `ble_spam_samsung`, `ble_spam_google`, `ble_spam_multi`. Reusam pipeline do apple_spam. TLV `HACK_BLE_SPAM_DONE 0x22` ganhou byte `vendor` no payload (0=Apple, 1=Samsung, 2=Google, 0xFF=multi). Backward-compat: app antigo que só lia 4B continua funcionando. |
| 2026-05-05 | Phase 1 | Heartbeat bidirecional: TLV `HEARTBEAT 0x00` emitido pelo firmware a cada 5s no `stream` (uptime + free SRAM/PSRAM). App detecta liveness sem polling. Reverso (app→firmware) continua via `ping`. |
