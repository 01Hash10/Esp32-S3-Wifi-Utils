# Methods — Como cada feature funciona

Documento de estudo e referência técnica. Para cada método/comando do
firmware, explica:

- **O que faz**: o efeito observável.
- **Como funciona**: a teoria por trás (protocolo / camada / RFC).
- **Implementação no firmware**: como o ESP32-S3 realiza.
- **Fluxo de dados**: caminho completo App ↔ ESP ↔ ar (texto + diagrama).
- **Limitações conhecidas**.

> **Regra**: toda feature nova adicionada ao firmware **DEVE** ter sua
> entrada aqui no mesmo commit que a implementa. Sem entrada aqui ↔
> feature incompleta. Mesma regra do `INTEGRATION.md` (que cobre
> protocolo BLE) — este aqui cobre **a teoria + implementação interna**.

## Sumário

### Phase 1 — Transporte
- [BLE GATT transport](#ble-gatt-transport-pareamentoadvertising)
- [Comandos básicos: ping / hello / status](#comandos-basicos-ping--hello--status)
- [Heartbeat (TLV `HEARTBEAT 0x00`)](#heartbeat--liveness-bidirecional)

### Phase 2 — Scan
- [WiFi scan ativo (`wifi_scan`)](#wifi_scan--scan-ativo-de-aps-2-4ghz)
- [BLE passive scan (`ble_scan` / `ble_scan_stop`)](#ble_scan--passive-discovery-de-devices-ble)

### Phase 3 — Hacking & Recon
- [Deauth (`deauth`)](#deauth--80211-deauth-attack)
- [Beacon flood (`beacon_flood`)](#beacon_flood--ssid-spoof-mass)
- [Channel jamming (`channel_jam`)](#channel_jam--airtime-lock-via-rts-broadcast)
- [WiFi STA connect/disconnect (`wifi_connect` / `wifi_disconnect`)](#wifi_connect--wifi_disconnect--associacao-sta)
- [ARP poisoning / NetCut (`arp_cut` / `arp_cut_stop`)](#arp_cut--netcut-style-poisoning-modo-drop)
- [ARP throttle (`arp_throttle`)](#arp_throttle--internet-intermitente-via-cycle-onoff)
- [LAN host discovery (`lan_scan`)](#lan_scan--arp-scan-no-24)
- [Probe request sniffing (`probe_sniff`)](#probe_sniff--captura-de-probe-requests)
- [WPA handshake capture (`wpa_capture`)](#wpa_capture--captura-do-eapol-4-way-handshake)
- [PMKID capture (`pmkid_capture`)](#pmkid_capture--extracao-de-pmkid-do-m1)

### Phase 4 — BLE
- [Apple Continuity spam (`ble_spam_apple`)](#ble_spam_apple--apple-continuity-proximity-spam)
- [Samsung EasySetup spam (`ble_spam_samsung`)](#ble_spam_samsung--samsung-easysetup-popup-spam)
- [Google Fast Pair spam (`ble_spam_google`)](#ble_spam_google--google-fast-pair-popup-spam)
- [Multi-vendor BLE spam (`ble_spam_multi`)](#ble_spam_multi--apple--samsung--google-aleatorio-por-cycle)

---

## BLE GATT transport (pareamento/advertising)

**O que faz**: expõe o ESP como um peripheral BLE com nome `WifiUtils-XXXX`
(últimos 4 hex do MAC) e um service custom de 128-bit com 2 characteristics:
`cmd_ctrl` (Write+Notify, JSON) e `stream` (Notify, TLV binário).

**Como funciona** (BLE 4.2 GATT):
- Advertising packet (31 bytes): flags + nome `WifiUtils-XXXX`.
- Scan response (31 bytes): UUID 128-bit do service. Separado porque
  nome + UUID 128 não cabem em 31 bytes do adv packet.
- GATT Server: service primário com 2 characteristics + CCCD para subscribe.
- MTU negociado pelo central via ATT_MTU_REQ; aceitamos até 247 (cabe em 1
  Data PDU sem fragmentação L2CAP).

**Implementação**:
- Stack: NimBLE (mais leve que Bluedroid). Configurada em `sdkconfig.defaults`.
- `transport_ble.c`:
  - `on_sync()`: callback do NimBLE quando host está pronto. Lê MAC BT,
    formata nome, configura device name, dispara `advertise()`.
  - `chr_access_cb()`: chamado a cada Write em `cmd_ctrl`. Faz
    `ble_hs_mbuf_to_flat` pra extrair os bytes e chama o callback do
    `command_router`.
  - `gap_event_cb()`: trata CONNECT/DISCONNECT/SUBSCRIBE/MTU/ADV_COMPLETE.
    Em DISCONNECT chama `advertise()` de novo.

**Fluxo**:
```
APP                   ESP (NimBLE host task)
 │                          │
 │── BLE scan ──────────────│  (adv WifiUtils-XXXX)
 │── connect ───────────────│  GAP_EVENT_CONNECT
 │── requestMtu(247) ───────│  GAP_EVENT_MTU
 │── discoverServices ──────│
 │── setNotify(cmd_ctrl) ───│  GAP_EVENT_SUBSCRIBE
 │── setNotify(stream) ─────│  GAP_EVENT_SUBSCRIBE
 │── write(cmd_ctrl,JSON) ──│  chr_access_cb → command_router
 │←── notify(cmd_ctrl,JSON) ─│  resposta JSON
 │←── notify(stream,TLV) ────│  eventos binários (scan, hacking)
```

**Limitações**: Just Works pairing (sem PIN). Apenas 1 conexão simultânea
por enquanto.

---

## Comandos básicos: ping / hello / status

**O que faz**: smoke tests do canal de comando.

- `ping` → `pong + uptime_ms` (RTT do JSON round-trip).
- `hello` → identidade do firmware (versão app, IDF, chip, cores, rev).
- `status` → uptime + free SRAM + free PSRAM + min free SRAM histórico.

**Implementação**: `command_router.c` handlers diretos. Usa `cJSON_*`
(componente `json` do IDF) pra montar resposta. Sem alocação dinâmica
nas tasks, exceto a string serializada do cJSON.

**Fluxo**:
```
APP ──{"cmd":"ping","seq":42}──→ ESP (cmd_ctrl write)
ESP ──{"resp":"pong","seq":42,"uptime_ms":12345}──→ APP (cmd_ctrl notify)
```

---

## Heartbeat — liveness bidirecional

**O que faz**: confirma que ESP e app estão vivos um pro outro sem polling
agressivo via comando.

**Como funciona** (BLE supervision e application-level liveness):
- Stack BLE tem supervision timeout (negociado, ~3–6s) — derruba conexão
  se nada chega no link layer. Mas conexão "zumbi" pode existir se um
  lado parou de processar dados embora ainda mantenha o link vivo.
- Solução application-level: cada lado emite sinal periódico de "estou
  vivo" no protocolo da app.

**Implementação** (`transport_ble.c`):
- `esp_timer` periódico de 5s (5_000_000 µs).
- Callback verifica `s_conn_handle != NONE && s_stream_subscribed`.
  Se sim, monta payload e emite TLV `HEARTBEAT 0x00` via `transport_ble_send_stream`.
- Payload (10B): uptime_ms (4B BE) + free_sram (4B BE) + free_psram_kb (2B BE).
- Sem cliente conectado: timer continua rodando mas o callback é early-return.
- Reverso (app→firmware): app envia `ping` periódico (já existe na Phase 1).
  Firmware recebe pong e atualiza seu próprio "última atividade do app".
  (Implementação dessa parte ficaria no firmware se quisermos detectar
  app-zumbi proativamente — por enquanto não é crítico.)

**Fluxo**:
```
ESP timer (5s)              transport_ble.heartbeat_cb
   ↓
   conn? subscribed? ─ não → return (sem cliente, sem trabalho)
   ↓ sim
   monta payload (uptime, sram, psram)
   tlv_encode + send_stream → App recebe TLV[0x00]

App
   recebe HEARTBEAT
   reseta timer "última heartbeat"
   se passar > 12s sem nada → assume zumbi → reconnect

App → ESP (ping a cada 10s)
   ESP responde pong via cmd_ctrl
```

**Limitações**: só envia quando há cliente conectado (intencional). Não
substitui supervision timeout do BLE — é camada acima. Custo: 1 timer
ESP_TIMER + 1 notify a cada 5s (~14 bytes pelo ar) — desprezível.

---

## `wifi_scan` — scan ativo de APs 2.4GHz

**O que faz**: lista APs visíveis (BSSID, SSID, RSSI, canal, auth_mode).

**Como funciona** (802.11 active scan):
- Para cada canal 1..13, ESP envia **probe request** (broadcast ou wildcard SSID).
- APs respondem com **probe response** contendo Beacon-like info (SSID,
  capabilities, supported rates, RSN IE).
- ESP coleta respostas + beacons capturados durante a janela.

**Implementação** (`scan_wifi.c`):
- `esp_wifi_scan_start(active, all_channels)` — async.
- `WIFI_EVENT_SCAN_DONE` dispara handler que pega `wifi_ap_record_t[]` via
  `esp_wifi_scan_get_ap_records`.
- Para cada record, codifica payload TLV `WIFI_SCAN_AP 0x10` (10B header +
  ssid_len ssid bytes) e envia via `transport_ble_send_stream`.
- Após emitir todos, envia `WIFI_SCAN_DONE 0x11` com totalizador.
- `vTaskDelay(5ms)` entre frames pra não saturar fila do GATT notify.

**Fluxo**:
```
App ──{"cmd":"wifi_scan"}──→ ESP
ESP ──{"resp":"wifi_scan","status":"started"}──→ App  (ack imediato)
   ┌────────────────── 2.4GHz radio ──────────────────┐
   │ ch1 → probe_req → probe_resp/beacon ... ch13     │
   └──────────────────────────────────────────────────┘
ESP ──TLV[0x10] AP1──→ App
ESP ──TLV[0x10] AP2──→ App
...
ESP ──TLV[0x11] DONE──→ App
```

**Limitações**: só 2.4GHz (S3 não tem 5GHz). Hidden SSIDs aparecem com
`ssid_len=0`.

---

## `ble_scan` — passive discovery de devices BLE

**O que faz**: lista devices BLE anunciando próximo (mac, rssi, name, mfg_data).

**Como funciona**: GAP discovery passivo — apenas escuta advertising packets.
Não envia scan_request, então não polui o canal nem revela nossa presença.
Devices anunciam:
- Flags
- Local name (Complete ou Shortened)
- Manufacturer Data (com Company ID nos 2 primeiros bytes LE)
- Service UUIDs

**Implementação** (`scan_ble.c`):
- `ble_gap_disc(BLE_OWN_ADDR_PUBLIC, duration_ms, params, cb)` com `passive=1`.
- `BLE_GAP_EVENT_DISC` para cada packet recebido.
- `ble_hs_adv_parse_fields()` extrai os campos.
- Dedup por MAC (linear scan em buffer estático de 64 entries).
- Cada device único emite TLV `BLE_SCAN_DEV 0x12`.
- Ao final: `BLE_SCAN_DONE 0x13`. Status=1 se truncou (>64 únicos).

**Fluxo**: análogo ao wifi_scan. Status=1 se passou de 64 MACs únicos.

**Limitações**: não vê scan responses (precisaria ativo). 64 unique cap
no firmware (memória estática) — app pode chamar várias vezes pra ampliar.

---

## `deauth` — 802.11 deauth attack

**O que faz**: envia frames forjados de deautenticação para forçar
clients a se desconectarem do AP. Cliente reassocia logo em seguida —
útil para forçar handshake de WPA, ou só pra bagunçar.

**Como funciona** (802.11 management frame, subtype 0xC):
- Frame de 26 bytes:
  - FC `0xC0 0x00` (type=Mgmt, subtype=Deauth)
  - duration `0x0000`
  - addr1 = destination (target client ou broadcast `ff:ff:...`)
  - addr2 = source = BSSID do AP (forjado)
  - addr3 = BSSID
  - sequence `0x0000`
  - reason code (LE) — 7 = "Class 3 frame received from nonassociated STA"
- Cliente recebe e protocol-aware desconecta sem questionar (até PMF/802.11w
  ser exigido — em redes domésticas geralmente não é).

**Implementação** (`hacking_wifi.c`):
- Pre-build template de 26 bytes em static const.
- Async via FreeRTOS task pra não bloquear BLE host:
  - `xTaskCreate(deauth_task, ...)` retorna ack `started` ao app.
  - Task: set channel, copia template, sobrescreve addr1/addr2/addr3/reason,
    loop `esp_wifi_80211_tx(WIFI_IF_STA, frame, 26, false)` × count.
  - 3ms delay entre frames pra não saturar.
  - Ao final emite TLV `HACK_DEAUTH_DONE 0x20` no stream.

**Fluxo**:
```
App ──{"cmd":"deauth","bssid":"AA:..","channel":6,"count":50}──→ ESP
ESP ──{"resp":"deauth","status":"started"}──→ App  (ack)

  ESP radio (ch6) ──deauth frame×50──→ ar
                                         ↓
                              client(s) desconectam
                              
ESP ──TLV[0x20] DEAUTH_DONE (sent=50, requested=50, ch=6, reason=7)──→ App
```

**Limitações**: o blob libnet80211 do IDF 5.4 filtra alguns mgmt frames —
~10–20 frames/chamada passam. APs com PMF (802.11w) ignoram deauth não
autenticado. Validação em hardware pendente (precisa cliente 2.4GHz separado).

---

## `beacon_flood` — SSID spoof mass

**O que faz**: gera N beacons falsos com SSIDs configurados, fazendo
aparecer redes fake no scanner do alvo. Visual / DoS de UI.

**Como funciona** (802.11 mgmt subtype 0x8):
- Beacon = frame mgmt que APs reais enviam ~10x/segundo anunciando seu SSID.
- Frame layout: header 24B + body fixo 12B (timestamp+interval+capability)
  + IEs variáveis (SSID, Supported Rates, DS Parameter, TIM, ERP, Extended Rates).
- Forjamos beacon completo com BSSID derivado de hash(ssid+idx) prefixado
  com `0x02` (locally administered MAC) — cada SSID parece ter o próprio AP.

**Implementação** (`hacking_wifi.c`):
- Async via task. Cada cycle percorre o array de SSIDs:
  - `make_bssid()`: FNV-1a hash do SSID + idx → 5 bytes baixos do MAC.
  - Monta frame em buffer (max ~94B) com IEs apropriadas pra parecer
    11g clean.
  - `esp_wifi_80211_tx`, 10ms delay.
- Final: TLV `HACK_BEACON_DONE 0x21`.

**Fluxo**: similar ao deauth. Frames vão pro ar; scanners mostram fake APs.

**Limitações**: sem HT/VHT capabilities IEs alguns scanners modernos
filtram. Validação visual no hardware pendente. Limite cycles=200.

---

## `channel_jam` — airtime lock via RTS broadcast

**O que faz**: trava o canal por N segundos. Stations no canal não
conseguem TX/RX significativo enquanto rodando — DoS de airtime.

**Como funciona** (802.11 NAV — Network Allocation Vector):
- Frame RTS (Request-to-Send) tem um campo `Duration` (16-bit) que diz
  pra outras stations: "vou ocupar o canal por X µs, fiquem quietas".
- Toda STA que ouve um RTS válido atualiza seu NAV e respeita —
  não TX até NAV expirar.
- Se mandarmos RTS com duration alto (32767µs ≈ 33ms) a cada ~25ms,
  o NAV nunca expira — todo o canal trava.

**Frame layout** (16 bytes, FC=Ctrl/RTS):
```
[0..1]   FC: 0xB4 0x00 (type=Ctrl=01, subtype=RTS=1011)
[2..3]   duration: 0xFF 0x7F (32767 µs LE)
[4..9]   addr1 (RA) = ff:ff:ff:ff:ff:ff (broadcast)
[10..15] addr2 (TA) = MAC fake (locally administered: 02:CA:FE:BE:EF:00)
```

**Implementação** (`hacking_wifi.c`):
- Async via task. Cap de 120s por sessão (não fritar a placa).
- Loop tight: copia template, `esp_wifi_80211_tx`, `vTaskDelay(25ms)`.
- Final: TLV `HACK_JAM_DONE 0x23` com sent + duration_sec + channel.

**Fluxo**:
```
App ──{"cmd":"channel_jam","channel":6,"duration_sec":30}──→ ESP
ESP ──ack {"status":"started"}──→ App

  ESP fixa ch=6
  loop por 30s:
    [RTS broadcast, dur=32767µs] ─── ar ───→ todas STAs no ch6
                                              ↓
                                      NAV atualizado, STAs silenciam
    sleep 25ms (NAV ainda válido por mais 8ms)
  fim do loop
  ESP ──TLV[0x23] HACK_JAM_DONE (sent=1200, dur=30, ch=6)──→ App
```

**Limitações**: não é CW puro (radio do S3 não expõe modo CW user-friendly).
Stations modernas com 802.11 mais robusto podem ignorar RTS sem CTS de
volta (MAC reset). Adapters em modo monitor não são afetados (não respeitam
NAV — só TX). Cap de 120s pra não esquentar demais o módulo.

---

## `wifi_connect` / `wifi_disconnect` — associação STA

**O que faz**: associa o ESP como cliente WiFi 2.4GHz numa rede WPA/WPA2-PSK
ou aberta. Habilita features LAN-level (`arp_cut`, `lan_scan`).

**Como funciona** (sequência 802.11 + 4-way handshake):
1. Probe / scan (já feito por `scan_wifi`).
2. Authentication (Open System).
3. Association request/response.
4. Se WPA/WPA2: 4-way handshake EAPOL-Key (M1..M4) → derivam PTK.
5. DHCP via lwIP → IP+gateway+DNS.

**Implementação** (`attack_lan.c`):
- `esp_wifi_set_config(WIFI_IF_STA, &cfg)` com SSID/password/authmode.
- `esp_wifi_connect()` → kernel cuida de auth + assoc + 4-way handshake.
- Espera `IP_EVENT_STA_GOT_IP` via FreeRTOS event group + timeout.
- Captura IP/gateway/our_MAC, retorna no JSON `wifi_connect`.

**Fluxo**:
```
App ──{"cmd":"wifi_connect","ssid":"x","password":"y"}──→ ESP
ESP ↔ AP: auth + assoc + 4-way handshake + DHCP
ESP ──{"resp":"wifi_connect","status":"connected","ip":"..","gw":".."}──→ App
```

**Limitações**: só 2.4GHz. Apenas WPA/WPA2-PSK (não WPA3). PMF marcado como
"capable, not required".

---

## `arp_cut` — NetCut-style poisoning (modo drop)

**O que faz**: tira a vítima da internet sem afetar outros. ESP envia ARP
replies forjadas dizendo:
- pra vítima: "gateway é meu_MAC"
- pro gateway: "vítima é meu_MAC"

ESP recebe os pacotes mas **não encaminha** (lwIP descarta) → vítima
fica off.

**Como funciona** (ARP / RFC 826 + cache poisoning):
- ARP cache de cada host mapeia IP→MAC. Não há autenticação.
- Frames ARP reply gratuitas (sem request) sobrescrevem entradas no cache.
- Repetir a cada N ms (default 1000ms) pra resistir a refresh natural do
  ARP cache (60s typically).

**Implementação** (`attack_lan.c`):
- `pbuf_alloc(PBUF_LINK, 42, PBUF_RAM)` aloca frame raw.
- Monta Ethernet header (14B) + ARP header (28B) com opcode REPLY.
- `netif->linkoutput(netif, p)` envia direto pelo driver WiFi (bypassa lwIP
  routing).
- Task assíncrona FreeRTOS roda 2 frames (poison vítima + poison gateway)
  a cada `interval_ms` até `deadline_us`.
- Task pode ser parada via `arp_cut_stop` (sinaliza `stop=true`).

**Fluxo**:
```
App ──{"cmd":"arp_cut","target_ip/mac","gateway_ip/mac"}──→ ESP
ESP ──ack {"status":"started"}──→ App
        ┌──── arp_cut_task ────┐
        │ a cada interval_ms:  │
        │  [Eth+ARP REPLY] →   │ vítima_MAC: "gw está em ESP_MAC"
        │  [Eth+ARP REPLY] →   │ gw_MAC: "vítima está em ESP_MAC"
        └──────────────────────┘
ESP recebe os pacotes redirecionados → lwIP dropa (não tem ARP cache da
chave verdadeira) → vítima sem internet.
```

**Limitações**: redes corporativas com Dynamic ARP Inspection (DAI) ou
ARP Inspection no switch silenciosamente bloqueiam. Só `drop` mode (modo
`throttle` com forwarding+rate-limit ainda no roadmap — precursor do MITM).

---

## `arp_throttle` — internet intermitente via cycle on/off

**O que faz**: mesma ideia do `arp_cut`, mas alterna entre fases ON
(cache poisoned, vítima sem internet) e OFF (cache restaurado, vítima
volta). Resultado: vítima tem internet "que falha" — bandwidth efetivo
fica ~`off_ms / (on_ms + off_ms)` da capacidade total.

**Como funciona**:
- Fase ON (default 5000ms): mesmo loop do `arp_cut`. Manda 2 ARP replies
  fake (poison vítima + poison gateway) a cada 1s.
- Fase OFF (default 5000ms): manda **1 par** de ARP replies *corretivas*
  com os MACs reais — restaura o cache da vítima e do gateway. Fica
  inerte por off_ms.
- Repete até `duration_sec`.

**Cleanup**: ao final (timeout ou stop), envia 1 par corretivo extra pra
não deixar a vítima offline depois do ataque.

**Implementação** (`attack_lan.c`):
- Estrutura separada `s_thr` para não conflitar com `s_cut`.
- Helpers `send_arp_poison()` e `send_arp_restore()` reusam o
  `send_arp_reply()` original.
- Task `arp_throttle_task` com 2 loops aninhados (poison loop + sleep loop).
- `wifi_disconnect` para `s_thr.stop = true` também.

**Fluxo**:
```
App ──{"cmd":"arp_throttle","on_ms":5000,"off_ms":5000,...}──→ ESP
ESP ──ack {"status":"started"}──→ App

  loop até duration_sec:
    [ON 5s]: poison.repeat 1s/par   → vítima offline
    [OFF 5s]: restore + idle         → vítima online
    [ON 5s]: poison.repeat ...
    ...
  cleanup: 1 último restore         → vítima volta normal
```

**Limitações**: vítima percebe instabilidade óbvia (não é stealth).
Apps com retry agressivo (browsers) podem mascarar parcialmente o efeito
durante fases curtas de OFF. Não é "rate limit" stricto-sensu (não
limita KB/s — limita uptime%). Real packet forwarding com token bucket
fica como precursor do MITM streaming, ainda na lista.

---

## `lan_scan` — ARP scan no /24

**O que faz**: descobre hosts vivos na LAN (IP+MAC) via ARP scan no /24
do nosso IP atual. Complementa o `arp_cut` — app lista hosts e o usuário
escolhe um alvo.

**Como funciona** (ARP cache discovery):
- Para cada IP de 1..254 do /24 (excluindo nosso IP), envia ARP request
  "who has X.X.X.Y? tell me".
- Hosts vivos respondem com ARP reply contendo seu MAC.
- lwIP automaticamente popula seu ARP cache com cada reply recebida.
- Após timeout, iteramos a tabela ARP do lwIP e emitimos hosts presentes.

**Implementação** (`attack_lan.c`):
- Async via task. 3 fases:
  1. **Probe**: `etharp_request(netif, &ip)` para cada IP, 15ms entre cada.
     ~3.8s pra um /24 inteiro.
  2. **Wait**: vTaskDelay(timeout_ms) (default 3000) pra replies popular cache.
  3. **Harvest**: `etharp_find_addr(netif, &ip, &mac, &ip_out)` para cada IP.
     Se idx >= 0, host está vivo → emite TLV `LAN_HOST 0x14` (10B: IP 4 + MAC 6).
- Final: TLV `LAN_SCAN_DONE 0x15` com count + scan_time_ms + status.

**Fluxo**:
```
App ──{"cmd":"lan_scan","timeout_ms":3000}──→ ESP (já wifi_connect-ado)
ESP ──ack {"status":"started"}──→ App

  ESP ──ARP req .1─→ ar  ←─ARP reply─ host 1
  ESP ──ARP req .2─→ ar
  ...                    (3.8s)
  ESP ──ARP req .254─→ ar ←─ARP reply─ host 254
  ↓ wait timeout_ms
  ESP itera ARP cache:
    ESP ──TLV[0x14] LAN_HOST 192.168.1.1 ab:cd:..──→ App
    ESP ──TLV[0x14] LAN_HOST 192.168.1.50 11:22:..──→ App
    ...
  ESP ──TLV[0x15] LAN_SCAN_DONE──→ App
```

**Limitações**: só /24 (assume netmask 255.255.255.0). Hosts que ignoram
ARP requests (raro) não aparecem. ARP cache do lwIP tem TTL — se demorar
muito, hosts podem evaporar antes do harvest.

---

## `probe_sniff` — captura de probe requests

**O que faz**: passive sniffer de probe requests com channel hopping.
Devices revelam SSIDs salvos quando procuram redes próximas — útil pra
fingerprinting / preferred network list.

**Como funciona** (802.11 mgmt subtype 0x4 + monitor mode):
- Modo promiscuous habilita rx de todos os frames no canal corrente.
- Probe request: FC `0x40 0x00`, source MAC = device, SSID IE no body
  com o nome procurado (vazio = wildcard / probe broadcast).

**Implementação** (`sniff_wifi.c`, modo PROBE):
- Controller task: hopa entre `ch_min..ch_max`, dwell `dwell_ms` por canal.
- Promisc CB (roda no contexto da wifi task!):
  - Filtra `WIFI_PKT_MGMT` + FC byte 0 = 0x40.
  - Parseia SSID IE em offset 24.
  - Dedup linear por (mac, ssid) num buffer alocado (256 entries × 39B = ~10KB).
  - Se nova entrada: `transport_ble_send_stream(TLV PROBE_REQ 0x16)`.
- Final: TLV `PROBE_DONE 0x17` (unique + frames_total + scan_time + status).

**Restrição**: ESP NÃO pode estar conectado como STA (channel hop quebra
associação ao AP). Command router checa `attack_lan_is_connected()` antes.

**Fluxo**:
```
App ──{"cmd":"probe_sniff","ch_min":1,"ch_max":13,"dwell_ms":500}──→ ESP
ESP ──ack {"status":"started"}──→ App

  controller_task        promisc_cb (wifi task)
  set ch=1 → dwell 500ms     ↓
                         frame mgmt 0x40
                         parse SSID IE
                         dedup (mac,ssid)
                         emit TLV[0x16] →─→ App
  set ch=2 → dwell 500ms ...
  ...
  ESP ──TLV[0x17] PROBE_DONE──→ App
```

**Limitações**: dedup cap 256 entries. Frames protegidos por MFP/PMF
ainda aparecem (probe é unprotected). 5GHz fora de alcance.

---

## `wpa_capture` — captura do EAPOL 4-way handshake

**O que faz**: captura os 4 frames EAPOL-Key do 4-way handshake WPA/WPA2.
Pcap resultante alimenta hashcat (`hcxpcapngtool` → `.hc22000`) pra
brute-force da PSK.

**Como funciona** (802.1X-2010 / 802.11i):
- Após associação, AP e cliente fazem 4-way handshake derivando PTK:
  - **M1** AP→STA: ANonce (cleartext)
  - **M2** STA→AP: SNonce + MIC + RSN IE
  - **M3** AP→STA: MIC + GTK encrypted in Key Data
  - **M4** STA→AP: MIC ack
- Hashcat precisa M1+M2 (ou M1+M3, etc) pra derivar PMK candidate e
  comparar MIC com a senha tentativa.

**Implementação** (`sniff_wifi.c`, modo EAPOL):
- Promisc filter `WIFI_PROMIS_FILTER_MASK_DATA`.
- Channel fixo (sem hop).
- CB filtra:
  - FC byte 0 type bits = `0b10` (Data, mask 0x0C == 0x08).
  - Não Protected (bit 6 do FC[1] = 0) — EAPOL é cleartext.
  - QoS data ajusta hdr_len para 26 (vs 24 normal).
  - DS bits identificam direção (ToDS/FromDS) e qual addr é BSSID/STA.
  - LLC/SNAP `AA AA 03 00 00 00 88 8E` confirma EtherType EAPOL.
  - EAPOL header type byte `0x03` = EAPOL-Key.
- Classifica msg index pelo Key Information field (16-bit BE):
  - bit 7 (0x0080) = ACK
  - bit 8 (0x0100) = MIC
  - bit 6 (0x0040) = Install
  - bit 9 (0x0200) = Secure
  - **M1**: ACK && !MIC; **M2**: !ACK && MIC && !Secure && !Install;
    **M3**: ACK && MIC && Install; **M4**: !ACK && MIC && Secure && !Install.
- Emite TLV `WPA_EAPOL 0x18` com header (bssid+sta+msg_idx+flags+orig_len)
  + frame 802.11 inteiro (max 227B, trunca se M3 com KEK grande).
- Atualiza `s_eapol_msg_mask` (bits M1..M4). Se 0x0F, encerra.
- Final: TLV `WPA_CAPTURE_DONE 0x19`.

**Fluxo**:
```
App ──{"cmd":"wpa_capture","bssid":"AA:..","channel":6}──→ ESP (não conectado)
ESP ──ack {"status":"started"}──→ App

  ESP fixa ch=6, promiscuous=on, filter=DATA
  ┌─── ar ───┐
  │ AP ↔ STA: 4-way handshake (forçado por deauth paralelo se preciso)
  └──────────┘
  promisc_cb captura cada EAPOL-Key:
    ESP ──TLV[0x18] WPA_EAPOL M1──→ App  (raw 802.11 frame, ~131B)
    ESP ──TLV[0x18] WPA_EAPOL M2──→ App
    ESP ──TLV[0x18] WPA_EAPOL M3──→ App
    ESP ──TLV[0x18] WPA_EAPOL M4──→ App
  
  s_eapol_msg_mask = 0x0F → break
  ESP ──TLV[0x19] WPA_CAPTURE_DONE (mask=0x0F)──→ App
  
  App grava bytes em pcap (LINKTYPE 105) → hcxpcapngtool → hashcat
```

**Limitações**: M3 com payload de Group Key pode ultrapassar 227B (truncado;
hashcat aceita parcialmente). Se nenhum cliente reassociar, nunca vê
handshake — daí o uso paralelo de `deauth`.

---

## `pmkid_capture` — extração de PMKID do M1

**O que faz**: extrai PMKID dos 16 bytes embutidos no Key Data do M1
quando AP suporta. Ataque mais elegante: **não precisa de cliente** —
basta um único M1 do AP. Funciona se o AP está disposto a iniciar
4-way mesmo sem ter conhecido o cliente antes (PMK caching).

**Como funciona** (802.11i + WPA-2008):
- PMKID = HMAC-SHA1-128("PMK Name" || AP_MAC || STA_MAC) trunc 128.
- AP envia PMKID no M1 dentro do Key Data como **KDE** (Key Data Element):
  ```
  Type=0xDD | Length=0x14 | OUI=00:0F:AC | DataType=0x04 | PMKID(16B)
  ```
- Hashcat recupera a PSK direto desse PMKID + ESSID conhecido (modo 22000):
  ```
  WPA*02*<pmkid>*<ap>*<sta>*<essid_hex>***
  ```

**Implementação** (`sniff_wifi.c`, modo PMKID):
- Mesmo pipeline do `wpa_capture`, mas:
  - Filtra **só M1** (ACK=1, MIC=0).
  - Parseia o Key Data field do EAPOL-Key:
    - Position: hdr_len + 8 (LLC) + 4 (EAPOL header) + 95 (EAPOL-Key fixed
      header até key_data_len) + 2 (key_data_len BE) = 99 bytes da EAPOL
      structure inteira → start of Key Data.
    - Itera TLVs (Type/Length/Value).
    - Procura: `Type=0xDD, Length>=20, Body[0..2]=00:0F:AC, Body[3]=0x04`.
    - Pega `Body[4..19]` = PMKID.
- Emite TLV compacto `PMKID_FOUND 0x1A` (28B: bssid + sta + pmkid).
- Encerra na 1ª PMKID encontrada (não precisa esperar mais).
- Final: TLV `PMKID_DONE 0x1B`.

**Fluxo**:
```
App ──{"cmd":"pmkid_capture","bssid":"AA:..","channel":6}──→ ESP (não conectado)
ESP ──ack──→ App

  promisc_cb_pmkid captura M1:
    parseia Key Data → encontra KDE 00:0F:AC type 0x04
    extrai 16B PMKID
    ESP ──TLV[0x1A] PMKID_FOUND (28B)──→ App
  break loop
  ESP ──TLV[0x1B] PMKID_DONE──→ App

App: WPA*02*<pmkid>*<ap>*<sta>*<essid_hex>*** → hashcat -m 22000
```

**Por que é tão melhor que wpa_capture**:
- 1 frame vs 4 frames.
- 28B no BLE vs ~190B × 4.
- Não precisa de cliente — basta ESP causar uma assoc fake (ou esperar
  qualquer reconnect natural).

**Limitações**: nem todo AP envia PMKID no M1 (depende do firmware/vendor).
Mesmo princípio do `wpa_capture` — precisa AP iniciar 4-way handshake.
Quando funciona, é o caminho mais rápido pra cracking.

---

## `ble_spam_apple` — Apple Continuity proximity spam

**O que faz**: gera popups de pareamento de AirPods/Beats em iPhones
próximos. Visual / DoS de UI iOS.

**Como funciona** (Apple Continuity protocol):
- iPhones perto de AirPods em modo pairing escutam BLE adv com:
  - Manufacturer Data Company ID `0x004C` (Apple)
  - Subtype `0x07` (Proximity Pairing) + payload de 27 bytes
  - Model ID nos bytes 5..6 (cada modelo de AirPods/Beats tem o seu)
- iOS mostra popup "AirPods próximos detectados — pair?" automaticamente.

**Implementação** (`hacking_ble.c`):
- 5 payloads pré-construídos (AirPods 1, AirPods Pro, Max, Beats Solo3, Pro 2).
- Async via task:
  - Para por algumas centenas de ms o adv normal do GATT.
  - Loop de cycles:
    - Pick payload aleatório (`esp_random() % 5`).
    - `ble_gap_adv_set_fields()` com mfg_data = payload.
    - `ble_gap_adv_start()` non-connectable, intervalo 20–30ms.
    - `vTaskDelay(100ms)`.
    - `ble_gap_adv_stop()` antes do próximo.
  - Final: `transport_ble_advertising_resume()` retoma o adv normal do GATT.
- Emite TLV `HACK_BLE_SPAM_DONE 0x22` ao final.

**Fluxo**:
```
App ──{"cmd":"ble_spam_apple","cycles":50}──→ ESP
ESP ──ack──→ App

  ESP pausa GATT adv
  loop ×50:
    pick random Apple payload (5 modelos)
    BLE adv mfg_data=payload  ──── ar ────→ iPhone próximo
                                              ↓
                                     popup "AirPods Pro detectados"
    sleep 100ms
  ESP retoma GATT adv
  ESP ──TLV[0x22] BLE_SPAM_DONE──→ App
```

**Limitações**: NimBLE não permite mudar nosso MAC durante uma conexão GATT
ativa — então MAC é fixo durante o spam. iOS coalesce popups por MAC, então
após alguns cycles o popup para de aparecer mesmo continuando o spam.
Workaround sério precisaria controle de adv address private resolvable
ou desconectar o app durante o spam.

---

## `ble_spam_samsung` — Samsung EasySetup popup spam

**O que faz**: gera popups de "Galaxy Buds detectados" / "smart device
nearby" em phones Samsung.

**Como funciona** (Samsung EasySetup proximity):
- Samsung phones (com app SmartThings/Galaxy Wearable) escutam BLE adv com:
  - Manufacturer Data Company ID `0x0075` (Samsung Electronics)
  - Subtype/payload identificando Galaxy Buds / Galaxy Watch
- Phone mostra popup automático com modelo detectado.

**Payload** (11 bytes): `[75 00] [01 00] [02 00] [model_3B] [01] [42]`
- `75 00`: company ID Samsung (LE)
- `01 00 02 00`: header EasySetup
- `model_3B`: identificador (Buds Live `A9 01 55`, Buds Pro `CD 01 55`, etc)
- `01 42`: trailer

**Implementação** (`hacking_ble.c`):
- 5 modelos pré-definidos. Loop async, igual `apple_spam`.
- Cada cycle pick random model + adv com mfg_data, 100ms delay.
- Final: TLV `HACK_BLE_SPAM_DONE 0x22` com `vendor=1`.

**Fluxo**: análogo ao `ble_spam_apple`, mas mfg_data Samsung.

**Limitações**: só funciona em phones Samsung com SmartThings/Galaxy
Wearable instalado e com BLE proximity habilitado. Coalesce por MAC
(NimBLE não permite mudar MAC em conexão GATT ativa) — popups param
após ~5 cycles em alvo único.

---

## `ble_spam_google` — Google Fast Pair popup spam

**O que faz**: gera popups de "Pixel Buds detectados" em Android com
Google Play Services + Fast Pair habilitado.

**Como funciona** (Google Fast Pair):
- Android escuta BLE adv com **Service Data** (não mfg_data) UUID
  `0xFE2C` (Google LLC).
- Body: 3 bytes de Model ID + payload variável (account_key, etc).
- GMS lookup do Model ID na cloud → mostra popup com nome+imagem do device.

**Adv layout** (Service Data IE):
```
[02 01 06]              ← flags
[len 0x09] [type 0x16]  ← Service Data IE header
[2C FE]                 ← UUID 0xFE2C (LE)
[3B model_id]           ← e.g. CD 82 56 = Pixel Buds A
[3B random]             ← random tail (Fast Pair v1 usa account_key bloom filter aqui)
```

NimBLE não tem campo direto pra svc_data 16-bit em `ble_hs_adv_fields`,
então usamos `ble_gap_adv_set_data(raw, len)` montando o adv packet manualmente.

**Implementação** (`hacking_ble.c`):
- 5 model IDs (Pixel Buds A, Pro, etc).
- `spam_one_cycle_svc_data()` constrói adv raw de 12 bytes.
- Final: TLV `HACK_BLE_SPAM_DONE 0x22` com `vendor=2`.

**Limitações**: só Android com Fast Pair on. Account key bloom filter
ausente (não tentamos forjar pareamento real, só popup). Random tail
muda a cada cycle, então phone vê adv "novo" sempre — mas coalesce
por MAC mesmo assim.

---

## `ble_spam_multi` — Apple + Samsung + Google aleatório por cycle

**O que faz**: cobertura máxima de vítimas com 1 só comando — cada cycle
pick random vendor (Apple/Samsung/Google) + random model dentro.

**Implementação** (`hacking_ble.c`):
- `spam_dispatch(cycles, BLE_SPAM_VENDOR_MULTI)` cria task com vendor=multi.
- Dentro do loop: `esp_random() % 3` → escolhe vendor → chama
  `run_apple_cycle / run_samsung_cycle / run_google_cycle`.
- Final: TLV `HACK_BLE_SPAM_DONE 0x22` com `vendor=0xFF`.

**Fluxo**: idêntico ao apple/samsung/google, só com vendor aleatório.

**Limitações**: como combina mfg_data (Apple/Samsung) + svc_data (Google)
e troca a cada 100ms, há chance de o phone alvo perder o popup específico
durante o ciclo. Para target dedicado a um vendor único, é melhor usar
o comando específico (`ble_spam_apple`).

---

## Roadmap de documentação

Conforme novas features forem entregues, **adicionar uma seção aqui no
mesmo commit** com o template:

```markdown
## `cmd_name` — descrição curta

**O que faz**:
**Como funciona** (camada/protocolo):
**Implementação**:
**Fluxo**:
**Limitações**:
```

Pendentes do roadmap que precisarão entrada aqui ao serem implementados:
- `arp_cut` modo throttle (forwarding com rate-limit) → precursor do MITM
- MITM pcap streaming (faixa TLV 0x40–0x4F)
- Channel hopping configurável standalone
- WiFi pcap capture
- BLE active scan / multi-vendor spam
- WPS Pixie Dust (se viável no S3)
- Defense detectors (deauth/evil twin/tracker)
- OTA via BLE
