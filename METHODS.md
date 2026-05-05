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
- [Pcap streaming (`pcap_start`)](#pcap_start--streaming-de-frames-80211-via-ble)
- [Karma attack (`karma_start`)](#karma_start--responde-probes-com-probe-response-forjado)
- [Evil Twin AP (`evil_twin_start`)](#evil_twin_start--softap-fake-com-tracking-de-clients)
- [WPS PIN test (`wps_pin_test`)](#wps_pin_test--testa-1-pin-wps-pixie-dust-blocked)
- [Captive Portal (`captive_portal_start`)](#captive_portal_start--dns-hijack--http-server)

### Phase 5 — Defense (Detection-only)
- [Defense WiFi monitor (`defense_start`)](#defense_start--detectores-deauth--beacon-flood--evil-twin--karma)
- [BLE spam detector (`ble_defense_start`)](#ble_defense_start--detector-de-ble_spam_-por-rate-de-macs-uacutenicos)
- [PMKID exposure self-audit (workflow)](#pmkid-exposure-self-audit-workflow-com-pmkid_capture)

### Phase 6 — Active counter-measures
- [Watchdog (`watchdog_start`)](#watchdog_start--gating-de-contra-acoes-com-rate-limit-e-whitelist)

### Phase 7 — Persistence
- [Profile storage NVS (`profile_save/load/list/delete`)](#profile_storage--profile_save--load--list--delete-via-nvs)

### Phase 3.5 — Macros (comandos compostos)
- [`wpa_capture_kick` / `pmkid_capture_kick` / `evil_twin_kick` / `recon_full`](#macros-phase-35--comandos-compostos)
- [Playbook engine (`playbook_run`)](#playbook_run--engine-declarativo-json)

### `pcap_start` — streaming de frames 802.11 via BLE

**O que faz**: captura frames 802.11 num canal fixo e os envia em
tempo real pro app via TLV `PCAP_FRAME` no `stream`. App gera arquivo
.pcap legível por Wireshark/tcpdump. **Sem storage local no ESP** —
frames vão direto pro app.

**Por que não armazenar no ESP**: decisão arquitetural pro futuro
MITM streaming. PSRAM tem 8MB, mas WiFi pode gerar 100+ KB/s; ringbuffer
local seria saturado em segundos. Filtrando + rate-limit + BLE notify
chega no app, e quem quiser persistir é o lado mobile (sem limite de
disco).

**Como funciona**:
- Modo promiscuous ESP-IDF (mesma infra do `probe_sniff`/`wpa_capture`).
- Filtro de hardware: `WIFI_PROMIS_FILTER_MASK_{MGMT,DATA,CTRL}` combinados
  conforme arg do app.
- Filtro adicional opcional: BSSID (frame só passa se addr1, addr2 ou
  addr3 = bssid alvo). Reduz volume drasticamente quando focando em 1 rede.
- Rate-limit interno: 5ms mínimo entre emits (200 fps teóricos = 50
  KB/s no MTU 247). Frames em excesso vão pro contador `dropped`.

**Frame TLV** (`PCAP_FRAME 0x40`, payload):
```
[0..3]  timestamp_us (uint32 BE) — relativo ao pcap_start
[4..5]  orig_len (uint16 BE) — frame original sem FCS
[6]     flags (bit0 = truncated)
[7..]   frame bytes (max 236, trunca se > 236)
```

**Implementação** (`sniff_wifi.c`, modo PCAP):
- `promisc_cb_pcap()`:
  - Verifica tipo (mgmt/data/ctrl) contra filter mask.
  - Se BSSID filter ativo, checa addr1/addr2/addr3.
  - Rate-limit por timestamp interno (`s_pcap_last_emit_us`).
  - Codifica TLV e chama `transport_ble_send_stream`.
- Task wrapper:
  - Set channel fixo, set promiscuous, esperar duration_sec ou stop.
  - Final: emit `PCAP_DONE 0x41` com emitted/dropped/elapsed_ms.

**Fluxo**:
```
App ──{"cmd":"pcap_start","channel":6,"filter":"mgmt","duration_sec":30}──→ ESP
ESP ──ack──→ App

  ESP fixa ch=6, filter=mgmt
  promisc_cb_pcap (wifi task):
    frame mgmt 0xC0 (deauth) 26B → emit TLV[0x40] (ts=12ms, len=26)
    frame mgmt 0x80 (beacon) 250B → emit TLV[0x40] (ts=15ms, len=236, TRUNC)
    frame mgmt 0x80 234ms depois → drop (5ms rate limit ainda ativo)
    ...
  fim do duration_sec
  ESP ──TLV[0x41] PCAP_DONE (emitted=8500, dropped=1200, ...)──→ App

App
  recebe TLV[0x40] sequencial
  monta arquivo .pcap (LINKTYPE_IEEE802_11=105):
    pcap global header (24B) + 
    pra cada frame: ts(4) + ts_us(4) + caplen(4) + origlen(4) + frame
  Wireshark/tcpdump abre direto.
```

**Filtros disponíveis** (string no comando):
- `"mgmt"` — só management (beacons, probes, deauth, assoc, auth)
- `"data"` — só data frames
- `"ctrl"` — só control (RTS, CTS, ACK)
- `"all"` — todos
- `"mgmt+data"` etc — combinações via substring

**Limitações**:
- Frame > 236B truncado (BLE MTU 247 - tlv_hdr 4 - pcap_hdr 7 = 236).
  Pcap aceita caplen != origlen, então Wireshark mostra clipped — útil
  pra mgmt frames (têm headers + IEs interessantes nos primeiros 200B);
  problemático pra payload de data frames.
- Rate-limit 5ms = ~200 fps. Em rede ocupada, dropados >> emitidos.
  Solução: filtrar mais agressivo (mgmt apenas + bssid específico).
- Channel fixo (sem hop). Pra hop, app pode chamar pcap_stop+start em
  sequência mudando channel.
- timestamp_us rolls over após ~71 min (uint32 µs). Pra captures longas,
  timestamp absoluto teria que ser uint64 — fica futuro.
- Sem storage local: se app desconecta no meio, frames perdidos.

**Cenários de uso**:
- Análise de mgmt traffic (probe behavior de devices nearby)
- Captura de deauth attacks (combinar com `deauth_detect` futuro)
- MITM streaming (depois com `arp_cut` + filtro em data IP) — esta API
  é o substrato.

---

## `karma_start` — responde probes com probe response forjado

**O que faz**: cliente cuja PNL (Preferred Network List) tem SSIDs salvos
manda probe req `"FreeWifi"`/`"Starbucks"`/etc procurando re-conectar.
ESP escuta esses probes e **responde imediatamente** com probe response
fingindo ser um AP daquele SSID. Cliente acha que achou e tenta associar
— foi karma'd.

Original Karma attack (Cache da Hak5 Pineapple): mesmo princípio.

**Como funciona** (802.11 mgmt):
- Probe Request (subtype 0x4): cliente broadcast (addr1=ff:ff..) com
  SSID-IE preenchido pedindo SSID específico (vs broadcast com ssid_len=0
  pedindo "qualquer um").
- Probe Response (subtype 0x5): AP responde com mesmo formato de Beacon
  (timestamp + interval + capability + IEs) endereçado AO probe issuer
  (addr1 = source do probe req).

**Implementação** (`sniff_wifi.c`, modo KARMA):
- Promisc filter MGMT.
- promisc_cb_karma:
  - Filtra FC byte 0 = 0x40 (probe req).
  - Extrai source MAC + SSID IE.
  - **Skip wildcard** (ssid_len = 0) — só responde direcionados pra evitar
    spam.
  - Chama `send_probe_response(client_mac, ssid, ssid_len, channel)`.
  - Track unique (mac, ssid) em buffer estático cap 128. Se par novo,
    emite TLV `KARMA_HIT 0x24` e incrementa unique counters.
- send_probe_response():
  - BSSID forjado: FNV-1a hash(ssid) + prefix `0x02` (locally administered).
    Cada SSID tem BSSID determinístico — cliente pode até cachear.
  - Frame Probe Response montado igual ao beacon, com FC `0x50 0x00`,
    addr1 = client_mac.
  - IEs: SSID + Supported Rates + DS Param + ERP + Extended Rates.
  - `esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false)`.
- Final: TLV `KARMA_DONE 0x25` (hits, unique clients, unique ssids, elapsed).

**Fluxo**:
```
App ──{"cmd":"karma_start","channel":6}──→ ESP
ESP ──ack──→ App

  ESP fixa ch=6, promiscuous=on
  (cliente próximo procura "MeuWifi" da PNL)
  Cliente ──probe req SSID="MeuWifi"──→ ar
  ESP promisc_cb captura
  ESP ──probe resp SSID="MeuWifi" BSSID=02:hash(...)──→ Cliente
  ESP ──TLV[0x24] KARMA_HIT (mac, "MeuWifi")──→ App

  (cliente tenta associar — auth/assoc — mas ESP não está em AP mode,
   então a associação falha. Pra concluir o ataque seria necessário
   evil twin ou softAP — não nesta feature.)

  fim do duration_sec
  ESP ──TLV[0x25] KARMA_DONE (hits=42, clients=3, ssids=18, ...)──→ App
```

**Limitações**:
- ESP não está em modo AP — então mesmo respondendo o probe, a
  associação subsequente do cliente vai falhar. Karma puro funciona
  como **recon** (revela PNL completa de devices nearby).
- Para concluir associação + DHCP + captive portal, combinar com
  Evil Twin (próxima feature) que sobe softAP de verdade.
- Probe response forjado pode bater com outros APs reais — race condition.
- Wildcard probes ignorados pra evitar spam.
- Cap 128 unique pairs.
- Channel fixo (sem hop) — único canal por sessão.

**Cenário de uso**:
- Mapear preferred networks de devices nearby (privacy reveal).
- Pré-passo pra Evil Twin: descobrir quais SSIDs spoofar.
- Pesquisa de segurança em redes próprias.

---

## `evil_twin_start` — SoftAP fake com tracking de clients

**O que faz**: o ESP sobe um Access Point real com SSID/canal/senha
escolhidos pelo app. Devices na vizinhança que conhecem aquele SSID
(ex: descoberto via `karma_start` antes) podem associar achando que é
o legítimo. ESP emite TLV pra cada associação/desassociação — base pra
captive portal e MITM em rede do atacante.

**Como funciona** (802.11 SoftAP):
- Modo `WIFI_MODE_APSTA`: rádio fica simultaneamente em STA (pra scan/promisc
  funcionarem) **e** AP (anunciando beacons + aceitando assoc).
- ESP-IDF `esp_netif_create_default_wifi_ap()` instancia netif com IP
  192.168.4.1/24 e DHCP server **automático** que atribui leases na
  range 192.168.4.2..N.
- `wifi_config_t.ap.{ssid, password, channel, max_connection, authmode}`
  configura o AP.
- Eventos `WIFI_EVENT_AP_STACONNECTED` / `STADISCONNECTED` disparam
  callbacks com MAC + AID (assoc id) / reason code.

**Implementação** (`evil_twin.c`):
- `evil_twin_init()` registra handler genérico `WIFI_EVENT, ESP_EVENT_ANY_ID`.
  Filtra pelos 2 IDs de interesse e emite TLVs.
- `evil_twin_start(ssid, psk, channel, max_conn)`:
  - Validações: SSID 1–32 chars, PSK 8–63 ou NULL/"" (open), channel 1–13.
  - `esp_netif_create_default_wifi_ap()` lazily na primeira call.
  - `esp_wifi_set_mode(APSTA)`.
  - `esp_wifi_set_config(AP, &cfg)` com WPA2_PSK ou OPEN.
  - PMF capable (não required) pra compat com clients que pedem MFP.
- `evil_twin_stop()`: volta pra `WIFI_MODE_STA` — beacon do AP para,
  clients reconectados ao AP perdem a associação.

**Fluxo**:
```
App ──{"cmd":"evil_twin_start","ssid":"FreeWifi","channel":6,"password":""}──→ ESP
ESP ──{"resp":"evil_twin_start","status":"started","ssid":"FreeWifi",...}──→ App

  ESP entra em APSTA, beacon "FreeWifi" no ch=6
  cliente próximo (que tem "FreeWifi" salvo) associa:
    auth + assoc + (4-way handshake se WPA2)
    DHCP request → ESP responde com 192.168.4.X
  WIFI_EVENT_AP_STACONNECTED dispara
  ESP ──TLV[0x26] EVIL_CLIENT_JOIN (mac, aid)──→ App
  
  cliente sai (out of range / explicit disconnect)
  WIFI_EVENT_AP_STADISCONNECTED
  ESP ──TLV[0x27] EVIL_CLIENT_LEAVE (mac, reason)──→ App

App ──{"cmd":"evil_twin_stop","seq":2}──→ ESP
ESP volta pra WIFI_MODE_STA, AP some
```

**Combinação com outros métodos**:
- `karma_start` antes pra mapear PNL e descobrir SSIDs preferidos
- `deauth` em paralelo pro AP legítimo, forçando clients a re-tentarem
  (e pegando o nosso fake)
- `pcap_start` no mesmo canal pra capturar tráfego do client associado
- (futuro) captive portal pra interceptar credenciais HTTP

**Limitações**:
- ESP suporta no máx ~10 clients simultâneos (limite SoftAP do IDF).
- Sem captive portal nesta versão: cliente associa, recebe IP, mas
  não tem internet/redirecionamento. Vamos adicionar DNS hijack +
  HTTP server numa próxima feature.
- WPA3 não suportado no SoftAP (hoje só OPEN ou WPA2-PSK).
- Modo APSTA tem trade-offs: rádio dividido entre AP beacon e qualquer
  scan ativo do STA — pode ter clients reportando RSSI inferior.

---

## `wps_pin_test` — testa 1 PIN WPS (Pixie Dust blocked)

**O que faz**: tenta autenticar contra um AP via WPS PIN (modo enrollee).
Se PIN é válido + AP responde, ESP recupera SSID + PSK. Single-shot —
1 PIN por chamada. Base pra brute-force lado-app ou validação de PIN
descoberto externamente (via pixiewps).

**Sobre Pixie Dust** (importante!):

Pixie Dust ataca o WPS PIN offline explorando RNG fraca de muitos APs:
captura M1+M2 do handshake e calcula o PIN sem mais round-trips com o AP.
Para fazer isso no ESP32 precisaríamos extrair os campos crus do M2
(PKr = chave pública DH do registrar, N1 = nonce, E-Hash1, E-Hash2).

**Limitação técnica do ESP-IDF 5.4**: a API pública (`esp_wps.h`) só
expõe enable/start/disable e eventos high-level (success com PSK,
failed com reason, timeout). Os campos crus do M2 ficam internos no
`wpa_supplicant/src/wps/` — sem callback público pra extrair. Patchear
o IDF é frágil (quebra updates).

**Workaround pra Pixie Dust offline**:
1. Sniffar a troca WPS entre o AP alvo e algum cliente legítimo:
   `pcap_start --channel X --filter data --bssid AA:BB:CC:...`
2. Salvar o pcap (já feito pelo nosso `pcap_test.py`).
3. Extrair os frames EAP-WPS (M1, M2, etc) com Wireshark ou tshark.
4. Rodar `pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <auth_key> -n <N1>`
   pra computar o PIN.
5. Validar com `wps_pin_test --bssid ... --pin XXXXXXXX`.

**Como funciona** (`wps_pin_test` em si):
- IDF supplicant: `esp_wifi_wps_enable(WPS_TYPE_PIN, pin)` + `esp_wifi_wps_start(0)`.
- Internamente faz: scan/find o AP do BSSID alvo, `EAPOL-Start`, troca
  M1..M8 do WPS state machine, e em sucesso recebe credenciais.
- Eventos relevantes:
  - `WIFI_EVENT_STA_WPS_ER_SUCCESS`: payload tem `ap_cred[]` com SSID+passphrase.
  - `WIFI_EVENT_STA_WPS_ER_FAILED`: reason = NORMAL / M2D (PIN inválido) / DEAUTH.
  - `WIFI_EVENT_STA_WPS_ER_TIMEOUT`: AP não respondeu.
  - `WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP`: AP está em PBC com múltiplos requests.

**Implementação** (`hacking_wifi.c`):
- Async via task. Cria `EventGroupHandle_t` pra sinalizar quando
  qualquer um dos 4 eventos chega.
- Registra handler pra `WIFI_EVENT, ESP_EVENT_ANY_ID`, captura o ID +
  payload do evento WPS, seta o bit do event group.
- Task aguarda com `xEventGroupWaitBits` (timeout = `timeout_sec * 1000ms`).
- Quando bit setado: lê `s_wps_event_id` + payloads, monta TLV
  `WPS_TEST_DONE 0x2C` (status + ssid + psk se sucesso, fail_reason se falhou).
- `esp_wifi_wps_disable()` no cleanup. Unregister handler.

**Fluxo**:
```
App ──{"cmd":"wps_pin_test","bssid":"AA:BB:..","pin":"12345670"}──→ ESP
ESP ──ack──→ App

  ESP: esp_wifi_wps_enable(PIN="12345670") + wps_start
  ESP ↔ AP: EAP-WPS handshake (M1..M8) sob o supplicant da IDF
  
  Caso 1 — PIN válido:
    AP responde com credenciais (SSID + PSK)
    WIFI_EVENT_STA_WPS_ER_SUCCESS dispara
    ESP ──TLV[0x2C] WPS_TEST_DONE (status=0, ssid="...", psk="...")──→ App
  
  Caso 2 — PIN inválido:
    AP responde M2D (Method-2 with Diagnostic = "PIN errado")
    WIFI_EVENT_STA_WPS_ER_FAILED reason=M2D
    ESP ──TLV[0x2C] WPS_TEST_DONE (status=1, fail_reason=1)──→ App
  
  Caso 3 — AP não responde:
    WIFI_EVENT_STA_WPS_ER_TIMEOUT
    ESP ──TLV[0x2C] WPS_TEST_DONE (status=2)──→ App

  ESP: wps_disable, libera supplicant
```

**Limitações**:
- 1 PIN por chamada — brute-force precisa loop lado-app (~3s por tentativa).
- APs modernos lockam após N falhas (3..10) por X minutos. App deve
  detectar M2D recorrente e backoff.
- Pixie Dust offline: NÃO funciona com este firmware diretamente.
  Workaround acima.
- WPS PBC mode (botão físico) não testado — implementação atual usa
  só PIN.

**Combinação com outros métodos**:
- `wifi_scan` antes pra descobrir BSSIDs com flag WPS=1 (já temos)
- `pcap_start` em paralelo capturando o handshake completo pra
  análise + Pixie Dust offline depois

---

## `captive_portal_start` — DNS hijack + HTTP server

**O que faz**: complementa o `evil_twin`. Sobe 2 servidores em userspace:
- **UDP:53 (DNS)**: responde QUALQUER query com `redirect_ip` (default
  192.168.4.1, IP do AP do ESP). Resultado: cliente acessa
  `apple.com`/`google.com`/qualquer-coisa → resolve pro ESP.
- **TCP:80 (HTTP)**: aceita conexões e serve uma página HTML
  configurável (default = formulário simples "Sign in to FreeWifi").
  Cada request emite TLV com método + path + body chunk → app captura
  credenciais de POST forms.

**Como funciona** (DNS):
- DHCP server da IDF (já ativo via `evil_twin`) configura o cliente com
  ESP como gateway + DNS server (192.168.4.1).
- Cliente faz query → chega na nossa task UDP:53.
- Parseia o nome da query (formato 802.11 com labels), emite TLV
  `PORTAL_DNS_QUERY 0x2D` (src_ip + domain).
- Constrói resposta DNS standard: copia header com QR=1, AA=1, RA=1,
  ANCOUNT=1; mantém question; appende answer com:
  - Compressed name pointer (`0xC0 0x0C` = "ver no offset 12 da question")
  - TYPE=A (1) + CLASS=IN (1) + TTL=60s + RDLENGTH=4 + IP de redireção.
- Sendto de volta. Cliente vê: `apple.com → 192.168.4.1`.

**Como funciona** (HTTP):
- Listen TCP:80. Accept loop com socket timeout de 1s pra evitar slowloris.
- Lê request até `\r\n\r\n` ou buffer cheio (1KB).
- Tenta ler mais 130 bytes de body (POST forms grandes).
- Parse: `METHOD PATH HTTP/x.x` na primeira linha; body após `\r\n\r\n`.
- Emite TLV `PORTAL_HTTP_REQ 0x2E` (src_ip + method + path + body).
- Resposta: `200 OK` + Content-Type html + HTML configurável.

**Captive Portal Detection** (auto-trigger nos 3 OS principais):
- iOS: `GET http://captive.apple.com/hotspot-detect.html` → espera body
  literal "Success". Como devolvemos HTML diferente, iOS abre a página
  em popup automático.
- Android: `GET http://connectivitycheck.gstatic.com/generate_204` →
  espera 204 No Content. Devolvemos 200 com HTML, Android mostra "Sign in
  to network".
- Windows: `GET http://www.msftconnecttest.com/connecttest.txt` → espera
  "Microsoft Connect Test". Idem, dispara popup.

Não precisamos casos especiais — qualquer resposta != esperada serve.

**Implementação** (`captive_portal.c`):
- 2 FreeRTOS tasks: `dns_task` (4 KB stack) + `http_task` (6 KB stack).
- Sockets lwIP via `lwip/sockets.h` (BSD-style).
- HTML armazenado em buffer `malloc`'d (cap 32 KB), liberado em `_stop`.
- `_stop` faz `shutdown(sock, SHUT_RDWR)` em ambos pra desbloquear
  `recvfrom`/`accept`, depois aguarda tasks se auto-deletarem.

**Fluxo**:
```
App ──{"cmd":"evil_twin_start","ssid":"FreeWifi","channel":6}──→ ESP
ESP ──ack started──→ App
App ──{"cmd":"captive_portal_start"}──→ ESP
ESP ──ack started──→ App

  ESP roda dns_task + http_task em paralelo.

  cliente associa no AP, recebe IP via DHCP (192.168.4.X)
  cliente: DNS query "apple.com"  ─UDP:53─→ ESP
  ESP responde "192.168.4.1"; emite TLV[0x2D] DNS_QUERY (src, "apple.com")
  
  iOS dispara captive popup
  cliente: GET http://captive.apple.com/hotspot-detect.html ─TCP:80─→ ESP
  ESP serve HTML; emite TLV[0x2E] HTTP_REQ
  
  usuário preenche e dá submit
  cliente: POST /login  body=username=lucas&password=hunter2 ─TCP:80─→ ESP
  ESP serve HTML; emite TLV[0x2E] HTTP_REQ (com body=username=...&password=...)
  App parseia → grava credenciais.
```

**Limitações**:
- Sem HTTPS (port 443). Apps que tentam HTTPS pra `apple.com` etc
  veem certificate mismatch e abortam — não capturamos credenciais
  HTTPS. Pra HTTPS-MITM precisaria CA fake instalada no client (out of
  scope).
- HTML cap 32 KB.
- Body chunk truncado em 130 bytes (BLE MTU 247 - overhead). Suficiente
  pra forms de login típicos (~50–80 bytes).
- 1 conexão HTTP por vez (sem pool). Tudo bem pra captive portal —
  fluxo é sequencial.
- Slowloris parcial mitigado por timeout 1s no recv. Nada robusto.

**Combinação natural**:
- `evil_twin_start(ssid)` + `captive_portal_start(html)` — twin + portal.
- Em paralelo: `deauth(legit_bssid)` força clientes a migrarem.

---

## `defense_start` — detectores deauth / beacon flood / evil twin / karma

**O que faz**: monitor passivo (promiscuous mgmt) que roda 4 detectores
em paralelo via bitmask:

| Bit | Detector | Heurística | TLV emitido |
|---|---|---|---|
| 0 | Deauth storm | ≥ 5 frames deauth/disassoc por segundo | `0x30 DEFENSE_DEAUTH` |
| 1 | Beacon flood | ≥ 20 BSSIDs únicos por segundo | `0x31 DEFENSE_BEACON_FLOOD` |
| 2 | Evil twin | mesmo SSID com 2 BSSIDs distintos | `0x32 DEFENSE_EVIL_TWIN` |
| 3 | Karma / Pineapple | beacon/probe response com BSSID locally-administered (bit `0x02` no byte 0) | `0x33 DEFENSE_KARMA` |

Cooldown global de 3s por tipo de alerta — evita inundar o app durante
um ataque ativo.

**Como funciona** (heurísticas):

- **Deauth storm**: contador per-segundo. Ambient normal: 0 deauths.
  Mais que ~5/s indica ataque ou misconfiguração. Real-world tools
  (mdk4, aireplay-ng) emitem 50–200/s.
- **Beacon flood**: contador de BSSIDs únicos com set de 64 entries
  resetado a cada janela. Ambient: 5–15 APs. > 20 indica flood
  (nosso `beacon_flood` cospe ~30+).
- **Evil twin**: tabela SSID→{primeiro BSSID, segundo BSSID se ≠ primeiro}.
  Quando vê o 2º distinto pra um SSID, alerta. Funciona ambivalentemente
  (legítimo: AP roaming entre 2 rádios; suspeito: nosso `evil_twin` ou
  outro fake). App pode filtrar por OUI / locally-admin.
- **Karma / Pineapple**: BSSID com bit `0x02` setado no byte 0 (locally
  administered) é forte indício de BSSID fake. Roteadores reais usam
  OUI da IEEE (bit limpo). Hak5 Pineapple e nosso `karma_make_bssid`
  ambos usam locally-admin → detectados.

**Implementação** (`sniff_wifi.c`, modo DEFENSE):
- Promisc filter MGMT.
- promisc_cb_defense:
  - FC 0xC0/0xA0 → incrementa deauth counter.
  - FC 0x80/0x50 → incrementa beacon counter, parse SSID, atualiza
    tabelas evil_twin/karma. Locally-admin check inline.
- Controller task com sleep 200ms. A cada 1000ms acumulado:
  - Checa thresholds → emit alerts (com cooldown 3s).
  - Reseta janelas (deauth_count, beacon_count, bssid set).
- Channel hop opcional: `channel=0` + `ch_min..ch_max` + `dwell_ms`.
  Útil pra cobertura full 2.4GHz; trade-off é perder eventos no canal
  ativo enquanto está em outros.
- Final: TLV `DEFENSE_DONE 0x34` com counters totais + alerts emitidos.

**Fluxo**:
```
App ──{"cmd":"defense_start","mask":15,"channel":0,"duration_sec":300}──→ ESP
ESP ──ack started──→ App

  promisc_cb (continuamente):
    deauth (0xC0) → contador++
    beacon (0x80) com SSID="..." e BSSID locally-admin → emit DEFENSE_KARMA
    beacon SSID="X" BSSID=AA:.. → tabela["X"]={a:AA:..}
    beacon SSID="X" BSSID=BB:.. → tabela["X"]={b:BB:..} → emit DEFENSE_EVIL_TWIN
  
  controller_task (a cada 1s):
    if deauth_count >= 5: emit DEFENSE_DEAUTH (cooldown 3s)
    if unique_bssids >= 20: emit DEFENSE_BEACON_FLOOD
    reset janelas
  
  fim do duration_sec
  ESP ──TLV[0x34] DEFENSE_DONE (alerts=N, totals)──→ App
```

**Limitações**:
- Heurísticas simples (thresholds fixos). Cenários edge:
  - Locais com muitos APs reais (aeroportos, conferências): falso-positivo
    de beacon_flood.
  - Roaming agressivo (campus WiFi com mesmo SSID em 50 APs): falso-positivo
    de evil_twin → vai disparar uma vez (cooldown evita spam).
  - Karma: alguns devices IoT usam locally-admin mesmo sendo legítimos
    (ex: ESP32 dev boards, smart bulbs). Falso-positivo aceitável.
- DEAUTH alert atualmente reporta BSSID `ff:ff:..` (broadcast). Versão
  futura pode discriminar quem está sendo deauth'd.
- Detector é silencioso se ataque dura < 1s (precisa cruzar janela).
- Channel hop perde eventos no canal não-ativo durante o dwell.

**Combinação com outros métodos**:
- Em paralelo com `pcap_start` em outro canal? **Não** — sniff_wifi
  é singleton. Pra captura + detecção, escolher um. Ou rodar em
  pares de invocações.

---

## `ble_defense_start` — detector de `ble_spam_*` por rate de MACs únicos

**O que faz**: detecta ataques de BLE spam (popups Apple/Samsung/Google
proximity pairing) baseando-se em **rate de MACs únicos broadcasting a
mesma assinatura vendor** numa janela de 1 segundo.

**Como funciona**:
- Real iPhone / Galaxy Buds / Pixel Buds usa MAC estável (random
  resolvable, mas com baixa rotação).
- `ble_spam_apple/samsung/google/multi` rotaciona MAC a cada cycle
  (~100ms) → > 10 MACs únicos/s broadcasting subtype 0x07 Apple.
- Threshold 6 MACs únicos/s por vendor com cooldown 3s separa o sinal
  do ruído ambiente (ambient real: 0–2 MACs/s broadcasting Apple
  Continuity proximity; ataque: 8–15+).

**Assinaturas detectadas** (mesmas que nosso `hacking_ble.c` emite):

| Vendor | Sinal procurado |
|---|---|
| Apple (0) | mfg_data primeiros bytes: `4C 00 07 19` (Apple + subtype Proximity Pairing + length 25) |
| Samsung (1) | mfg_data primeiros bytes: `75 00 01 00 02 00` (Samsung + EasySetup header) |
| Google (2) | svc_data UUID 16-bit `0xFE2C` (Fast Pair) |

**Implementação** (`scan_ble.c`):
- Roda passive `ble_gap_disc` continuamente (mesmo path que `ble_scan` mas
  com `s_defense_mode = true`).
- `gap_disc_event_cb` em modo defense:
  - Parse fields normalmente.
  - `classify_spam_signature()` retorna 0/1/2 ou -1.
  - Se ≥ 0, adiciona MAC ao set `s_spam_macs[vendor]` (cap 32, dedup linear).
  - Não emite `BLE_SCAN_DEV` neste modo (só TLVs de defense).
- Task `defense_check_task`: sleep 200ms; a cada 1s acumulado checa
  `s_spam_count[v]` ≥ threshold → emit `DEFENSE_BLE_SPAM 0x35` (com
  cooldown 3s) e reseta contadores.
- Stop via `s_defense_stop_requested` ou deadline.

**Fluxo**:
```
App ──{"cmd":"ble_defense_start","duration_sec":300}──→ ESP
ESP ──ack started──→ App

  promisc/scan loop captura advs:
    iPhone real (Continuity 0x10 handoff) — não classify, ignorado
    spam Apple do atacante (Continuity 0x07 proximity) — classify=0
      → adiciona MAC ao set (vendor=Apple)
    spam novamente com MAC2 — adiciona
    ... 6 MACs únicos em 800ms
  
  defense_check_task (a cada 1s):
    s_spam_count[Apple] = 8 >= 6 (threshold)
    cooldown OK
    ESP ──TLV[0x35] DEFENSE_BLE_SPAM (vendor=0, unique_macs=8, window_ms=1000)──→ App
    reset s_spam_count
  
  fim duration_sec
  ble_gap_disc_cancel + emit BLE_SCAN_DONE 0x13
```

**Limitações**:
- Falso-positivo possível em locais com muitos AirPods reais broadcasting
  ao mesmo tempo (≥ 6 distintos no raio). Cooldown reduz spam de alerta.
- Falso-negativo: spam com MAC fixo (caso extremo do nosso `apple_spam`
  quando GATT está conectado e NimBLE não permite mudar MAC) escapa do
  detector — rate de MACs únicos é só 1.
- Detection scope = só Apple/Samsung/Google. Outros spammers (Tile, Microsoft
  Surface) não cobertos.
- Mutex com `ble_scan` regular (mesmo `s_busy`). Pode rodar 1 OU outro.

**Combinação natural**:
- `defense_start` (WiFi) + `ble_defense_start` (BLE) em paralelo →
  monitor full-stack 24/7. Rádios independentes, sem conflito.

---

## PMKID exposure self-audit (workflow com `pmkid_capture`)

**O que faz**: confirma se a sua própria rede WPA2 é vulnerável a
ataque PMKID offline (sem cliente). Não é feature firmware nova — é
um padrão de uso da primitiva `pmkid_capture` apontada pra própria rede.

**Workflow**:

```bash
# 1. Garante que ESP NÃO está conectado (pra promisc + canal fixo)
echo '{"cmd":"wifi_disconnect","seq":1}' | scripts/ble_test.py

# 2. Roda scan pra confirmar BSSID + canal da sua rede
scripts/ble_test.py  # mostra wifi_scan; anote BSSID + channel da sua rede

# 3. Dispara pmkid_capture apontado pra ela
scripts/pmkid_capture_test.py \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 \
    --essid "MinhaCasa" --duration 60

# 4. Em paralelo (outra shell), força associação de algum cliente
#    (deauth burst no broadcast)
scripts/deauth_test.py \
    --bssid AA:BB:CC:DD:EE:FF --channel 6 --count 30
```

**Interpretação**:
- Se `pmkid.hc22000` foi gerado (PMKID encontrado): seu AP **expõe** PMKID
  KDE no M1 → vulnerável a brute-force offline. Mitigação: desabilitar
  WPS no roteador, ou trocar por WPA3.
- Se nenhum PMKID após 60s + deauth: AP não expõe PMKID. Não-vulnerável a
  esse vetor (mas pode ser a outros).

Por que **não** virou comando firmware:
- Sequência depende de timing (deauth pra forçar handshake) que app/script
  controlam melhor.
- `pmkid_capture` exige NOT connected — não dá pra encadear `wifi_connect`
  + `pmkid_capture` direto.
- Ferramentas hashcat/aircrack-ng do lado-app já cobrem o restante do
  audit (cracking).

Marcado no roadmap como "covered by `pmkid_capture` + workflow doc".

---

## `watchdog_start` — gating de contra-ações com rate-limit e whitelist

**O que faz**: ativa modo "active defense". Quando os detectores
(`defense_start` / `ble_defense_start`) já em execução cruzam threshold,
o watchdog dispara contra-ações automáticas:

- **anti_evil_twin** (bit 0): quando `DEFENSE_EVIL_TWIN` alerta, fire
  `deauth(broadcast)` no BSSID identificado como twin.
- **ble_spam_jam** (bit 1): quando `DEFENSE_BLE_SPAM` alerta, fire
  `ble_adv_flood(5s)` pra congestar o canal BLE.

**Anti-deauth NÃO implementado** (motivo): atacantes spoofam o `addr2`
(source) do frame deauth como sendo o AP legítimo. Direcionar contra-deauth
ao "atacante" significaria deauth no AP legítimo — não-funcional. Mitigação
real exige triangulação RF / fingerprint de hardware, fora do escopo
prático aqui. Detecção segue funcionando via `defense_start`; só não há
contra-ação automática.

**Heurística de "qual é o twin"** (anti_evil_twin):
- Dos 2 BSSIDs reportados pra mesmo SSID:
  - Se um tem bit `0x02` (locally-administered) e outro não → o LA é o twin.
  - Senão, o de menor RSSI (mais distante, mais provável fake).

**Salvaguardas**:
- **Whitelist**: array de BSSIDs (max 16) que nunca são alvo. Use pra
  proteger seus próprios APs em modo evil_twin de teste.
- **Cooldown_ms**: tempo mínimo entre 2 contra-ações do mesmo tipo
  (default 10s). Evita feedback loops com detector pegando nossa própria
  contra-ação.
- **max_actions**: cap total de contra-ações na sessão (default 5). Pra
  watchdog rodando 24/7, evita escalada infinita em caso de detector
  com falso-positivo persistente.

**Implementação** (`watchdog.c` + hooks):
- Componente `watchdog` mantém estado global (`s_active` flag, mask,
  whitelist, contadores).
- Hooks **weak**:
  - `watchdog_hook_evil_twin(bssid_a, rssi_a, bssid_b, rssi_b, channel)`
    declarado weak em `sniff_wifi.c` (no-op se watchdog component não
    linkado). Strong em `watchdog.c`.
  - `watchdog_hook_ble_spam(vendor)` análogo em `scan_ble.c`.
- Quando alerta cruza threshold, detector chama o hook. Watchdog:
  1. Checa `s_active` (no-op se desligado)
  2. Checa `actions & ACTION_X` (skip se ação não habilitada)
  3. Checa whitelist → bump `blocked_whitelist`, return
  4. Checa cooldown + max → bump contador correspondente, return
  5. Dispara contra-ação async via `hacking_wifi_deauth` ou
     `hacking_ble_adv_flood` (já são tasks)
  6. Emite TLV `WATCHDOG_ACTION 0x37` com action_id + target_bssid + status

**Fluxo full**:
```
App ──{"cmd":"defense_start","mask":15}──→ ESP                (detectores rodando)
App ──{"cmd":"ble_defense_start","duration_sec":3600}──→ ESP  (BLE detector rodando)
App ──{"cmd":"watchdog_start","actions":3,"whitelist":["AA:BB:CC:..."]}──→ ESP

  defense (sniff_wifi) detecta evil_twin → emit TLV[0x32]
                        → call watchdog_hook_evil_twin(...)
                        → watchdog: BSSID não na whitelist, cooldown OK
                        → call hacking_wifi_deauth(broadcast, twin_bssid, ch, 30)
                        → emit TLV[0x37] WATCHDOG_ACTION action=1
  
  scan_ble detecta BLE spam → emit TLV[0x35]
                        → call watchdog_hook_ble_spam(vendor)
                        → watchdog: cooldown OK, max não atingido
                        → call hacking_ble_adv_flood(5s)
                        → emit TLV[0x37] WATCHDOG_ACTION action=2
  
  ... (mais alertas, alguns blocked por cooldown/whitelist)
  
App ──{"cmd":"watchdog_stop"}──→ ESP
ESP ──TLV[0x38] WATCHDOG_DONE (fired=N, blocked_wl=N, blocked_cd=N, blocked_cap=N)──→ App
```

**Combinação obrigatória**:
- watchdog SOZINHO não faz nada — precisa que `defense_start` e/ou
  `ble_defense_start` estejam rodando. Caso contrário, sem alertas → sem
  hooks → sem contra-ações.
- App ou playbook (Phase 3.5) deve orquestrar a sequência:
  ```
  defense_start → ble_defense_start → watchdog_start
  ```

**Limitações**:
- Anti-deauth ausente (já discutido).
- Watchdog é global (1 instância por boot). Múltiplos perfis de defesa
  exigiriam stop+start.
- Whitelist suporta só BSSIDs WiFi; pra BLE spam, vendor é único alvo
  (não MAC-specific).
- Falso-positivo no detector → contra-ação errada. Use `cooldown` agressivo
  + `max_actions` baixo em ambientes desconhecidos.

---

## profile_storage — `profile_save / load / list / delete` via NVS

**O que faz**: storage persistente de profiles JSON nomeados na partição
NVS do ESP. Profiles sobrevivem reboots — útil pra:
- Salvar configs de defesa específicas (ex: profile "modo casa" com
  whitelist do AP doméstico, watchdog mask específico).
- Pré-popular workflows (ex: profile "kit recon" com lista de SSIDs/canais
  pra rotina de auditoria).
- Futuro: playbook engine (Phase 3.5) recall profiles automaticamente.

Firmware trata o conteúdo como **opaco** — não interpreta o JSON. App é
responsável pelo schema do que vai dentro.

**Como funciona** (NVS):
- ESP-IDF NVS = partition `nvs` (4 KB típico) com namespace key-value.
- Componente `persist` usa namespace `"wifiutils"`.
- Keys = profile names (max 14 chars, ASCII printable sem espaço).
- Values = blob (até 1024 bytes por profile).
- ~50–100 profiles cabem antes da partition encher (depende do tamanho).

**Comandos**:
- **profile_save(name, data)**: `nvs_set_blob(name, data, len)` + commit.
- **profile_load(name)**: `nvs_get_blob` + emite TLV `PROFILE_DATA 0x39`
  no stream (conteúdo pode ser >240B → truncado em 1 frame; futuro
  fragmenta).
- **profile_delete(name)**: `nvs_erase_key`.
- **profile_list**: itera entries do namespace via `nvs_entry_find` /
  `nvs_entry_next`. Emite N×`PROFILE_LIST_ITEM 0x3A` + 1×`PROFILE_LIST_DONE 0x3B`.

**Implementação** (`persist.c`):
- `persist_init()`: tenta abrir o namespace pra confirmar (NVS é
  inicializado pelo `transport_ble`).
- `name_valid()`: 1..14 chars, ASCII printable.
- Outras funções: wrappers triviais sobre nvs_*.

**Fluxo**:
```
App ──{"cmd":"profile_save","name":"casa","data":"{\"defense_mask\":15,\"whitelist\":[\"AA:..\"]}"}──→ ESP
ESP ──{"resp":"profile_save","status":"saved","name":"casa","bytes":47}──→ App

  reboot do ESP — profile permanece no NVS

App ──{"cmd":"profile_load","name":"casa"}──→ ESP
ESP ──{"resp":"profile_load","status":"started"}──→ App  (ack)
ESP ──TLV[0x39] PROFILE_DATA (name="casa", data="{\"defense_mask\":...}")──→ App

App ──{"cmd":"profile_list"}──→ ESP
ESP ──ack──→ App
ESP ──TLV[0x3A] PROFILE_LIST_ITEM "casa"──→ App
ESP ──TLV[0x3A] PROFILE_LIST_ITEM "lab"──→ App
ESP ──TLV[0x3A] PROFILE_LIST_ITEM "aula"──→ App
ESP ──TLV[0x3B] PROFILE_LIST_DONE (count=3)──→ App

App ──{"cmd":"profile_delete","name":"casa"}──→ ESP
ESP ──{"resp":"profile_delete","status":"deleted","name":"casa"}──→ App
```

**Limitações**:
- 14 chars max no nome (limite key NVS = 15 com NUL).
- 1024 bytes max por profile.
- Sem fragmentação na entrega — profiles maiores que 240B são truncados
  no `PROFILE_DATA` (frame único). Versão futura fragmenta.
- NVS partition de 4 KB tem espaço pra ~50 profiles small. Aumentar
  partition em `partitions.csv` se precisar de mais.
- Conteúdo opaco pro firmware → erros de schema só são detectados pelo
  app/playbook que consome.

**Combinação natural**:
- Pre-Phase 3.5: app envia profile pelo `profile_save`, depois recall
  pelo `profile_load` antes de enviar comandos individuais.
- Phase 3.5 (playbook): app salva playbook JSON via `profile_save`;
  comando `playbook_run` futuro vai aceitar arg `profile=name` pra
  carregar e executar diretamente do NVS sem app conectado.

---

## Macros Phase 3.5 — comandos compostos

**O que faz**: 4 comandos novos que orquestram 2+ primitivas existentes
internamente. App envia 1 só comando → firmware roda a sequência.
Cada macro reusa os TLVs das primitivas (não há TLVs novos).

**Padrão de implementação**: handler do comando faz `vTaskDelay(150ms)`
entre os 2 starts pra promiscuous estabilizar antes do TX começar.
A delay roda no contexto NimBLE — 150ms é tolerável (<< supervision
timeout 6s+). Após delay, dispara o segundo job e retorna ack JSON.

### `wpa_capture_kick`

Combina `wpa_capture(bssid, channel, duration)` + `deauth(broadcast,
bssid, channel, count)`. Pipeline:

1. `sniff_wifi_eapol_start(bssid, channel, duration_sec)` — fixa promisc
   no canal alvo
2. `vTaskDelay(150ms)` — promiscuous ativa estável
3. `hacking_wifi_deauth(broadcast, bssid, channel, deauth_count, reason=7)` —
   força clients a reassociar
4. Ack JSON com status

Caso de uso: cracking WPA/WPA2 PSK convencional. Saída pcap via TLVs
`WPA_EAPOL 0x18` + `WPA_CAPTURE_DONE 0x19` do wpa_capture.

Status retornado:
- `started` se ambos OK
- `started_no_kick` se wpa_capture iniciou mas deauth falhou
  (wpa_capture continua rodando — handshake ainda pode emergir
  passivamente)

### `pmkid_capture_kick`

Análogo ao acima mas com `pmkid_capture` + `deauth`. Defaults menores
(deauth_count=10, duration=60s) porque PMKID emerge no M1 (1º frame),
não precisa do 4-way completo.

### `evil_twin_kick`

Combina `evil_twin_start(ssid, password, channel)` + opcional
`deauth(broadcast, legit_bssid, channel, count)`. Pipeline:

1. `evil_twin_start(...)` sobe SoftAP fake
2. Se `legit_bssid` foi passado:
   - `vTaskDelay(200ms)` — twin estabiliza beacon
   - `hacking_wifi_deauth(broadcast, legit_bssid, channel, count, 7)` —
     kicka clients do AP legítimo. Eles reassociam → muitos pegam o twin.

Status retornado inclui `kick_fired` (bool).

Após o macro retornar, app pode encadear com `captive_portal_start`
pra capturar credenciais.

### `recon_full`

Snapshot completo do entorno em 1 comando. Dispara em paralelo:
1. `scan_wifi_start(SCAN_WIFI_MODE_PASSIVE, 0)` — todos os canais 2.4GHz
2. `scan_ble_start_ex(SCAN_BLE_MODE_ACTIVE, 15)` — 15s de active scan
3. Se `include_lan=true` e ESP conectado: `attack_lan_lan_scan_start(3000)`

Cada subprimitivo emite seus próprios TLVs (`WIFI_SCAN_AP/DONE`,
`BLE_SCAN_DEV/DONE`, `LAN_HOST/DONE`). App processa todos paralelos.

Status retornado: 3 booleans indicando quais scans iniciaram OK.

**Exemplo de fluxo combinado** (ataque WPA full):
```
App ──{"cmd":"wpa_capture_kick","bssid":"AA:..","channel":6,"duration_sec":120,"deauth_count":50}──→ ESP
ESP ──ack started──→ App
   (wpa_capture rodando + 50 deauths disparados em background)
   ESP ──TLV[0x18] WPA_EAPOL M1──→ App
   ESP ──TLV[0x18] WPA_EAPOL M2──→ App
   ESP ──TLV[0x18] WPA_EAPOL M3──→ App
   ESP ──TLV[0x18] WPA_EAPOL M4──→ App
   ESP ──TLV[0x19] WPA_CAPTURE_DONE──→ App
App grava pcap → hashcat
```

**Limitações**:
- 150ms vTaskDelay no NimBLE host task — bloqueia BLE por 150ms.
  Tolerável mas não ideal. Solução futura: spawn task auxiliar
  (mais código).
- Macros não fazem cleanup automático em caso de falha parcial. Se
  evil_twin_kick fica com `kick_fired=false`, twin segue rodando —
  app deve chamar `evil_twin_stop` se quiser.
- Não há TLV próprio do macro — app correlaciona pelos TLVs das
  primitivas (mais flexível, menos prescritivo).

### `karma_then_twin` (✅ entregue 2026-05-05)

Mini-playbook embutido. Pipeline:
1. Inicia `sniff_wifi_karma_start(channel, duration)` que escuta probe req
   e responde com probe response forjado.
2. Hook **weak** `macros_hook_karma_hit(src, ssid, ssid_len)` declarado em
   sniff_wifi.c, override forte em command_router.c.
3. Hook agrega hits por SSID em tabela (cap 32). Roda na NimBLE host task
   (sem alocação dinâmica, fast).
4. Task auxiliar `karma_then_twin_task` aguarda duration + 500ms folga,
   tira a flag `s_kt_active` (hook vira no-op), encontra top-1 SSID.
5. Dispara `evil_twin_start(top_ssid, password?, channel, max_conn=4)`.
6. Emite resposta JSON final assíncrona com status (twin_up | no_hits |
   twin_failed).

Args: `channel`, `duration_sec` (5–120, default 30), `password` (opcional WPA2).

### `deauth_storm` (✅ entregue 2026-05-05)

Single task que intercala deauth + RTS jam pra evitar conflito do
s_busy global do hacking_wifi (deauth, beacon_flood, channel_jam são
mutex entre si).

Pipeline interno:
1. set_channel
2. Burst inicial de `deauth_count` deauths (3ms entre cada)
3. Loop até `jam_seconds`: 30 RTS frames (25ms cada, NAV lock) + 5 deauths
4. Final logado

Args: `bssid`, `target?` (default broadcast), `channel`, `deauth_count`
(10–500, default 50), `jam_seconds` (5–60, default 15).

### `mitm_capture` ⚠ "weak" (✅ entregue 2026-05-05, mas com limitação)

Combina `arp_cut` (modo drop) + `pcap_start(filter=data, bssid=AP)`.
Vítima fica **offline** durante captura — ESP poisona ARP cache mas não
encaminha pacotes. Mesmo offline, ESP captura tudo que vítima tenta
enviar via promiscuous + emite TLV `PCAP_FRAME 0x40`.

Args: `target_ip`, `target_mac`, `gateway_ip`, `gateway_mac`, `bssid`,
`channel`, `duration_sec` (5–300, default 60).

**Não é MITM clássico**. Pra MITM real (forwarding com vítima online),
exigiria:
- `arp_throttle` com forwarding via lwIP raw inject + recálculo de
  checksums + rate-limit per-flow
- OU modo APSTA atuando como roteador

Ambos são refactors grandes — fica como evolução. "weak drop capture"
cobre pesquisa de tráfego sem precisar manter conectividade da vítima.

### `tracker_hunt` ⚠ versão simples (✅ entregue 2026-05-05)

Versão atual: `ble_scan(active, duration_sec)` longo (cap 1h). Devices
com flag `tracker` setada (Apple Find My / Samsung SmartTag / Tile /
Chipolo) são reportados via `BLE_SCAN_DEV 0x12`.

Args: `duration_sec` (30–3600, default 300).

**Agregação multi-scan no firmware ainda pendente** (TLV
`TRACKER_PERSISTENT 0x2B` reservado mas não emitido). Heurística completa:
- Loop de scans com tabela de estado entre runs
- Histórico de RSSI por MAC com janela deslizante
- Correlação com mfg_data pra MACs random rotativos
- Persistente em ≥3 scans consecutivos + RSSI estável (±10 dBm) → emit alert

Por enquanto, app agrega correlacionando os `BLE_SCAN_DEV` entre múltiplas
chamadas. Firmware-side fica como evolução depois.

---

## `playbook_run` — engine declarativo JSON

**O que faz**: executa workflows declarativos sem precisar do app
gerenciar timing/sequência. App envia 1 só comando com array de steps;
firmware executa em ordem na própria task. Diferente dos macros
hardcoded, é arbitrariamente combinável.

**Step types (v1)**:

| type | Args | O que faz |
|---|---|---|
| `cmd` | `cmd`, `args:{...}` | Despacha comando pelo command_router local. args mergeados com `cmd` + `seq:-1`. |
| `wait_ms` | `ms` (0–600000) | `vTaskDelay`. |
| `wait_event` | `tlv` (msg_type), `timeout_ms` (100–600000, default 30s) | Aguarda TLV específico via hook weak no transport_ble. Falha por timeout. |
| `set` | `name` (`$var`), `value` (string/number) | Armazena variável (max 8). |

**Variáveis**: strings começando com `$` em qualquer arg de step
subsequente são substituídas pelo último value setado via `set`. Útil
pra encadear: capturar valor num step, usar no próximo.

**Como funciona** (`playbook.c`):
- Spawn task `playbook` com cópia local do JSON
- Walks steps sequencialmente:
  - `cmd`: monta JSON `{cmd, seq:-1, args...}`, substitui `$vars`,
    chama `command_router_handle_json` direto (despacha localmente)
  - `wait_ms`: loop com vTaskDelay 50ms até timeout
  - `wait_event`: seta `s_wait_event_msg_type`, loop poll `s_wait_event_seen`
    até timeout (hook weak setado por playbook_hook_tlv strong override)
  - `set`: armazena no array de vars
- Após cada step: emite TLV `PLAYBOOK_STEP_DONE 0x28`
- Aborta em 3 erros consecutivos
- Final: TLV `PLAYBOOK_DONE 0x29` com totals

**Hook TLV** (`transport_ble.c`):
- `__attribute__((weak)) void playbook_hook_tlv(msg_type, payload, len)`
- Chamado em todo `transport_ble_send_stream` antes do BLE notify
- Strong override em `playbook.c` checa msg_type contra step.tlv

**Persistência**: comando aceita `profile` em vez de `steps` — carrega
JSON via `persist_profile_load`. Permite rodar workflows sem app
conectado (boot → NVS → playbook autônomo). Combinado com `profile_save`
da Phase 7.

**Exemplo de playbook** (auto-Karma + EvilTwin + captive):
```jsonc
{
  "cmd": "playbook_run",
  "seq": 1,
  "steps": [
    {"type": "cmd", "cmd": "karma_then_twin",
     "args": {"channel": 6, "duration_sec": 30}},
    {"type": "wait_event", "tlv": 38, "timeout_ms": 60000},
    // (tlv 38 = 0x26 EVIL_CLIENT_JOIN — espera 1 cliente associar)
    {"type": "cmd", "cmd": "captive_portal_start"}
  ]
}
```

**Exemplo persistido**:
```jsonc
// 1. App salva o profile
{"cmd": "profile_save", "name": "auto_karma",
 "data": "[{\"type\":\"cmd\",...}]"}

// 2. Roda direto da NVS
{"cmd": "playbook_run", "profile": "auto_karma"}
```

**Limites**:
- 32 steps por playbook
- 8 variáveis simultâneas
- 4096 bytes JSON
- 3 erros consecutivos = abort
- Vars são strings (max 64 chars cada) — sem JSON anidados na value

**Limitações conhecidas**:
- Sem `if`/`loop`/`select_top` ainda. Casos com decisão usam macros
  hardcoded (ex: `karma_then_twin` faz a lógica em C).
- Hook TLV roda no contexto do emitter (NimBLE host task ou worker
  task). Setar flag é fast e seguro.
- Wait_event captura SEMPRE o próximo TLV daquele type — sem filtro
  por payload. Se 2 jobs paralelos emitem mesmo TLV, ambiguidade.
- `cmd` step não pode esperar resposta do command (não há "ack
  capture"). Se app precisa do resultado, encadeia com `wait_event`
  no TLV de done correspondente (ex: `WIFI_SCAN_DONE 0x11` após
  `wifi_scan`).

**Combinação natural com playbook**:
- `profile_save` → `playbook_run profile=` → workflow autônomo, restart-safe
- Watchdog rodando em paralelo — playbook + watchdog cobrem detect+respond
  + workflow scripted automático

---

## Phase 4 — BLE
- [Apple Continuity spam (`ble_spam_apple`)](#ble_spam_apple--apple-continuity-proximity-spam)
- [Samsung EasySetup spam (`ble_spam_samsung`)](#ble_spam_samsung--samsung-easysetup-popup-spam)
- [Google Fast Pair spam (`ble_spam_google`)](#ble_spam_google--google-fast-pair-popup-spam)
- [Multi-vendor BLE spam (`ble_spam_multi`)](#ble_spam_multi--apple--samsung--google-aleatorio-por-cycle)
- [BLE adv flood (`ble_adv_flood`)](#ble_adv_flood--dos-via-channel-congestion)

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

## `wifi_scan` — scan ativo/passivo de APs 2.4GHz

**O que faz**: lista APs visíveis (BSSID, SSID, RSSI, canal, auth_mode,
+ flags hidden/WPS/phy). Suporta scan **ativo** (envia probe req) e
**passivo** (só escuta beacons).

**Como funciona**:
- **Ativo** (default): ESP envia probe request broadcast por canal. APs
  respondem com probe response. Rápido (~80–120ms por canal) mas anuncia
  presença.
- **Passivo**: ESP só escuta beacons (~100ms a cada 100ms cada AP envia
  beacon). Silencioso, mas demora mais (~360ms por canal).

**WPS detection**: o IDF parseia o WPS IE (Microsoft OUI `00:50:F2`
type `0x04`) durante o scan e popula `wifi_ap_record_t.wps`. Expomos
isso como flag bit 1 no payload TLV.

**Hidden detection**: AP com SSID vazio em beacon (broadcast suprimido).
`ssid_len == 0` → flag bit 0 setado.

**Implementação** (`scan_wifi.c`):
- API: `scan_wifi_start(mode, channel)` — mode = ACTIVE/PASSIVE,
  channel = 0 (todos) ou 1..13.
- `wifi_scan_config_t` configurado:
  - `scan_type = WIFI_SCAN_TYPE_ACTIVE` ou `_PASSIVE`
  - `scan_time.passive = 360` ms (passive) OR `scan_time.active = {min:80, max:120}`
  - `show_hidden = true` (sempre captura hidden)
- `WIFI_EVENT_SCAN_DONE` dispara handler que pega `wifi_ap_record_t[]`
  via `esp_wifi_scan_get_ap_records`.
- Para cada record, codifica payload TLV `WIFI_SCAN_AP 0x10`:
  - bssid (6) + rssi (1) + channel (1) + auth_mode (1) + ssid_len (1)
    + ssid (variable) + **flags (1)**.
  - Flags bits: 0=hidden, 1=WPS, 2=phy_11b, 3=phy_11n.
- Envia via `transport_ble_send_stream`, com `vTaskDelay(5ms)` entre frames.
- Final: `WIFI_SCAN_DONE 0x11`.

**Fluxo**:
```
App ──{"cmd":"wifi_scan","mode":"passive","channel":0}──→ ESP
ESP ──{"resp":"wifi_scan","status":"started"}──→ App  (ack imediato)
   ┌────────────────── 2.4GHz radio ──────────────────┐
   │ passive: ch1 (listen 360ms) → ch2 → ... → ch13   │
   │ active : ch1 (probe→resp 80–120ms) → ch2 → ...   │
   └──────────────────────────────────────────────────┘
ESP ──TLV[0x10] AP1 (flags: hidden=0, wps=1)──→ App
ESP ──TLV[0x10] AP2 (flags: hidden=1, wps=0)──→ App
...
ESP ──TLV[0x11] DONE──→ App
```

**Limitações**: só 2.4GHz (S3 não tem 5GHz). Hidden SSIDs aparecem com
`ssid_len=0` e flag bit 0 setado. WPS detection depende do AP anunciar
o WPS IE em beacons/probe responses. Channel hopping configurável só
suporta single-channel ou all (não range arbitrário — limitação do
`esp_wifi_scan_start`). Para range customizado, app pode iterar canais.

---

## `ble_scan` — discovery passivo/ativo + tracker classification

**O que faz**: lista devices BLE anunciando próximo (mac, rssi, name,
mfg_data) + classifica trackers conhecidos (Apple Find My, Samsung
SmartTag, Tile, Chipolo) emitindo bitmask `tracker` no payload.

**Como funciona**:
- **Passive**: GAP discovery silencioso, só escuta advertising packets.
- **Active**: ESP envia scan_request → device retorna scan_response com
  payload extra (frequentemente o nome completo ou IDs adicionais).
  Mais info, mas anuncia presença do ESP.

Devices anunciam:
- Flags (Limited/General Discoverable, BR/EDR Not Supported, etc)
- Local name (Complete ou Shortened)
- Manufacturer Data (Company ID 2B LE + payload vendor-specific)
- Service UUIDs (16/32/128-bit)
- Service Data (UUID + payload)

**Tracker classification** (`classify_tracker()` em `scan_ble.c`):

| Tracker | Sinal procurado | Bit |
|---|---|---|
| Apple Find My (AirTag) | mfg_data Apple `4C 00` + subtype `0x12` (Offline Finding) | 0 |
| Samsung SmartTag | svc_data UUID `0xFD5A` (Samsung Find) | 1 |
| Tile | mfg_data Company ID `0x0067` (LE: `67 00`) | 2 |
| Chipolo | mfg_data Company ID `0x07E6` (LE: `E6 07`) | 3 |

**Implementação** (`scan_ble.c`):
- API: `scan_ble_start_ex(mode, duration_sec)`.
- `ble_gap_disc(BLE_OWN_ADDR_PUBLIC, duration_ms, params, cb)` com
  `passive = (mode == PASSIVE) ? 1 : 0`.
- `BLE_GAP_EVENT_DISC` para cada packet recebido.
- `ble_hs_adv_parse_fields()` extrai os campos.
- Dedup por MAC (linear scan em buffer estático de 64 entries).
- `classify_tracker()` retorna bitmask.
- Cada device único emite TLV `BLE_SCAN_DEV 0x12` com tracker byte
  apended ao final do payload (backward-compat).
- Ao final: `BLE_SCAN_DONE 0x13`. Status=1 se truncou (>64 únicos).

**Fluxo**:
```
App ──{"cmd":"ble_scan","mode":"active","duration_sec":15}──→ ESP
ESP ──ack──→ App

  ESP scan ativo:
    BLE_GAP_EVENT_DISC: peripheral X →
      ble_hs_adv_parse_fields() →
      classify_tracker() bitmask
      emit TLV[0x12] BLE_SCAN_DEV (mac, rssi, name, mfg_data, tracker=0x01)
    
    [se active]: ESP envia scan_request a X
    BLE_GAP_EVENT_DISC: scan_response de X (extra data)
    (mesma classificação, novo TLV se MAC ainda não visto)
  
  ESP ──TLV[0x13] BLE_SCAN_DONE──→ App
```

**Limitações**: 64 unique cap no firmware (memória estática). Active
scan polui o canal e o ESP fica visível pra outros scanners. Tracker
classification é heurística baseada em company IDs/UUIDs — pode dar
falso-positivo (ex: outro device usando mfg_data Apple subtype 0x12).
Tracker following (mesmo device acompanhando você) requer agregação
multi-scan no app — firmware só fornece sinal pontual.

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

## `ble_adv_flood` — DoS via channel congestion

**O que faz**: spamma advs BLE com payload aleatório no rate máximo
permitido (interval 20ms). Diferente dos `ble_spam_*` que tentam
triggerar popups específicos, aqui o objetivo é **saturar os canais
BLE de advertising (37/38/39)** — devices BLE legítimos perto sofrem
pra anunciar ou ser descobertos.

**Como funciona** (BLE 5 advertising):
- BLE adv é transmitido nos 3 canais primários (37, 38, 39 = 2402, 2426,
  2480 MHz). Controllers escolhem qual canal por adv event.
- Adv interval mínimo prático: 20ms (configurável via `itvl_min`/`itvl_max`
  em unidades de 0.625ms = `0x20`).
- Cada cycle de set_data + adv_start dispara 1 adv event nos canais
  configurados (default: todos 3 = 3 PDUs).

**Implementação** (`hacking_ble.c`):
- Async via FreeRTOS task. Cap duration_sec=60 pra não esquentar.
- Loop tight (40ms entre cycles → ~25 cycles/s × 3 canais ≈ 75 PDUs/s):
  - Gera 31 bytes random (`esp_random()`).
  - Sanitiza primeiro IE: `length` em range plausível (2–29) + `type` random,
    pra evitar rejeição do controller.
  - `ble_gap_adv_stop` + `ble_gap_adv_set_data(adv, 31)` + `ble_gap_adv_start`
    (non-conn, non-disc, itvl_min/max=0x20).
- Pausa GATT adv no início, retoma com `transport_ble_advertising_resume`
  ao final (mesmo padrão do spam_apple).
- TLV `BLE_FLOOD_DONE 0x2F` (sent + duration_sec).

**Fluxo**:
```
App ──{"cmd":"ble_adv_flood","duration_sec":15}──→ ESP
ESP ──ack started──→ App

  ESP pausa GATT adv
  loop por 15s:
    gen 31 random bytes
    set_data + adv_start (itvl 20ms)
    sleep 40ms
  ESP retoma GATT adv
  ESP ──TLV[0x2F] BLE_FLOOD_DONE (sent=375, duration_sec=15)──→ App
```

**Limitações**:
- Random bytes podem ser rejeitados pelo controller em casos extremos
  (length byte inconsistente, etc) — sanitização cobre os casos mais
  comuns mas não garante 100%.
- iOS/Android scanners modernos têm filtragem de adv malformado —
  conta como ruído mas pode não impedir descoberta de device legítimo.
- 60s cap evita aquecimento, mas mesmo 60s é bem agressivo pra
  módulos BLE — deixar a placa ventilada.
- Não muda MAC (NimBLE não permite com GATT conectado), então 1 device
  consistente. Detect/block fácil pra defesas que filtram por MAC.
- Active scan abuse: Phase 4 listou separadamente, mas já está coberto
  pelo `ble_scan mode=active` (Phase 2) — captura scan_responses dos
  peripherals próximos enviando scan_request.

**Combinação natural**:
- Em paralelo com `channel_jam` (canal WiFi adjacente 2.4GHz) → DoS
  multi-camada na vizinhança.

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
