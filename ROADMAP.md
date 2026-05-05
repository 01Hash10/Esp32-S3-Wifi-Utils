# Roadmap

Documento vivo. Marcar `[x]` conforme entrega; itens podem ser reordenados
ou removidos ao longo do projeto.

## Decisões de arquitetura

- **Firmware**: ESP-IDF 5.4 puro, C
- **App**: Flutter (`flutter_blue_plus`)
- **Transporte**: BLE GATT (NUS-style, custom service)
- **Protocolo (híbrido)**:
  - `cmd_ctrl` characteristic → **JSON minificado** (comandos, ack/err, status)
  - `stream` characteristic → **TLV binário** (scan results, eventos, pcap)
- **Frame TLV**: `[u16 length BE][u8 msg_type][u8 seq][payload]`
- **Branch strategy**: `main` direta por enquanto

---

## Phase 0 — Foundation

- [x] PlatformIO + ESP-IDF setup
- [x] PSRAM Octal 80MHz + Flash 16MB QIO + CPU 240MHz
- [x] Particionamento custom (4MB factory + ~12MB storage)
- [x] Console via USB-Serial-JTAG nativa (bypass CH343)
- [x] Boot diag (SRAM/PSRAM via heap_caps)
- [x] Scripts `flash.sh` / `monitor.sh`

## Phase 1 — Transport & Protocol

- [x] BLE GATT server (custom service UUID, NimBLE host)
- [x] Characteristic `cmd_ctrl` (Write + Notify)
- [x] Characteristic `stream` (Notify)
- [x] Pareamento (Just Works inicialmente, PIN depois)
- [x] Encoder/decoder JSON minificado (cJSON da IDF)
- [x] Encoder/decoder TLV binário (componente `protocol`)
- [x] Command router (dispatch via JSON `cmd` field)
- [x] Heartbeat/keepalive bidirecional (TLV `HEARTBEAT 0x00` periódico do firmware; app continua usando `ping` no reverso)
- [x] Sequence numbers nos JSON responses
- [x] Error envelope padronizado (`{err, seq, msg}`)
- [x] Configuração de MTU (negociar 247)
- [x] Comandos básicos: `ping`, `hello`, `status`

## Phase 2 — Scan

### WiFi
- [x] Scan ativo (probe request)
- [x] Scan passivo (`wifi_scan` com `mode:"passive"` — só escuta beacons)
- [x] Stream contínuo de results pro app
- [x] Channel hopping configurável (`wifi_scan` com `channel:0..13` — single ou todos)
- [x] Decoding: BSSID, SSID, RSSI, canal, segurança, **hidden flag** (bit0), phy_11b/n flags
- [ ] Lookup de OUI (vendor a partir do MAC) — **lado-app** (tabela OUI ~50KB; firmware emite MAC, app resolve vendor)
- [x] Detecção de WPS habilitado (flag bit1 no `WIFI_SCAN_AP`)
- [ ] Histórico de RSSI por BSSID — **lado-app** (agregação multi-scan)
- [x] Captura de pcap (promiscuous streaming, sem storage no ESP) — `pcap_start` emite TLV `PCAP_FRAME 0x40` em tempo real
- [x] Export de pcap via BLE pro app — script monta arquivo LINKTYPE 105 a partir dos TLVs

### BLE
- [x] Scan passivo (NimBLE GAP discover)
- [x] Scan ativo (`ble_scan` com `mode:"active"` — captura scan_response)
- [x] Parsing de advertising data (flags, name, mfg data, svc data)
- [ ] Fingerprint por mfg data (Apple, Samsung, Google, etc) — **lado-app** (tabela de Company IDs IEEE)
- [x] Detecção de AirTags / SmartTags / Tile / Chipolo (flag `tracker` no `BLE_SCAN_DEV`)
- [ ] Detecção de tracker following (RSSI seguindo no tempo) — **lado-app** (agregação multi-scan)
- [x] Stream contínuo pro app

### Análise / classificação
- [ ] Threat classifier WiFi: open, WEP, WPS, hidden, beacon anomalies — **lado-app** (firmware já fornece authmode + flags hidden/WPS; classifier é regra de negócio do app)
- [ ] Threat classifier BLE: tracker, spam signatures, devices unknown — **lado-app** (firmware já fornece flags `tracker` + mfg_data; assinatura de spam é regra do app)

## Phase 3 — Hacking WiFi

### MVP (primeiras a entregar)
- [~] Deauth attack — single target — código pronto, **validação pendente**
  (não testável neste setup: roteador da empresa em 5GHz e ESP32-S3 só
  tem 2.4GHz; precisa de cliente 2.4GHz separado pra confirmar TX).
- [~] Deauth broadcast — mesmo bloqueio acima.
- [~] Beacon flood — código pronto, `esp_wifi_80211_tx` retorna OK em
  todos os 1000 frames mas **scanner de celular não detecta os SSIDs
  consistentemente**. Pendências de melhoria:
  - Confirmar que TX está de fato no ar via modo promiscuous do próprio
    ESP (sniff dos próprios beacons em outro componente).
  - Investigar se IDF 5.4 limita beacon raw em STA mode (testar APSTA
    + WIFI_IF_AP).
  - Comparar com scanner de baixo nível no Mac (`wdutil`, `Wireless Diagnostics`).
  - Ajustar IEs (HT/VHT capabilities) se filtros do scanner exigirem.
- [x] WPA handshake capture (EAPOL 4-way) → emite frames 802.11 brutos via TLV (`wpa_capture`); script de teste monta pcap

### LAN-level (atacante associado à rede)
- [x] WiFi STA connect/disconnect (`wifi_connect`/`wifi_disconnect`)
- [x] ARP poisoning / NetCut — modo "drop" (`arp_cut` / `arp_cut_stop`)
- [x] ARP poisoning — modo "throttle" (cycle on/off de poisoning, internet intermitente na vítima) — `arp_throttle`
- [x] LAN host discovery — ARP scan no /24 (`lan_scan`)

### Demais
- [x] PMKID capture (`pmkid_capture` — extrai PMKID KDE do M1, hash hashcat WPA*02)
- [x] Probe request sniffing (`probe_sniff` + dedup por mac/ssid + channel hop)
- [ ] Dossiê de devices a partir de probe history (lado app — agregação multi-sessão)
- [x] Evil twin / Captive portal:
  - `evil_twin_start` — SoftAP fake + DHCP + TLVs `EVIL_CLIENT_JOIN`/`LEAVE`
  - `captive_portal_start` — DNS hijack UDP:53 + HTTP server TCP:80, captura credenciais de POST forms via TLVs `PORTAL_DNS_QUERY`/`PORTAL_HTTP_REQ`
- [x] Karma attack — `karma_start`: escuta probe req direcionado, responde com probe response forjado (BSSID = hash do SSID + prefix `0x02`). Útil pra mapear PNL; pra completar assoc precisa de Evil Twin.
- [~] WPS attack:
  - [x] `wps_pin_test`: testa 1 PIN via supplicant da IDF; emite TLV com SSID+PSK em sucesso. Base pra brute-force lado-app.
  - [blocked] **Pixie Dust nativo**: API pública do IDF 5.4 não expõe M2 cru → impossível sem patch invasivo. Workaround documentado: `pcap_start` + processar offline com `pixiewps`.
- [x] Channel jamming via RTS NAV-lock (`channel_jam`) — não é CW puro mas trava airtime efetivamente

## Phase 3.5 — Comandos compostos & Playbook

> **Por quê esta fase**: várias features só fazem sentido combinadas
> (ex: `wpa_capture` + `deauth`, `evil_twin` + `karma` + `deauth`).
> Hoje o app/script encadeia manualmente. Aqui formalizamos: macros
> hardcoded pras combinações comuns + playbook engine pra workflows
> complexos. Ver `COMPOSITION.md` pra catálogo completo + matriz de
> compatibilidade entre componentes.

### Macros (firmware-side, comandos compostos hardcoded)

- [ ] `wpa_capture_kick` — `deauth(broadcast, count=30)` + `wpa_capture`
  no mesmo BSSID/canal. Caso de uso: cracking WPA convencional.
- [ ] `pmkid_capture_kick` — análogo: `deauth` + `pmkid_capture`.
  Caso de uso: PMKID-only attack se AP não suportar Offline Finding KDE
  na primeira tentativa.
- [ ] `evil_twin_kick` — `evil_twin_start(ssid)` + `deauth(legit_bssid)`
  paralelo. Caso de uso: forçar clients a migrar do AP legítimo pro twin.
- [ ] `karma_then_twin` — `karma_start` por N segundos, escolhe o SSID
  mais probed, **automaticamente** sobe `evil_twin` com aquele SSID.
  Mini-playbook embutido.
- [ ] `recon_full` — `wifi_scan(passive, all)` + `ble_scan(active)`
  paralelos + (se `wifi_connect` ativo) `lan_scan`. Snapshot completo
  do entorno em 1 comando.
- [ ] `deauth_storm` — `deauth(bssid, count=200)` + `channel_jam` no
  mesmo canal. DoS combinado: kicka clients e impede reconexão.
- [ ] `mitm_capture` — `arp_cut(target)` modo throttle + `pcap_start`
  no canal do AP filtrando por target_mac. Captura tráfego HTTP do
  alvo enquanto o cut estrangula a banda. (Depende de forwarding mode
  futuro do arp_cut pra realmente passar dados.)
- [ ] `tracker_hunt` — `ble_scan(active)` por N segundos, agrega devices
  com flag `tracker` no `BLE_SCAN_DEV` payload, emite alerta TLV se
  algum device persistir entre múltiplos scans (= seguindo você).
  Lado-app pode fazer; mas embutir no firmware permite operação 24/7
  sem app conectado.

### Playbook engine (médio prazo)

- [ ] Comando `playbook_run`: aceita JSON com array de steps + condicionais
- [ ] Step types: `cmd` (executa comando interno), `wait_ms`, `wait_event`
  (TLV específico com filtros), `if`, `select_top` (pega top-N de uma
  lista de TLVs por contagem), `loop`
- [ ] Output: TLV `PLAYBOOK_STEP_DONE 0x28` por step + `PLAYBOOK_DONE 0x29`
- [ ] Persistência opcional: `playbook_save` em NVS (vinculado à Phase 7)
- [ ] Watchdog: rate-limit, timeout total, abort em N erros consecutivos

## Phase 4 — Hacking BLE

- [x] BLE spam — Apple Continuity (popup AirPods/etc) — TX validado (100/100
  cycles), validação visual em iPhone pendente. Limitação: MAC fixo durante
  o spam (NimBLE não permite mudar addr enquanto há GATT conectado),
  iPhone pode coalescer popups por MAC.
- [x] BLE spam — Samsung EasySetup (`ble_spam_samsung`)
- [x] BLE spam — Google Fast Pair (`ble_spam_google`)
- [x] BLE spam — multi-vendor concorrente (`ble_spam_multi` — random Apple/Samsung/Google por cycle)
- [x] BLE advertising flood (`ble_adv_flood` — DoS via channel congestion: random adv data + interval mínimo 20ms × 3 canais ≈ 75 PDUs/s, cap 60s)
- [x] BLE active scan abuse (já coberto pelo `ble_scan mode=active` da Phase 2 — envia scan_request e captura scan_response que muitas vezes traz info adicional)

## Phase 5 — Defense (Detection-only)

- [x] Deauth detector + alerta no app — `defense_start` com `mask & 0x01`, threshold 5/s, TLV `DEFENSE_DEAUTH 0x30`
- [x] Evil twin detector — `mask & 0x04`, mesmo SSID com 2+ BSSIDs distintos, TLV `DEFENSE_EVIL_TWIN 0x32`
- [x] Beacon flood detector — `mask & 0x02`, threshold 20 BSSIDs únicos/s, TLV `DEFENSE_BEACON_FLOOD 0x31`
- [x] BLE spam detector — `ble_defense_start`, classifica advs por assinatura vendor (Apple Continuity / Samsung EasySetup / Google Fast Pair), alerta quando rate de MACs únicos cruza threshold (6/s/vendor)
- [ ] Tracker following detector (BLE) — agregação multi-scan, marcado lado-app na Phase 2
- [x] WiFi Pineapple / Karma detector — `mask & 0x08`, BSSID com bit locally-admin, TLV `DEFENSE_KARMA 0x33`
- [x] PMKID exposure scanner (sua própria rede) — workflow documentado em METHODS.md usando `pmkid_capture` + `deauth` paralelo. Não virou comando firmware separado (timing controlado melhor pelo app/script).
- [ ] Histórico de eventos persistente (ring buffer + NVS) — bloqueado pela Phase 7

## Phase 6 — Defense (Active counter-measures)

> ⚠ Uso restrito a redes/dispositivos próprios em laboratório.

- [blocked] Anti-deauth: **inviável diretamente** (atacante spoofa addr2 = AP legítimo, então direcionar contra-deauth significa deauth no AP). Documentado em METHODS.md. Detecção segue ativa via `defense_start`.
- [x] Anti-evil-twin: `watchdog_start --actions=1` dispara `deauth(broadcast)` no BSSID twin (heurística locally-admin / RSSI mais fraco)
- [x] BLE spam jam: `watchdog_start --actions=2` dispara `ble_adv_flood(5s)` quando `DEFENSE_BLE_SPAM` alerta
- [x] Watchdog mode: detect → ação automática — `watchdog_start` é o framework central que cobre os itens acima
- [x] Rate limiting de contra-medidas (cooldown_ms + max_actions configuráveis, default 10s/5)
- [x] Whitelist (array de BSSIDs no `watchdog_start`, max 16, contra-ação skipa target whitelisted)

## Phase 7 — Persistence & UX (Firmware)

- [ ] NVS storage de configs (canal, modos, whitelists)
- [ ] Profiles persistentes (ex: "modo aula", "modo lab")
- [ ] Pcap export streaming via BLE
- [ ] OTA update via BLE (longo prazo)
- [ ] Power management básico (sleep entre scans)

## Phase 8 — App Flutter

- [ ] Setup Flutter + flutter_blue_plus
- [ ] Tela: pareamento BLE / discovery do device
- [ ] Tela: dashboard (status, free heap, uptime)
- [ ] Tela: Scan (WiFi/BLE live, com filtros)
- [ ] Tela: Hacking (categorizada, com alvos pré-selecionados)
- [ ] Tela: Defense (toggle detection/active, log de eventos)
- [ ] Tela: Pcap viewer básico OU export pro file system
- [ ] Notificações em background (defense alerts)
- [ ] Mapa de RSSI / heatmap (stretch)
- [ ] Tema dark/hacker (estético, baixa prioridade)

## Phase 9 — Quality & Hardening

- [ ] Logging estruturado e filtrável (níveis por componente)
- [ ] Tests unitários do command router e TLV codec
- [ ] CI/CD: build do firmware no GitHub Actions
- [ ] Documentação por componente (header docs)
- [ ] Threat model documentado
- [ ] Policy de uso responsável (uso lab-only) no README

---

## Referências de progresso

- Resumo de status no `README.md` (seção "Status")
- Decisões fechadas viram entry em `CLAUDE.md`
- Cada feature implementada idealmente com seu próprio commit + log no monitor
