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
- [ ] Heartbeat/keepalive bidirecional
- [x] Sequence numbers nos JSON responses
- [x] Error envelope padronizado (`{err, seq, msg}`)
- [x] Configuração de MTU (negociar 247)
- [x] Comandos básicos: `ping`, `hello`, `status`

## Phase 2 — Scan

### WiFi
- [x] Scan ativo (probe request)
- [ ] Scan passivo (channel hop + listen)
- [x] Stream contínuo de results pro app
- [ ] Channel hopping configurável
- [ ] Decoding: BSSID, SSID, RSSI, canal, segurança, hidden flag
- [ ] Lookup de OUI (vendor a partir do MAC)
- [ ] Detecção de WPS habilitado
- [ ] Histórico de RSSI por BSSID
- [ ] Captura de pcap (promiscuous → flash storage)
- [ ] Export de pcap via BLE pro app

### BLE
- [x] Scan passivo (NimBLE GAP discover)
- [ ] Scan ativo (com scan request)
- [x] Parsing de advertising data (flags, name, mfg data)
- [ ] Fingerprint por mfg data (Apple, Samsung, Google, etc) — pode ser no app
- [ ] Detecção de AirTags / SmartTags
- [ ] Detecção de tracker following (RSSI seguindo no tempo)
- [ ] Stream contínuo pro app

### Análise / classificação
- [ ] Threat classifier WiFi: open, WEP, WPS, hidden, beacon anomalies
- [ ] Threat classifier BLE: tracker, spam signatures, devices unknown

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
- [ ] Evil twin / Captive portal (AP fake + DNS hijack)
- [ ] Karma attack (responde a probes com SSIDs procurados)
- [ ] WPS attack (Pixie Dust — viabilidade no S3 a confirmar)
- [x] Channel jamming via RTS NAV-lock (`channel_jam`) — não é CW puro mas trava airtime efetivamente

## Phase 4 — Hacking BLE

- [x] BLE spam — Apple Continuity (popup AirPods/etc) — TX validado (100/100
  cycles), validação visual em iPhone pendente. Limitação: MAC fixo durante
  o spam (NimBLE não permite mudar addr enquanto há GATT conectado),
  iPhone pode coalescer popups por MAC.
- [x] BLE spam — Samsung EasySetup (`ble_spam_samsung`)
- [x] BLE spam — Google Fast Pair (`ble_spam_google`)
- [x] BLE spam — multi-vendor concorrente (`ble_spam_multi` — random Apple/Samsung/Google por cycle)
- [ ] BLE advertising flood (DoS via canal congestion)
- [ ] BLE active scan abuse (probe → captura de scan response)

## Phase 5 — Defense (Detection-only)

- [ ] Deauth detector + alerta no app
- [ ] Evil twin detector (mesmo SSID, BSSID diferente / RSSI suspeito)
- [ ] Beacon flood detector
- [ ] BLE spam detector (matcher de assinaturas conhecidas)
- [ ] Tracker following detector (BLE)
- [ ] WiFi Pineapple / Karma detector
- [ ] PMKID exposure scanner (sua própria rede)
- [ ] Histórico de eventos persistente (ring buffer + NVS)

## Phase 6 — Defense (Active counter-measures)

> ⚠ Uso restrito a redes/dispositivos próprios em laboratório.

- [ ] Anti-deauth: deauth de volta no atacante
- [ ] Anti-evil-twin: deauth dos clients conectados ao twin
- [ ] BLE spam jam: flood do canal de adv do atacante
- [ ] Watchdog mode: detect → ação automática contínua
- [ ] Rate limiting de contra-medidas (evitar feedback loops)
- [ ] Whitelist (não atacar BSSIDs/MACs próprios)

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
