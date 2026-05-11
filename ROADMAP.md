# Roadmap

Documento vivo. Marcar `[x]` conforme entrega; itens podem ser reordenados
ou removidos ao longo do projeto.

## Decisões de arquitetura

- **Firmware**: ESP-IDF 5.1.2 puro, C (versão pinada — necessária pro bypass de `ieee80211_raw_frame_sanity_check`; ver `CLAUDE.md`)
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
- [~] Deauth attack — single target — TX path **agora real** (commit `028e2e2`,
  2026-05-08): bypass de `ieee80211_raw_frame_sanity_check` via `--weaken-symbol`
  + `wsl_bypasser.c` + helpers `inject_begin`/`inject_end` (liga promiscuous
  antes do TX porque driver só aceita raw mgmt em modo raw). **Defaults do
  protocolo continuam `count=10`/`reason=7`** — a mudança do default interno
  pra 100/4 em `hacking_wifi_deauth()` é dead code via JSON (`command_router`
  defaulta 10/7 antes); pra retomada: mover defaults pro command_router OU
  remover do hacking_wifi pra evitar confusão. **Validação visual em cliente
  2.4GHz ainda pendente**: testes empíricos nesta sessão (2026-05-08/11)
  mostraram serial corrompida durante bursts grandes, então confirmar
  TX→efeito num STA conhecido fica como tarefa de retomada.
- [~] Deauth broadcast — mesmo bypass; warning emitido no log lembrando
  que clients modernos podem ignorar broadcast (usar MAC específico do STA
  pra efeito garantido). Confirmação visual também pendente.
- [~] Beacon flood — mesmo bypass via `inject_begin/end`. APs falsos
  deveriam aparecer em scanners 2.4GHz; confirmação visual fica pendente
  junto com os dois itens acima. Limitação restante: scanners modernos
  podem filtrar IEs sem HT/VHT capabilities.
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
  - [blocked] **Pixie Dust nativo**: API pública do IDF (5.1.2 atual, igual em 5.2+) não expõe M2 cru → impossível sem patch invasivo. Workaround documentado: `pcap_start` + processar offline com `pixiewps`.
- [x] Channel jamming via RTS NAV-lock (`channel_jam`) — não é CW puro mas trava airtime efetivamente

## Phase 3.5 — Comandos compostos & Playbook

> **Por quê esta fase**: várias features só fazem sentido combinadas
> (ex: `wpa_capture` + `deauth`, `evil_twin` + `karma` + `deauth`).
> Hoje o app/script encadeia manualmente. Aqui formalizamos: macros
> hardcoded pras combinações comuns + playbook engine pra workflows
> complexos. Ver `COMPOSITION.md` pra catálogo completo + matriz de
> compatibilidade entre componentes.

### Macros (firmware-side, comandos compostos hardcoded)

- [x] `wpa_capture_kick` — `wpa_capture` + delay 150ms + `deauth(broadcast)` na mesma sessão
- [x] `pmkid_capture_kick` — análogo: `pmkid_capture` + `deauth`
- [x] `evil_twin_kick` — `evil_twin_start` + opcional `deauth(legit_bssid)`
- [x] `karma_then_twin` — hook weak `macros_hook_karma_hit` no sniff_wifi + agregação interna no command_router + spawn task que decide top SSID e dispara `evil_twin_start`
- [x] `recon_full` — `wifi_scan(passive,all)` + `ble_scan(active,15s)` + (opt) `lan_scan` paralelos
- [x] `deauth_storm` — nova função `hacking_wifi_deauth_storm` em uma task única que intercala burst de deauths + RTS jam (evita conflito de s_busy)
- [~] `mitm_capture` — versão "weak": `arp_cut` modo drop + `pcap_start` filter=data por bssid. Vítima offline mas ESP captura tráfego dela. Forwarding real (MITM clássico com pacotes encaminhados) ainda bloqueado pelo lwIP raw injection — fica como evolução
- [~] `tracker_hunt` — versão simples: `ble_scan` ativo longo. Agregação multi-scan no firmware (TLV `TRACKER_PERSISTENT 0x2B`) ainda pendente — app correlaciona os `BLE_SCAN_DEV` com flag `tracker` por enquanto

### Playbook engine (médio prazo)

- [x] Comando `playbook_run`: aceita JSON com array de steps (v1: 4 step types)
- [~] Step types implementados em v1: `cmd`, `wait_ms`, `wait_event`, `set`. **Faltam** `if`/`select_top`/`loop` (futuras evoluções)
- [x] Output: TLV `PLAYBOOK_STEP_DONE 0x28` por step + `PLAYBOOK_DONE 0x29`
- [x] Persistência: comando aceita `profile=name` carregando do NVS via `persist`. Salvar via `profile_save` regular (Phase 7)
- [x] Watchdog: 3 erros consecutivos = abort, `playbook_stop` cancela em qualquer step

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

- [x] NVS storage de configs — componente `persist` com namespace `wifiutils`, API genérica de blob storage
- [x] Profiles persistentes — comandos `profile_save/load/list/delete` salvam JSON blob nomeado (≤14 chars name, ≤1024 bytes data) no NVS
- [x] Pcap export streaming via BLE — já feito na Phase 2 (`pcap_start` emite TLV `PCAP_FRAME 0x40`)
- [ ] OTA update via BLE — deferred (longo prazo, exige protocolo dedicado pra firmware update over BLE chunks + verificação SHA256)
- [skipped] Power management básico — usuário usa cabo USB (powerbank/celular), sleep entre scans não é priority. Pular por enquanto.

## Phase 8 — App Flutter

> Detalhe completo vive em `/Volumes/SSD-Lucas/code/personal/nexus/ROADMAP.md` (raiz do app). Aqui só tracking de alto nível.

- [x] Setup Flutter + flutter_blue_plus + riverpod + go_router + hive_ce
- [x] Tela: pareamento BLE / discovery (radar + checklist dinâmica · 5 variantes de erro)
- [x] Tela: dashboard (KPIs do heartbeat · quick playbooks reais)
- [x] Tela: Scan — Recon · 5 abas (Wi-Fi / BLE / LAN / Probe / Dossier)
- [x] Tela: Hacking categorizada — Offense · 8 abas (WPA / PMKID / EVIL / KARMA / WPS / ARP / BLE / MITM)
- [x] Tela: Defense · 3 abas (Monitor / Settings / Watchdog) com toggle ARM/DISARM + mask granular persistido
- [x] Tela: Pcap viewer · Vault com export pro file system
- [x] Notificações em background (defense alerts críticos via `flutter_local_notifications`)
- [x] Mapa de RSSI / heatmap — `spectrumHistoryProvider` 13×24 alimenta Defense Monitor
- [x] Tema dark/hacker — Cold Console (verde matrix #00FF9C)
- [x] Cobertura 100 % do catálogo: 57 cmds JSON em `NxActions` + 38 TLVs em providers Riverpod
- [x] TargetContext global (sprint P · 2026-05-11) — telas ofensivas/LAN compartilham alvo, sem query params espalhados
- [x] Suite: 159 testes verdes (transport + parsers + actions + domain + widgets + integration)
- [ ] Build de produção assinado — depende do mantenedor (keystore Android, Apple Developer team, screenshots, política de privacidade pública)

## Phase 9 — Quality & Hardening

- [ ] Logging estruturado e filtrável (níveis por componente) — futuro: comando `log_set` em runtime via `esp_log_level_set`
- [~] Tests unitários do TLV codec — `test/test_tlv/` com 9 cases Unity (encode válido/sem payload/máximo/buffer pequeno/payload acima do max + decode round-trip/frame pequeno/inconsistência length). **Falta** coverage do command_router (mais complexo — depende de N componentes)
- [x] CI/CD: build do firmware no GitHub Actions (`.github/workflows/ci.yml` — build + size budget check + lint dos docs)
- [ ] Documentação por componente (header docs Doxygen-style) — futuro incremental
- [x] Threat model documentado — `THREAT_MODEL.md` com 5 surfaces (BLE/WiFi/BLE adversarial/Persistence/OTA), gaps priorizados, roadmap de hardening
- [x] Policy de uso responsável (uso lab-only) no README — checklist legal + jurisdições + link pro THREAT_MODEL

---

## Referências de progresso

- Resumo de status no `README.md` (seção "Status")
- Decisões fechadas viram entry em `CLAUDE.md`
- Cada feature implementada idealmente com seu próprio commit + log no monitor
