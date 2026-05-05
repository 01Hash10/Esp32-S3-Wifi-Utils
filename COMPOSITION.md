# Composition — Combinações de ataques & orquestração

Documento de referência sobre **como compor features** do firmware
WifiUtils. Complementa `METHODS.md` (que documenta cada método isolado)
focando em:

1. **Auditoria de exclusão**: quais componentes têm estado mutuamente
   exclusivo e por quê.
2. **Matriz de compatibilidade**: o que pode rodar em paralelo.
3. **Catálogo de macros**: comandos compostos planejados.
4. **Padrões de orquestração**: client-side, macros, playbook engine.

---

## 1. Auditoria de busy flags

| Componente | Flag | Escopo | Razão da exclusão |
|---|---|---|---|
| `scan_wifi` | `s_busy` | Todo o componente | IDF `esp_wifi_scan_start` não suporta scans concorrentes |
| `scan_ble` | `s_busy` | Todo o componente | NimBLE `ble_gap_disc` é singleton |
| `hacking_wifi` | `s_busy` | deauth + beacon_flood + channel_jam | Concorrência em `esp_wifi_set_channel` + TX queue compartilhada |
| `hacking_ble` | `s_busy` | apple/samsung/google/multi spam | NimBLE `ble_gap_adv_set_data` é singleton (1 adv por vez) |
| `attack_lan` | `s_cut.stop` | arp_cut | 2 poison loops sobrescreveriam o cache |
| `attack_lan` | `s_thr.stop` | arp_throttle | Idem; e cycle on/off conflita com cut contínuo |
| `attack_lan` | `s_lan_busy` | lan_scan | Cache do lwIP é único; lan_scan + arp_cut/throttle rodando juntos = cache poluído |
| `sniff_wifi` | `s_mode` | probe / eapol / pmkid / pcap / karma | 1 promiscuous CB + 1 filter por vez |
| `evil_twin` | `s_active` | SoftAP fake | Hardware suporta 1 AP só |
| `captive_portal` | `s_active` | DNS:53 + HTTP:80 servers | Singleton (1 par de tasks ouvindo nas portas) |
| `watchdog` | `s_active` | gating de contra-ações | Estado global (1 watchdog por boot). Hooks via weak symbols nos detectores |

### Cross-component (mutex entre componentes diferentes)

`attack_lan` foi reforçado em 2026-05-05: agora `arp_cut`, `arp_throttle`
e `lan_scan` checam mutuamente. Antes era possível iniciar `lan_scan`
durante `arp_cut` → resultados corrompidos.

Demais cross-component são por **canal de rádio** (não por busy flag):

- WiFi STA conectado **bloqueia o canal** ao AP. Promiscuous + sniff
  no mesmo canal = OK; em outros canais = quebra a STA.
- `evil_twin` (APSTA) força beacon do AP no canal escolhido. Sniff/scan
  ativo nesse canal coexistem; em outros canais = STA quebra.
- BLE (NimBLE) e WiFi rodam em rádios independentes — sempre OK em paralelo.

---

## 2. Matriz de compatibilidade

✓ = roda em paralelo  ✗ = bloqueia (busy flag)  
**ch** = OK desde que mesmo canal de rádio  
*nota = ver linha abaixo*

| | scan_wifi | sniff_wifi | hacking_wifi | evil_twin | attack_lan(STA) | scan_ble | hacking_ble |
|---|---|---|---|---|---|---|---|
| **scan_wifi**     | ✗ | ✗*[a]* | ✗*[a]* | ✗*[a]* | ✗*[b]* | ✓ | ✓ |
| **sniff_wifi**    |   | ✗ | **ch**[c] | **ch**[c] | ✗*[b]* | ✓ | ✓ |
| **hacking_wifi**  |   |   | ✗ | **ch** | ✗*[b]* | ✓ | ✓ |
| **evil_twin**     |   |   |   | ✗ | ✗*[d]* | ✓ | ✓ |
| **attack_lan(STA)**|   |   |   |   | parcial[e] | ✓ | ✓ |
| **scan_ble**      |   |   |   |   |   | ✗ | ✗*[f]* |
| **hacking_ble**   |   |   |   |   |   |   | ✗ |

**Notas**:

- **[a]** scan_wifi monopoliza a fila do driver WiFi enquanto o `esp_wifi_scan_start`
  está em andamento. Esperar o `WIFI_SCAN_DONE` antes de iniciar o próximo.
- **[b]** STA conectada bloqueia o canal no AP da rede. Iniciar
  `sniff_wifi`/`scan_wifi`/`hacking_wifi` em outro canal **derruba a
  conexão STA** (e portanto o `arp_cut`/`arp_throttle` que depende dela).
- **[c]** sniff_wifi.pcap + hacking_wifi.deauth no mesmo canal: ambos
  recebem/transmitem no mesmo set_channel. Fundamental pra
  `wpa_capture_kick`. Como `s_busy` é per-componente, JÁ funciona — mas
  app precisa garantir mesmo canal.
- **[d]** evil_twin (modo APSTA) e STA conectada: incompatível porque
  STA precisa estar livre do AP corrente pra modo APSTA não conflitar
  com canal do AP do twin. Sempre `wifi_disconnect` antes do `evil_twin_start`.
- **[e]** attack_lan: arp_cut e arp_throttle são mutex entre si; lan_scan
  é mutex com ambos (audit fix de 2026-05-05).
- **[f]** scan_ble (GAP discover) e hacking_ble (adv) ambos usam o
  controlador NimBLE. NimBLE permite scan + adv simultâneos em peripheral
  duplo (já temos GATT adv durante scan), mas spam_* faz `adv_set_data`
  brutalmente trocando os bytes — vai bagunçar o adv do GATT durante o
  spam. spam_apple/samsung/google/multi pausa GATT adv no início; trocar
  por scan novo entre dois spams é OK mas 2 spams concorrentes não.

---

## 3. Catálogo de macros (Phase 3.5)

Comandos compostos que disparam 2+ jobs internamente, ack como qualquer
comando, emitem TLVs componentes + DONE final.

### `wpa_capture_kick` ✅ implementado em 2026-05-05

**O que combina**: `wpa_capture(bssid, channel)` + delay 150ms + `deauth(broadcast)`.

**Args**: `bssid`, `channel`, `duration_sec` (5–600, default 90),
`deauth_count` (5–200, default 30).

Implementação no `command_router.c`. Sem TLV próprio — saída via TLVs
do wpa_capture (`WPA_EAPOL 0x18` + `WPA_CAPTURE_DONE 0x19`).

### `pmkid_capture_kick` ✅ implementado em 2026-05-05

**O que combina**: `pmkid_capture(bssid, channel)` + delay 150ms + `deauth(broadcast)`.

**Args**: `bssid`, `channel`, `duration_sec` (5–600, default 60),
`deauth_count` (1–100, default 10).

PMKID precisa só do M1 (que vem após cliente iniciar associação). Deauth
força reassoc → AP manda M1. Mais leve que wpa_capture_kick.

### `evil_twin_kick` ✅ implementado em 2026-05-05

**O que combina**: `evil_twin_start(ssid, channel)` + (opcional) `deauth(legit_bssid, channel)`

Setup completo do evil twin: sobe AP fake e simultaneamente martela o AP
legítimo. Clients perdidos no legítimo veem o twin com mesmo SSID e
associam.

**Args**: `ssid`, `channel`, `password?`, `legit_bssid?` (opcional — se
ausente, só sobe twin sem deauth), `deauth_count` (5–200, default 30).
Resposta inclui `kick_fired` (bool) indicando se o deauth foi disparado.

### `karma_then_twin`

**Mini-playbook embutido** (não é macro simples, tem decisão):

1. `karma_start(channel, duration_sec=30)` por 30s.
2. Aggrega `KARMA_HIT`s por SSID, conta hits.
3. Pega o top-1 SSID (mais probed).
4. `evil_twin_start(top_ssid, channel)`.
5. Mantém ativo até `karma_then_twin_stop` ou timeout absoluto.

Útil pra "automode": liga em ambiente desconhecido, ESP descobre o que
todo mundo procura, e oferece ele mesmo como AP.

### `recon_full` ✅ implementado em 2026-05-05

**O que combina**: `wifi_scan(passive, all)` + `ble_scan(active, 15s)` +
(se `include_lan=true` e conectado) `lan_scan(timeout=3s)`.

Snapshot completo do entorno em 1 comando. Cada subcomponente emite
seus TLVs normais (`WIFI_SCAN_AP/DONE`, `BLE_SCAN_DEV/DONE`,
`LAN_HOST/DONE`). Resposta JSON tem 3 booleans indicando quais scans
iniciaram OK. Sem TLV próprio do macro — desejável agregar lado-app.

### `deauth_storm`

**O que combina**: `deauth(bssid, count=200)` + `channel_jam(channel, 30s)`

Aggressive DoS: kicka clients **e** impede reconexão por 30s. Só usar
em redes próprias.

### `mitm_capture` (depende de Phase 3 throttle "real")

**O que combina**: `arp_cut(target, throttle modo forwarding)` + `pcap_start(channel, filter=data, target_mac=...)`

**Limitação atual**: nosso `arp_throttle` não faz forwarding real (só
cycle on/off). Pra mitm_capture funcionar, precisa do "forwarding com
rate limit" do roadmap (ARP poisoning real → ESP repassa pacotes).
Marcado como blocked até essa feature.

### `tracker_hunt`

**O que combina**: `ble_scan(active, 60s)` em loop + agregação de devices
com flag `tracker` setada.

Cada `BLE_SCAN_DEV` recebido é agregado por MAC (se MAC privado randomizar,
pode usar mfg_data hash como ID). Se um tracker aparecer em 3 scans
consecutivos com RSSI estável → emite alerta `TRACKER_PERSISTENT 0x2B`.

Útil pra rodar 24/7 detectando AirTag stalking sem precisar do app
processar.

---

## 4. Padrões de orquestração

### A. Client-side chaining (já viável hoje)

App/script envia comandos em sequência, escutando os `*_DONE` TLVs.

```python
# pseudocode
await send("karma_start", channel=6, duration_sec=30)
hits = await collect_until("KARMA_DONE")
top_ssid = pick_top(hits)
await send("evil_twin_start", ssid=top_ssid, channel=6)
```

**Prós**: máxima flexibilidade, total observabilidade do estado, lógica
de decisão complexa em Python/Dart.  
**Cons**: depende de BLE conectado o tempo todo. Se app cair, workflow
para no meio.

### B. Macros firmware (Phase 3.5 itens marcados ✗ ainda)

Comandos hardcoded que disparam combinações comuns. App envia 1
comando, firmware executa N jobs.

**Prós**: 1 round-trip BLE, roda mesmo se app desconectar (firmware
mantém os jobs rodando). Garante timing consistente entre os jobs.  
**Cons**: explosão combinatorial se virar moda. Não cobre lógica
custom (precisa de playbook).

### C. Playbook engine (Phase 3.5 médio prazo)

Comando `playbook_run` com JSON declarativo:

```jsonc
{
  "cmd": "playbook_run",
  "seq": 1,
  "steps": [
    {"type": "cmd", "cmd": "karma_start", "args": {"channel": 6, "duration_sec": 30}},
    {"type": "wait_event", "event": "KARMA_DONE"},
    {"type": "select_top", "from": "KARMA_HIT", "by": "ssid", "n": 1, "into": "$top_ssid"},
    {"type": "if", "cond": "$top_ssid != null", "then": [
      {"type": "cmd", "cmd": "evil_twin_start", "args": {"ssid": "$top_ssid", "channel": 6}},
      {"type": "wait_ms", "ms": 60000},
      {"type": "cmd", "cmd": "evil_twin_stop"}
    ]}
  ]
}
```

**Prós**: workflows complexos sem app conectado (autônomo). Persistível
em NVS pra "modo lab" / "modo aula".  
**Cons**: design + interpreter + testes consideráveis. Difícil debugar.

Ordem de implementação prevista:
1. Reforço de exclusão cross-component (DONE em 2026-05-05).
2. Macros simples (`wpa_capture_kick`, `pmkid_capture_kick`).
3. Macros com decisão (`karma_then_twin`).
4. Playbook engine completo (após app Flutter existir e UX justificar).

---

## 5. Rules of thumb

- **Mesmo canal**: features que TX/RX no rádio WiFi têm que estar no
  mesmo canal pra funcionarem em paralelo. Se canais diferentes, o
  último `set_channel` ganha.
- **Modo do rádio**: STA, APSTA e promiscuous coexistem; mas STA
  conectada trava o canal no AP corrente.
- **BLE vs WiFi**: rádios independentes — sempre paralelizáveis (limite
  só de CPU/heap).
- **Sequencing > parallelism**: na dúvida, usar o padrão A (client-side)
  com `await *_DONE` antes de iniciar o próximo. Evita race conditions
  e simplifica debug.
- **Documentar combinações**: toda macro nova deve ter entrada aqui
  + entrada em `METHODS.md` (regra paralela ao INTEGRATION.md/ROADMAP.md).
