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
| `hacking_wifi` | promiscuous global | `inject_begin`/`inject_end` em deauth/beacon/jam/storm | Driver Wi-Fi só aceita TX de raw mgmt em modo promiscuous; `inject_end()` desliga ao terminar — **afeta `sniff_wifi` e `defense_start` em paralelo**. Ver seção 5. |
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
- **[c]** sniff_wifi + hacking_wifi no mesmo canal: ambos
  recebem/transmitem no mesmo set_channel. Fundamental pra
  `wpa_capture_kick` / `pmkid_capture_kick`. Como `s_busy` é per-componente,
  a flag por si só não bloqueia — mas desde commit `028e2e2` (2026-05-08)
  hacking_wifi liga **e desliga** promiscuous global em `inject_begin/end`.
  Isso quebra `sniff_wifi.s_mode` em paralelo: após o deauth retornar,
  callback do sniffer fica registrado mas o driver para de entregar
  frames. **Não é "JÁ funciona"** mais — ver seção 5 pra detalhes de
  por que as macros ainda funcionam (timing) e o que NÃO funciona
  (sniff longo após deauth curto).
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

### `karma_then_twin` ✅ implementado em 2026-05-05

**Mini-playbook embutido** (não é macro simples, tem decisão):

1. `sniff_wifi_karma_start(channel, duration_sec)` por N segundos.
2. Agrega `KARMA_HIT`s por SSID via hook **weak** `macros_hook_karma_hit`
   declarado em sniff_wifi.c, override forte no command_router.c.
3. Após duration + 500ms folga, escolhe o top-1 SSID (mais probed).
4. `evil_twin_start(top_ssid, optional_password, channel, max_conn=4)`.
5. Resposta final assíncrona: `{"status":"twin_up","ssid":"X","hits":N}`,
   `{"status":"no_hits"}` ou `{"status":"twin_failed","err":"..."}`.

Útil pra "automode": liga em ambiente desconhecido, ESP descobre o que
todo mundo procura, e oferece ele mesmo como AP. Args: `channel`,
`duration_sec` (5–120, default 30), `password` (opcional WPA2).

### `recon_full` ✅ implementado em 2026-05-05

**O que combina**: `wifi_scan(passive, all)` + `ble_scan(active, 15s)` +
(se `include_lan=true` e conectado) `lan_scan(timeout=3s)`.

Snapshot completo do entorno em 1 comando. Cada subcomponente emite
seus TLVs normais (`WIFI_SCAN_AP/DONE`, `BLE_SCAN_DEV/DONE`,
`LAN_HOST/DONE`). Resposta JSON tem 3 booleans indicando quais scans
iniciaram OK. Sem TLV próprio do macro — desejável agregar lado-app.

### `deauth_storm` ✅ implementado em 2026-05-05

**O que combina**: burst inicial de `deauth_count` deauths + loop alternando 30 RTS jam + 5 deauths até `jam_seconds`.

Implementação: nova função `hacking_wifi_deauth_storm()` que roda numa
**task única** alternando deauth e RTS — evita race em set_channel e
conflito do s_busy global do hacking_wifi (deauth e channel_jam são
mutex; storm é um job próprio).

Args: `bssid`, `target` (opcional, default broadcast), `channel` (1–14),
`deauth_count` (10–500, default 50), `jam_seconds` (5–60, default 15).

Aggressive DoS: kicka clients **e** impede reconexão. Só usar em redes
próprias.

### `mitm_capture` ⚠ versão "weak" implementada em 2026-05-05

**O que combina**: `arp_cut` modo drop + `pcap_start` filter=data + bssid.

Pipeline: ESP poisona vítima e gateway → todo tráfego da vítima vai pra
ESP_MAC → ESP **NÃO encaminha** (vítima offline) → mas captura tudo que
a vítima tenta enviar via promiscuous + emite TLV `PCAP_FRAME 0x40`.

Args: `target_ip`, `target_mac`, `gateway_ip`, `gateway_mac`, `bssid`,
`channel`, `duration_sec` (5–300, default 60).

Resposta: `{"resp":"mitm_capture","status":"started","mode":"weak_drop_capture"}`.

**Limitação importante**: NÃO é MITM clássico. Vítima fica offline durante
captura (sem internet). Para MITM real (forwarding com pacotes
encaminhados pra gateway, vítima online), exigiria:
1. `arp_throttle` com **forwarding real** (lwIP raw inject + recálculo de
   checksums + rate-limit per-flow)
2. Ou modo APSTA atuando como roteador entre AP legítimo e SoftAP novo

Ambos são refactors grandes. Por enquanto, "weak drop capture" cobre
casos de pesquisa de tráfego sem precisar manter conectividade da vítima.

### `tracker_hunt` ⚠ versão simples implementada em 2026-05-05

**O que combina**: `ble_scan(active, duration_sec)` longo. Devices com
flag `tracker` setada no payload `BLE_SCAN_DEV` (Apple Find My / Samsung
SmartTag / Tile / Chipolo) são reportados normalmente. Args:
`duration_sec` (30–3600, default 300).

**Agregação multi-scan no firmware ainda pendente**: a heurística completa
(device persistir em ≥3 scans consecutivos com RSSI estável → emit
`TRACKER_PERSISTENT 0x2B`) requer:
- Loop de scans repetidos com tabela de estado entre runs
- Histórico de RSSI por MAC com janela deslizante
- Correlação com mfg_data pra MACs random rotativos (AirTag muda ~15min)

Por enquanto, app correlaciona: salva devices vistos, refaz scan após
N min, compara, alerta visual se mesmo device persistir.

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

## 5. Caveat do promiscuous em hacking_wifi (desde 2026-05-08)

A partir do commit `028e2e2`, **`deauth` / `beacon_flood` / `channel_jam`
/ `deauth_storm`** entram numa fase mandatória antes do TX:

```c
inject_begin(channel):
    esp_wifi_set_promiscuous(true)
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE)

[ ...loop de TX raw com esp_wifi_80211_tx... ]

inject_end():
    esp_wifi_set_promiscuous(false)
```

Sem essa fase o driver Wi-Fi do IDF rejeita mgmt frames forjados com
`unsupport frame type` + `ESP_ERR_INVALID_ARG` — o filter só é bypassado
quando o STA está em modo raw. Combinada com o override de
`ieee80211_raw_frame_sanity_check` (ver `METHODS.md` seção `deauth`), é
o que torna o TX **efetivo de fato**.

### Quem é afetado

`esp_wifi_set_promiscuous` é **estado global** do driver. `inject_end`
desliga incondicionalmente. Componentes que dependem de promiscuous on
e estão rodando em paralelo perdem callbacks a partir desse momento:

| Componente em paralelo | Estado depois do `inject_end` |
|---|---|
| `sniff_wifi` (probe / eapol / pmkid / pcap / karma) | Callback registrado mas driver não entrega frames → fica silencioso |
| `defense_start` (todos os detectores rodam em promiscuous mgmt) | Idem, alertas param |
| `evil_twin` (APSTA + DHCP) | OK — independe de promiscuous (Soft-AP) |
| `attack_lan` (arp_cut/throttle/scan) | OK — opera em STA assoc, sem promiscuous |
| BLE (scan/hack) | OK — rádio separado |

### Por que as macros existentes ainda funcionam

- **`wpa_capture_kick`** = `wpa_capture` + 150ms delay + `deauth(broadcast)`.
  - `wpa_capture` (sniff_wifi.s_mode=eapol) liga promiscuous via sniff_wifi.
  - Após 150ms, `deauth_task` faz `inject_begin` (promiscuous já on → noop)
    e roda ~`count×3ms = 300ms` com `count=100`. Aí `inject_end` desliga
    promiscuous → **wpa_capture fica cego pelo resto do `duration_sec`**
    (default 90s). Frames EAPOL emitidos durante os 300ms do deauth
    ainda saem (sniffer ativo nesse intervalo); depois disso só M1/M2/M3/M4
    que chegarem no exato momento do deauth.
  - Na prática **funciona o suficiente** porque o deauth provoca reassoc
    imediato, e o handshake completo ocorre nos primeiros ms após o
    último frame de deauth — antes do `inject_end`. Mas se o cliente
    demora pra reassociar (rede saturada, sinal fraco), perde-se o
    handshake. Workaround: aumentar `count` pra estender a janela de
    captura ativa (count=200 → ~600ms de janela).

- **`pmkid_capture_kick`** — análogo, mas `deauth_count` default = 10
  → deauth dura só ~30ms. PMKID emerge no M1 (primeiro pacote pós-deauth)
  que costuma chegar nesse intervalo. Se não chegar → captura morta.

- **`evil_twin_kick`** — evil_twin não usa promiscuous (é SoftAP), então
  o `inject_end` do deauth opcional não afeta. 100% seguro.

- **`deauth_storm`** — uma task só, sem componente em paralelo esperado.

### Casos que NÃO funcionam mais

- `wpa_capture` longo (90s+) + `deauth` separado disparado pelo app no meio:
  funcionava antes (deauth pegava emprestado o promiscuous do sniff),
  agora **mata o sniff**. Use `wpa_capture_kick` ou aceite que só vai
  pegar o handshake imediato.
- `defense_start` rodando + `deauth`/`beacon_flood` no mesmo boot:
  **defense para de detectar** após o primeiro TX. Sequência correta:
  rodar TX → reiniciar defense.

### Workaround para "sticky promiscuous"

Quem precisar de sniff longo + TX raw deveria fazer um wrapper externo:

```c
esp_wifi_set_promiscuous(true);       // pega o estado pra mim
hacking_wifi_deauth(...);              // inject_begin: noop, inject_end: off
esp_wifi_set_promiscuous(true);       // ressuscita
```

Não está implementado — `inject_end` é incondicional. Pra fixar
corretamente, mover o pareamento set/unset pra dentro de `hacking_wifi`
com refcount, ou expor uma flag `keep_promisc`. Fica como tarefa de
retomada.

---

## 6. Rules of thumb

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
