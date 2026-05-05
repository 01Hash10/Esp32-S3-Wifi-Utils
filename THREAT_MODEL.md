# Threat Model — Esp32-S3-Wifi-Utils

Documento de modelagem de ameaças do firmware. Cobre:
1. Superfícies de ataque do **próprio firmware** (vetores contra o ESP)
2. Premissas de uso (o que assumimos sobre o ambiente operacional)
3. Mitigações em vigor + gaps conhecidos

> **Importante**: este documento NÃO é um manual de uso ofensivo do
> firmware contra terceiros. Para isso, ver `INTEGRATION.md` (protocolo)
> e `METHODS.md` (como cada feature funciona). Aqui falamos sobre como
> proteger o ESP em si e o ambiente em volta.

---

## 1. Premissas de uso (operational assumptions)

| # | Premissa | Razão |
|---|---|---|
| A1 | ESP roda em **lab controlado** ou em redes/devices **propriedade do operador** | Várias features são ofensivas — uso em redes alheias é ilegal na maioria das jurisdições |
| A2 | Operador é o único com **acesso físico** ao ESP enquanto rodando | Sem acesso físico, atacante não pode reflashar nem ler GPIO |
| A3 | Operador controla o **app cliente** (Flutter ou scripts) | Comandos vêm de fonte confiável — sem auth no GATT por enquanto |
| A4 | Powerbank/laptop USB é o power source | Sem dependência de bateria isolada → sem ataques de power glitching práticos |
| A5 | Ambiente RF típico: residencial / pequeno escritório | Não-otimizado pra ambientes saturados (aeroporto, conferência) |

---

## 2. Surface map — vetores contra o firmware

### 2.1 BLE GATT (cmd_ctrl + stream)

| Vetor | Risco | Mitigação atual | Gap |
|---|---|---|---|
| Pareamento sem PIN ("Just Works") | Qualquer device em range pode parear e enviar comandos | Nenhuma — confia em A3 (operador) | Pareamento com PIN/passkey (Phase 1 marca como "depois", ainda pendente) |
| JSON malformado em `cmd_ctrl` | Crash do parser → reset | `cJSON_ParseWithLength` + checagem de tipos antes de acessar campos. Erro retorna `bad_json`/`missing_cmd` | OK |
| Comando inválido | Nenhum efeito | `unknown_cmd` retornado | OK |
| Buffer overflow na escrita do GATT | Stack overflow | `chr_access_cb` valida `len <= 512`; usa buf 513 com NUL terminator | OK |
| Heartbeat reveal de info sensível | Free SRAM/PSRAM não são sensíveis isoladamente | Apenas uptime + heap stats são emitidos | Aceitável |
| BLE supervision timeout durante ataques longos | Conexão cai, app perde estado | Comandos longos viram tasks async, ack imediato; heartbeat de 5s mantém liveness | OK (após Phase 1 heartbeat) |

### 2.2 WiFi (modos STA, APSTA, promiscuous)

| Vetor | Risco | Mitigação atual | Gap |
|---|---|---|---|
| Pacotes 802.11 malformados em promiscuous | Crash do driver IDF | IDF tem hardening interno; nossos parsers (probe/eapol/pmkid/defense) validam comprimento antes de ler campos | OK genericamente; edge cases possíveis |
| WPS PIN brute-force lockout no ROUTER alvo | Lock no roteador real (efeito colateral) | API `wps_pin_test` é single-shot; app é responsável por backoff em M2D | Documentado em METHODS.md |
| Evil twin não-stop no boot | AP fake permanente sem operador presente | `evil_twin_start` é manual; nada inicia automático no boot | OK |
| ARP poison persistir após reboot do ESP | Cache da vítima permanece poisoned | `arp_throttle` limpa no fim; `arp_cut` não — vítima precisa renovar ARP (acontece naturalmente em ~60s) | Aceitável; documentado |
| Captive portal expor credenciais via Bluetooth aberto | Outras pessoas em range BLE veem credenciais via TLV | Confia em A3 — pareamento + subscribe necessários | Pareamento com PIN resolveria |

### 2.3 BLE adversarial (spam, scan abuse)

| Vetor | Risco | Mitigação atual | Gap |
|---|---|---|---|
| Spam contínuo aquecendo o módulo | Dano térmico ao ESP em longas sessões | Cap em duration_sec (60s pra adv_flood, 500 cycles pra apple_spam) | Aceitável |
| Watchdog disparando contra-ações em loop | Feedback loop alimentado por falso-positivo | `cooldown_ms` + `max_actions` + whitelist no watchdog | OK |

### 2.4 Persistência (NVS profiles)

| Vetor | Risco | Mitigação atual | Gap |
|---|---|---|---|
| Profile JSON malicioso preenchendo NVS | DoS por exhaustion | Cap 1024 bytes por profile + max ~50–100 profiles na partição 4KB | OK |
| Profile com playbook que executa em boot | Operação autônoma sem operador | Playbook NÃO roda automaticamente no boot — só via comando explícito `playbook_run` | OK |
| Conteúdo do profile lido por outro app | Vazamento se profile contém credenciais | Profile é opaco — app é responsável por não armazenar segredos lá | Documentar pro operador |

### 2.5 Atualizações de firmware

| Vetor | Risco | Mitigação atual | Gap |
|---|---|---|---|
| OTA via BLE | Atacante reflash o ESP via BLE | OTA não implementado (Phase 7 deferred) | N/A até OTA existir; quando implementar, exigir signed updates |
| Flash via USB | Acesso físico necessário | Confia em A2 | OK |

---

## 3. Mitigações arquiteturais

### 3.1 Componentes isolados com `s_busy` flags
Cada componente expõe estado próprio. Cross-component validados em
`COMPOSITION.md`. Reduz superfície de race conditions.

### 3.2 Tasks dedicadas pra trabalho long-running
Comandos que demoram (deauth, beacon_flood, sniff_*, evil_twin) rodam
em FreeRTOS task própria. NimBLE host task não bloqueia → BLE liveness
preservado. Ack imediato + DONE TLV no fim.

### 3.3 Hooks weak pra orquestração opcional
Watchdog e playbook usam weak symbols. Sem o componente, hooks são no-op
— zero overhead. Permite firmware modular.

### 3.4 Validation rigorosa em `command_router`
Toda função handler valida tipos e ranges via cJSON antes de chamar
primitivas. Erros retornam JSON com schema padronizado.

### 3.5 Watchdog com whitelist + cooldown + max_actions
Contra-ações são rate-limited e podem ser whitelisted. Evita feedback
loops em ambientes ruidosos.

---

## 4. Gaps conhecidos (priorizados)

| # | Gap | Severidade | Prioridade |
|---|---|---|---|
| G1 | Pareamento BLE sem PIN | Média | Alta — alguém em range pode controlar |
| G2 | Sem auth/auth no GATT | Média | Alta — depende de G1 |
| G3 | OTA não implementado (impede patches remotos) | Baixa | Média — workaround é flash via USB |
| G4 | Tests unitários cobrem só TLV codec, não command_router | Baixa | Baixa — primitivas têm validação manual |
| G5 | Sem rate limit globalde comandos | Baixa | Baixa — flood de comandos via BLE = só travamento de NimBLE |
| G6 | Debug logs (`ESP_LOGI`) emitidos sempre — info revelada via console | Mínima | Baixa — console é local, sem mass deployment |

---

## 5. Roadmap de hardening

Em ordem de impacto:

1. **G1+G2: PIN pairing + GATT auth** — Phase 1 pendente. Implementar
   `BLE_GAP_AUTHENTICATE` + bond storage no NVS. Após bond, comandos
   só de devices conhecidos.
2. **OTA assinado** — Phase 7 longo prazo. ECDSA-P256 sign + rollback
   anti-downgrade. ESP-IDF tem `secure_boot_v2` que cobre.
3. **Tests de integração** — fuzzer para command_router (cJSON malformado,
   args extremos) e snifer (frames 802.11 malformados).
4. **Logging estruturado** — `esp_log_level_set` per-tag em runtime
   via comando `log_set` no router. Permite reduzir verbosidade em
   produção.

---

## 6. Política de uso responsável

Este firmware contém features ofensivas (deauth, evil twin, captive
portal, ARP poisoning) **só legais em ambientes próprios ou com
autorização explícita do dono da rede/device**.

Uso fora desses cenários:
- Pode violar leis de inviolabilidade de comunicações (Brasil: Lei
  9.296/96; EU: GDPR + ePrivacy; US: Computer Fraud and Abuse Act).
- Pode causar danos a equipamentos de terceiros (DoS por jam continuado).
- Pode ser detectado e logado pelo target (forensics: nosso fingerprint
  inclui ESP MAC, mfg_data Apple/Samsung patterns reconhecíveis).

**Antes de testar qualquer coisa**:
1. Verifique que está em ambiente que você controla (hardware seu OU
   autorização escrita do dono).
2. Documente o teste (data, escopo, alvos) — facilita defesa em caso
   de questionamento legal.
3. Não exponha o ESP em redes públicas — usar Hotspot pessoal ou rede
   isolada de lab.
4. Após teste, parar serviços (`evil_twin_stop`, `captive_portal_stop`,
   `arp_cut_stop`) — não deixar AP fake ou MITM rodando.

Em caso de dúvida sobre legalidade: **pergunte a um advogado, não
pergunte ao chatbot**.
