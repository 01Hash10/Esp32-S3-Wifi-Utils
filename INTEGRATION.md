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

> A ser detalhado quando o GATT server estiver implementado (Phase 1, próximo passo).

Resumo planejado:

1. Scan no Flutter por nome `WifiUtils-` ou pelo Service UUID.
2. Connect.
3. Negociar MTU = 247 (request via `requestMtu(247)` no `flutter_blue_plus`).
4. Discover services + characteristics.
5. Subscribe aos `Notify` em ambas characteristics.
6. Enviar `{"cmd":"hello"}` no `cmd_ctrl` para handshake → device responde com info.

Pareamento: **Just Works** na Phase 1 (sem PIN). Pareamento com PIN/passkey
fica pra fase posterior se necessário.

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

> _Vazio. Será preenchido em ordem conforme cada feature é implementada._

| `cmd` | Args | Resposta | Phase |
|---|---|---|---|
| _(nenhum ainda)_ | | | |

## Catálogo de eventos TLV (`stream`)

> _Vazio. Será preenchido em ordem conforme cada feature é implementada._

| `type` (hex) | Nome | Direção | Payload | Phase |
|---|---|---|---|---|
| _(nenhum ainda)_ | | | | |

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

### Conexão básica (planejado)

```dart
// flutter_blue_plus pseudo-code, será expandido na próxima entrega
final device = await FlutterBluePlus.scanForName('WifiUtils-');
await device.connect();
await device.requestMtu(247);
final svc = (await device.discoverServices())
    .firstWhere((s) => s.uuid == Guid('e7c0c5a0-4f1f-4b1a-9d6c-1a8d4b5e0c01'));
final cmd = svc.characteristics.firstWhere((c) => c.uuid == Guid('...0c02'));
final stream = svc.characteristics.firstWhere((c) => c.uuid == Guid('...0c03'));
await cmd.setNotifyValue(true);
await stream.setNotifyValue(true);
```

---

## Histórico de mudanças do protocolo

| Data | Phase | Mudança |
|---|---|---|
| 2026-05-04 | Phase 1 | Definição inicial: service UUID, duas characteristics, frame TLV, schema JSON |
