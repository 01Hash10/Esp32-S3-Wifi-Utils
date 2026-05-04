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

  // Listener para frames TLV no stream (a partir da Phase 2)
  stream.lastValueStream.listen((bytes) {
    // bytes[0..1] = length BE, bytes[2] = type, bytes[3] = seq, resto = payload
    print('stream recv: ${bytes.length} bytes, type=0x${bytes[2].toRadixString(16)}');
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
