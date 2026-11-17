// The iroh control plane: the handshake and proxy lines the dsh-mobile iroh
// host expects, and the reply parsing that decides whether a peer may proxy.
//
// Pure string work — no native library, so this runs in plain `flutter test`.

import 'dart:convert';

import 'package:dsh_app/remote/mobile/iroh/iroh_wire.dart';
import 'package:flutter_test/flutter_test.dart';

Map<String, Object?> _decodeLine(String line) {
  expect(line.endsWith('\n'), isTrue, reason: 'the host reads one line per message');
  return jsonDecode(line.substring(0, line.length - 1)) as Map<String, Object?>;
}

void main() {
  group('control lines', () {
    test('a hello names the device and carries no code', () {
      final message = _decodeLine(irohHandshakeLine(name: 'DSH Go'));
      expect(message, {'version': 1, 'type': 'hello', 'name': 'DSH Go'});
    });

    test('a pair adds the six-digit code', () {
      final message = _decodeLine(irohHandshakeLine(name: 'phone', code: '123456'));
      expect(message, {'version': 1, 'type': 'pair', 'code': '123456', 'name': 'phone'});
    });

    test('the proxy opener is the exact line the host matches', () {
      expect(irohProxyLine, '{"version":1,"type":"proxy"}\n');
    });

    test('the ALPN is the one both ends pin', () {
      expect(irohAlpn, 'dsh-mobile-iroh/0');
      expect(irohWireVersion, 1);
    });
  });

  group('parseIrohHandshakeReply', () {
    test('accepts pair-ok only where a pair was sent', () {
      final ok = parseIrohHandshakeReply('{"version":1,"type":"pair-ok","name":"phone"}', expectPair: true);
      expect(ok, isA<IrohHandshakeOk>());
      expect((ok as IrohHandshakeOk).name, 'phone');

      final wrong = parseIrohHandshakeReply('{"version":1,"type":"pair-ok"}', expectPair: false);
      expect(wrong, isA<IrohHandshakeFailed>());
      expect((wrong as IrohHandshakeFailed).reason, 'handshake_refused');
    });

    test('accepts hello-ok only where a hello was sent', () {
      final ok = parseIrohHandshakeReply('{"version":1,"type":"hello-ok"}', expectPair: false);
      expect(ok, isA<IrohHandshakeOk>());
      expect((ok as IrohHandshakeOk).name, isNull);

      final wrong = parseIrohHandshakeReply('{"version":1,"type":"hello-ok"}', expectPair: true);
      expect((wrong as IrohHandshakeFailed).reason, 'handshake_refused');
    });

    test('pair-fail keeps the host reason, so the person sees why', () {
      final denied = parseIrohHandshakeReply('{"version":1,"type":"pair-fail","reason":"not_paired"}', expectPair: true);
      expect((denied as IrohHandshakeFailed).reason, 'not_paired');

      final anonymous = parseIrohHandshakeReply('{"version":1,"type":"pair-fail"}', expectPair: true);
      expect((anonymous as IrohHandshakeFailed).reason, 'handshake_refused');

      final blank = parseIrohHandshakeReply('{"version":1,"type":"pair-fail","reason":""}', expectPair: true);
      expect((blank as IrohHandshakeFailed).reason, 'handshake_refused');
    });

    test('malformed input is a bad handshake, never an acceptance', () {
      for (final line in <String>['', 'not json', '[]', 'null', '{"type":"pair-ok"}']) {
        final reply = parseIrohHandshakeReply(line, expectPair: true);
        expect(reply, isA<IrohHandshakeFailed>(), reason: 'line: $line');
      }
    });

    test('a newer wire version is refused rather than half-understood', () {
      final reply = parseIrohHandshakeReply('{"version":2,"type":"pair-ok"}', expectPair: true);
      expect((reply as IrohHandshakeFailed).reason, 'bad_handshake');
    });
  });
}
