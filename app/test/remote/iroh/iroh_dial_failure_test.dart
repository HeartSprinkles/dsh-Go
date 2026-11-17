// How a failed dial becomes an error the UI can name.
//
// The pairing page only shows a specific sentence for `IrohChannelException`;
// anything else collapses into the generic "pairing did not finish" text. A
// native dial failure therefore has to be mapped onto that type, which is what
// `irohDialFailure` does — and why these cases matter.
//
// Pure Dart: it only builds exceptions, never an endpoint.

import 'dart:async';

import 'package:dsh_app/remote/mobile/iroh/iroh_channel.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('irohDialFailure', () {
    test('keeps an existing channel error untouched', () {
      const original = IrohChannelException('handshake_refused');
      final mapped = irohDialFailure(original);
      expect(identical(mapped, original), isTrue);
      expect(mapped.reason, 'handshake_refused');
    });

    test('turns a dial timeout into its own reason', () {
      final mapped = irohDialFailure(TimeoutException('handshake', const Duration(seconds: 20)));
      expect(mapped.reason, 'connect_timeout');
      expect(mapped.detail, isNull);
    });

    test('keeps the native text of any other failure for the details line', () {
      final mapped = irohDialFailure(StateError('could not resolve to any address'));
      expect(mapped.reason, 'connect_failed');
      expect(mapped.detail, contains('could not resolve to any address'));
    });

    test('a refusal keeps the reason the link maps to a non-retryable error', () {
      // The reason decides retryability in mobile_link.dart's irohError().
      expect(irohDialFailure(StateError('boom')).reason, isNot('handshake_refused'));
      expect(irohDialFailure(const IrohChannelException('pair-fail')).reason, 'pair-fail');
    });
  });
}
