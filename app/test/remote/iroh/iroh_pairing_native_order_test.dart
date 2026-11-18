// The native runtime has to be up before the identity is touched.
//
// `SecretKey.generate()` and `SecretKey.fromBytes()` call straight into the Rust
// core through flutter_rust_bridge; only `Iroh.init()` starts it. This test pins
// the consequence: whatever that first native touch throws - a missing library,
// an unusable key - must reach the caller as an `IrohChannelException`, because
// every other type collapses into the pairing page's generic sentence.
//
// A unit-test process has no Iroh native library on purpose, so the failure path
// is the one exercised here. The descriptor is fresh, so decoding and the expiry
// check pass and the code really does reach the native step.

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dsh_app/remote/mobile/iroh/iroh_channel.dart';
import 'package:dsh_app/remote/mobile/iroh/iroh_descriptor.dart';
import 'package:dsh_app/remote/mobile/iroh/iroh_pairing.dart';
import 'package:flutter_test/flutter_test.dart';

/// A descriptor the host could plausibly show: valid fields, a CA whose SHA-256
/// is its own instance id, and an expiry in the future.
IrohPairingDescriptor _freshDescriptor() {
  final caDer = List<int>.generate(64, (i) => i);
  return IrohPairingDescriptor(
    endpointId: 'a' * 64,
    localPort: 25443,
    irohCode: '123456',
    gatewayToken: 'A' * 43,
    caCertificateDer: caDer,
    instanceId: sha256.convert(caDer).toString(),
    expiresAt: DateTime.now().add(const Duration(minutes: 3)),
  );
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('pairOverIroh before the native runtime is up', () {
    test('reports a named iroh failure, never a bare platform exception', () async {
      final descriptor = _freshDescriptor();

      // The page only has a specific sentence for IrohChannelException.
      await expectLater(
        () => pairOverIroh(descriptor: descriptor, secretKeyBytes: null).timeout(
          const Duration(seconds: 30),
        ),
        throwsA(isA<IrohChannelException>()),
      );
    });

    test('a stored identity fails the same way, not with a raw loader error', () async {
      final descriptor = _freshDescriptor();
      final stored = base64Encode(List<int>.filled(32, 7));

      await expectLater(
        () => pairOverIroh(
          descriptor: descriptor,
          secretKeyBytes: base64Decode(stored),
        ).timeout(const Duration(seconds: 30)),
        throwsA(isA<IrohChannelException>()),
      );
    });

    test('an expired descriptor is still refused before any native call', () async {
      final caDer = List<int>.generate(64, (i) => i);
      final expired = IrohPairingDescriptor(
        endpointId: 'a' * 64,
        localPort: 25443,
        irohCode: '123456',
        gatewayToken: 'A' * 43,
        caCertificateDer: caDer,
        instanceId: sha256.convert(caDer).toString(),
        expiresAt: DateTime.now().subtract(const Duration(seconds: 1)),
      );

      await expectLater(
        () => pairOverIroh(descriptor: expired, secretKeyBytes: null),
        throwsA(isA<IrohDescriptorException>()),
      );
    });
  });
}
