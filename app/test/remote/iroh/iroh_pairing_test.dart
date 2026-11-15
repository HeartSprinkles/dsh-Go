// What an iroh pairing hands back to the store: the host config (transport,
// endpoint id, loopback port) and the three secrets, without any iroh call.
//
// The outcome object itself is plain data, so this runs in `flutter test`
// without the native library; only `IrohChannel.open` needs it.

import 'dart:convert';

import 'package:dsh_app/remote/mobile/iroh/iroh_descriptor.dart';
import 'package:dsh_app/remote/mobile/iroh/iroh_pairing.dart';
import 'package:dsh_app/remote/mobile/mobile_config.dart';
import 'package:dsh_app/remote/mobile/mobile_pairing.dart';
import 'package:flutter_test/flutter_test.dart';

/// Stand-in CA bytes: the descriptor only hashes them, never parses X.509.
final _caDer = List<int>.generate(64, (i) => i);

/// An endpoint id and its derived `iroh.localhost` origin.
final _endpointId = 'a' * 64;

IrohPairingDescriptor _descriptor({String? instanceId, DateTime? expiresAt}) =>
    IrohPairingDescriptor(
      endpointId: _endpointId,
      localPort: 25443,
      irohCode: '012345',
      gatewayToken: 'A' * 43,
      caCertificateDer: _caDer,
      instanceId: instanceId ?? sha256Hex(_caDer),
      expiresAt: expiresAt ?? DateTime.now().add(const Duration(minutes: 5)),
    );

MobileSession _session({required String instanceId, String? deviceToken = 'device-token', String deviceId = 'device-1'}) =>
    MobileSession(
      instanceId: instanceId,
      deviceId: deviceId,
      deviceToken: deviceToken,
      sessionToken: 'session',
      csrfToken: 'csrf',
      sessionExpiresAt: DateTime.fromMillisecondsSinceEpoch(1800000000000),
      deviceExpiresAt: DateTime.fromMillisecondsSinceEpoch(1900000000000),
    );

void main() {
  group('IrohPairingOutcome', () {
    final descriptor = _descriptor();
    final keyBytes = List<int>.generate(32, (i) => i);

    IrohPairingOutcome outcome({MobileSession? session}) => IrohPairingOutcome(
      descriptor: descriptor,
      session: session ?? _session(instanceId: descriptor.instanceId),
      secretKeyBytes: keyBytes,
      deviceLabel: 'DSH Go',
    );

    test('the config carries the transport, endpoint id and loopback port', () {
      final config = outcome().toConfig(id: 'mobile-1', name: '家');
      expect(config.id, 'mobile-1');
      expect(config.name, '家');
      expect(config.transport, MobileTransport.iroh);
      expect(config.isIroh, isTrue);
      expect(config.endpointId, _endpointId);
      expect(config.localPort, 25443);
      expect(config.origin, descriptor.origin);
      expect(config.deviceId, 'device-1');
      expect(config.deviceExpiresAt, DateTime.fromMillisecondsSinceEpoch(1900000000000));
    });

    test('the CA fingerprint is the descriptor instance id, so the prompt matches', () {
      final config = outcome().toConfig(id: 'mobile-1', name: '家');
      expect(config.caFingerprint, descriptor.instanceId);
      expect(config.instanceId, descriptor.instanceId);
    });

    test('the secrets are the device token, the CA PEM and the iroh identity', () {
      final secrets = outcome().toSecrets();
      expect(secrets.deviceToken, 'device-token');
      expect(secrets.caPem, startsWith('-----BEGIN CERTIFICATE-----'));
      expect(secrets.caPem, endsWith('-----END CERTIFICATE-----\n'));
      expect(base64Decode(secrets.irohSecretKey), keyBytes);
    });

    test('a gateway that reports its own instance id wins over the descriptor', () {
      final renamed = outcome(session: _session(instanceId: 'e' * 64)).toConfig(id: 'mobile-1', name: '家');
      expect(renamed.instanceId, 'e' * 64);
      // The pinned CA still comes from the descriptor: it is what the descriptor
      // proved, and the trust prompt showed its fingerprint.
      expect(renamed.caFingerprint, descriptor.instanceId);
    });

    test('a session without a device token stores an empty one, not a crash', () {
      final anonymous = outcome(
        session: _session(instanceId: descriptor.instanceId, deviceToken: null, deviceId: ''),
      );
      expect(anonymous.toSecrets().deviceToken, '');
      expect(anonymous.toConfig(id: 'mobile-1', name: 'n').deviceId, isNull);
      expect(anonymous.toConfig(id: 'mobile-1', name: 'n').deviceExpiresAt, DateTime.fromMillisecondsSinceEpoch(1900000000000));
    });

    test('the outcome config round-trips through JSON like any saved host', () {
      final config = outcome().toConfig(id: 'mobile-1', name: '家');
      expect(MobileHostConfig.fromJson(jsonDecode(jsonEncode(config.toJson()))), config);
    });
  });

  group('IrohPairingDescriptor', () {
    test('a fresh descriptor is fresh, an expired one is not', () {
      final now = DateTime.now();
      expect(_descriptor(expiresAt: now.add(const Duration(minutes: 1))).isFreshAt(now), isTrue);
      expect(_descriptor(expiresAt: now.subtract(const Duration(seconds: 1))).isFreshAt(now), isFalse);
    });

    test('the origin is the derived iroh.localhost name at the loopback port', () {
      final descriptor = _descriptor();
      expect(descriptor.hostname, '${'a' * 32}.${'a' * 32}.iroh.localhost');
      expect(descriptor.origin, 'https://${'a' * 32}.${'a' * 32}.iroh.localhost:25443');
    });
  });
}
