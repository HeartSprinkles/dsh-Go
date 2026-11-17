import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dsh_app/remote/mobile/iroh/iroh_descriptor.dart';
import 'package:flutter_test/flutter_test.dart';

/// Stand-in CA bytes: the decoder only hashes them, never parses X.509.
final _caDer = List<int>.generate(64, (i) => i);

String get _instanceId => sha256.convert(_caDer).toString();

/// 64 hex characters, i.e. what an iroh endpoint id looks like on the wire.
final _endpointId = 'a' * 64;

String get _hostname => '${'a' * 32}.${'a' * 32}.iroh.localhost';

Map<String, Object?> _valid({
  String? endpointId,
  String? hostname,
  int port = 25443,
  String? instanceId,
  String? caBase64,
}) {
  final id = endpointId ?? _endpointId;
  final host = hostname ?? '${id.substring(0, 32)}.${id.substring(32)}.iroh.localhost';
  return <String, Object?>{
    'version': 1,
    'type': 'dsh-mobile-iroh-pairing',
    'endpointId': id,
    'origin': 'https://$host:$port',
    'localPort': port,
    'irohCode': '012345',
    'gatewayToken': 'A' * 43,
    'caCertificate': caBase64 ?? base64Encode(_caDer),
    'instanceId': instanceId ?? _instanceId,
    'expiresAt': DateTime.now().add(const Duration(minutes: 5)).millisecondsSinceEpoch,
  };
}

Matcher _rejects(String reason) => throwsA(isA<IrohDescriptorException>().having((e) => e.reason, 'reason', reason));

void main() {
  group('IrohPairingDescriptor.decode', () {
    test('accepts a descriptor the plugin would emit', () {
      final descriptor = IrohPairingDescriptor.decode(jsonEncode(_valid()));

      expect(descriptor.endpointId, _endpointId);
      expect(descriptor.localPort, 25443);
      expect(descriptor.irohCode, '012345');
      expect(descriptor.origin, 'https://$_hostname:25443');
      expect(descriptor.hostname, _hostname);
      expect(descriptor.caCertificateDer, _caDer);
      expect(descriptor.isFreshAt(DateTime.now()), isTrue);
    });

    test('splits the endpoint id in half for the gateway hostname', () {
      final id = '0123456789abcdef' * 4;
      final descriptor = IrohPairingDescriptor.decode(jsonEncode(_valid(endpointId: id)));

      expect(descriptor.hostname, '0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef.iroh.localhost');
    });

    // The plugin compares the key set for equality, so an extra field means a
    // different producer and cannot be ignored.
    test('rejects an extra field', () {
      expect(() => IrohPairingDescriptor.decode(jsonEncode({..._valid(), 'extra': 1})), _rejects('unexpected_fields'));
    });

    test('rejects a missing field', () {
      final value = _valid()..remove('irohCode');
      expect(() => IrohPairingDescriptor.decode(jsonEncode(value)), _rejects('unexpected_fields'));
    });

    test('rejects an origin that does not match the endpoint and port', () {
      final value = _valid()..['origin'] = 'https://evil.example:25443';
      expect(() => IrohPairingDescriptor.decode(jsonEncode(value)), _rejects('invalid_origin'));
    });

    test('rejects an origin whose port disagrees with localPort', () {
      final value = _valid()..['origin'] = 'https://$_hostname:25444';
      expect(() => IrohPairingDescriptor.decode(jsonEncode(value)), _rejects('invalid_origin'));
    });

    test('rejects a CA whose hash is not the instance id', () {
      final value = _valid(instanceId: 'b' * 64);
      expect(() => IrohPairingDescriptor.decode(jsonEncode(value)), _rejects('ca_fingerprint_mismatch'));
    });

    test('rejects a malformed token, code, endpoint id or port', () {
      final patches = <String, Map<String, Object?>>{
        'token': {'gatewayToken': 'short'},
        'code': {'irohCode': '12345'},
        'endpoint': {'endpointId': 'A' * 64},
        'port': {'localPort': 80},
      };
      patches.forEach((label, patch) {
        expect(
          () => IrohPairingDescriptor.decode(jsonEncode({..._valid(), ...patch})),
          throwsA(isA<IrohDescriptorException>()),
          reason: label,
        );
      });
    });

    test('rejects a different descriptor type or version', () {
      expect(
        () => IrohPairingDescriptor.decode(jsonEncode({..._valid(), 'type': 'other'})),
        _rejects('unsupported_descriptor'),
      );
      expect(
        () => IrohPairingDescriptor.decode(jsonEncode({..._valid(), 'version': 2})),
        _rejects('unsupported_descriptor'),
      );
    });

    test('bounds descriptor bytes, CA size and timestamp range', () {
      expect(() => IrohPairingDescriptor.decode(' ' * 2201), _rejects('descriptor_too_large'));
      expect(() => IrohPairingDescriptor.decode(jsonEncode(_valid(caBase64: ''))), _rejects('invalid_ca'));
      for (final expiry in [DateTime.now().add(const Duration(minutes: 11)).millisecondsSinceEpoch, 9000000000000000]) {
        expect(
          () => IrohPairingDescriptor.decode(jsonEncode({..._valid(), 'expiresAt': expiry})),
          _rejects('invalid_expiry'),
        );
      }
    });

    test('rejects non-JSON input and non-object JSON', () {
      expect(() => IrohPairingDescriptor.decode('not json'), _rejects('not_json'));
      expect(() => IrohPairingDescriptor.decode('[1,2]'), _rejects('not_object'));
    });

    // A stale descriptor is usable data, so it decodes and reports staleness
    // instead of throwing; the caller decides whether to ask for a new one.
    test('reports a stale descriptor rather than failing', () {
      final value = _valid()
        ..['expiresAt'] = DateTime.now().subtract(const Duration(minutes: 1)).millisecondsSinceEpoch;

      final descriptor = IrohPairingDescriptor.decode(jsonEncode(value));

      expect(descriptor.isFreshAt(DateTime.now()), isFalse);
    });
  });
}
