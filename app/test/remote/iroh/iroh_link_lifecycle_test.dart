import 'dart:async';
import 'dart:convert';

import 'package:dsh_app/remote/link_status.dart';
import 'package:dsh_app/remote/mobile/mobile_config.dart';
import 'package:dsh_app/remote/mobile/mobile_link.dart';
import 'package:dsh_app/remote/mobile/mobile_pairing.dart';
import 'package:flutter_test/flutter_test.dart';

class _PendingPairing extends MobilePairingClient {
  final started = Completer<void>();
  final result = Completer<MobileSession>();
  int calls = 0;

  @override
  Future<MobileSession> renew(String origin, String deviceToken, {String? instanceId, String? trustedPem}) {
    calls++;
    if (!started.isCompleted) started.complete();
    return result.future;
  }
}

const _lanConfig = MobileHostConfig(id: 'host', name: 'test', origin: 'https://host.invalid');
const _lanSecrets = MobileSecrets(deviceToken: 'device-secret', caPem: '');

void main() {
  test('close cancels a pending secret load and prevents late renew', () async {
    final loading = Completer<MobileSecrets>();
    final started = Completer<void>();
    final pairing = _PendingPairing();
    final link = MobileHostLink(
      config: _lanConfig,
      loadSecrets: () {
        started.complete();
        return loading.future;
      },
      pairing: pairing,
    );
    final opening = link.open();
    final rejected = expectLater(opening, throwsStateError);
    await started.future;
    final closing = link.close();
    expect(identical(closing, link.close()), isTrue);
    await closing.timeout(const Duration(seconds: 1));
    await rejected;
    loading.complete(_lanSecrets);
    await Future<void>.delayed(Duration.zero);
    expect(pairing.calls, 0);
    expect(link.status.phase, HostLinkPhase.idle);
    expect(link.currentClient, isNull);
    await expectLater(link.open(), throwsStateError);
  });

  test('close cancels a pending renew without waiting for its response', () async {
    final pairing = _PendingPairing();
    final link = MobileHostLink(config: _lanConfig, loadSecrets: () async => _lanSecrets, pairing: pairing);
    final rejected = expectLater(link.open(), throwsStateError);
    await pairing.started.future;
    await link.close().timeout(const Duration(seconds: 1));
    await rejected;
    pairing.result.completeError(StateError('late response'));
    await Future<void>.delayed(Duration.zero);
    expect(pairing.calls, 1);
    expect(link.status.phase, HostLinkPhase.idle);
  });

  test('synchronous status listener cannot start a second opening', () async {
    final pairing = _PendingPairing();
    var loads = 0;
    final link = MobileHostLink(
      config: _lanConfig,
      loadSecrets: () async {
        loads++;
        return _lanSecrets;
      },
      pairing: pairing,
    );
    Future<Object?>? reentrant;
    final subscription = link.statuses.listen((status) {
      if (status.phase == HostLinkPhase.connecting) {
        reentrant = link.open().then<Object?>((value) => value, onError: (Object error) => error);
      }
    });
    final rejected = expectLater(link.open(), throwsStateError);
    await pairing.started.future;
    await link.close();
    await rejected;
    expect(await reentrant, isA<StateError>());
    expect(loads, 1);
    expect(pairing.calls, 1);
    await subscription.cancel();
  });

  group('stored iroh security binding is checked before native or renew', () {
    final endpoint = 'a' * 64;
    final fingerprint = caFingerprint([1, 2, 3]);
    final host = MobileHostConfig(
      id: 'host',
      name: 'test',
      transport: MobileTransport.iroh,
      endpointId: endpoint,
      localPort: 25443,
      origin: 'https://${'a' * 32}.${'a' * 32}.iroh.localhost:25443',
      instanceId: fingerprint,
      caFingerprint: fingerprint,
    );
    final secrets = MobileSecrets(
      deviceToken: 'device-secret',
      caPem: caDerToPem([1, 2, 3]),
      irohSecretKey: base64Encode(List.filled(32, 0)),
    );
    final configurations = <String, MobileHostConfig>{
      'transport downgrade': host.copyWith(transport: MobileTransport.lan, origin: 'http://attacker.invalid'),
      'plaintext origin': host.copyWith(origin: host.origin.replaceFirst('https:', 'http:')),
      'foreign origin': host.copyWith(origin: 'https://attacker.invalid'),
      'path in origin': host.copyWith(origin: '${host.origin}/path'),
      'endpoint mismatch': host.copyWith(endpointId: 'b' * 64),
      'malformed endpoint': host.copyWith(endpointId: 'bad'),
      'invalid port': host.copyWith(localPort: 80),
      'instance mismatch': host.copyWith(instanceId: 'b' * 64),
      'fingerprint mismatch': host.copyWith(caFingerprint: 'b' * 64),
    };
    final reasons = <String, String>{
      'transport downgrade': 'iroh_transport_changed',
      'plaintext origin': 'iroh_origin_mismatch',
      'foreign origin': 'iroh_origin_mismatch',
      'path in origin': 'iroh_origin_mismatch',
      'endpoint mismatch': 'iroh_origin_mismatch',
      'malformed endpoint': 'iroh_invalid_endpoint',
      'invalid port': 'iroh_invalid_port',
      'instance mismatch': 'iroh_ca_identity_mismatch',
      'fingerprint mismatch': 'iroh_ca_identity_mismatch',
    };
    for (final entry in configurations.entries) {
      test(entry.key, () async {
        final pairing = _PendingPairing();
        final link = MobileHostLink(config: entry.value, loadSecrets: () async => secrets, pairing: pairing);
        await expectLater(
          link.open(),
          throwsA(
            isA<HostLinkError>()
                .having((error) => error.retryable, 'retryable', isFalse)
                .having((error) => error.kind, 'kind', HostLinkErrorKind.hostKeyMismatch)
                .having((error) => error.detail, 'detail', reasons[entry.key]),
          ),
        );
        expect(pairing.calls, 0);
        await link.close();
      });
    }
    for (final ca in [
      '',
      'not a certificate',
      caDerToPem([1, 2, 3]),
    ]) {
      test('missing or malformed CA fails closed: $ca', () async {
        final link = MobileHostLink(
          config: host,
          loadSecrets: () async =>
              MobileSecrets(deviceToken: secrets.deviceToken, caPem: ca, irohSecretKey: secrets.irohSecretKey),
        );
        await expectLater(
          link.open(),
          throwsA(isA<HostLinkError>().having((error) => error.retryable, 'retryable', isFalse)),
        );
        await link.close();
      });
    }
  });
}
