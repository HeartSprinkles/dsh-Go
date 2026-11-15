// dsh-mobile link: how a pairing/renew failure becomes something the person can
// act on, which failures retry, and how the host kind wires into the app's
// connection providers.

import 'dart:async';

import 'package:dsh_app/remote/link_status.dart';
import 'package:dsh_app/remote/mobile/mobile_config.dart';
import 'package:dsh_app/remote/mobile/mobile_link.dart';
import 'package:dsh_app/remote/mobile/mobile_pairing.dart';
import 'package:dsh_app/remote/secret_store.dart';
import 'package:dsh_app/state/connection_state.dart';
import 'package:dsh_app/state/hosts_state.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/wait.dart';

const _host = MobileHostConfig(id: 'mobile-1', name: '电脑', origin: 'https://192.168.1.20:3443');

/// A pairing client whose renew fails with a chosen code, without a socket.
class _FailingPairing extends MobilePairingClient {
  _FailingPairing(this.code, {this.sessions = 0});

  final String code;

  /// How many renew calls succeed before the failure kicks in; used to check
  /// that a transient failure is retried.
  final int sessions;
  int renews = 0;

  @override
  Future<MobileSession> renew(String origin, String deviceToken, {String? instanceId, String? trustedPem}) async {
    renews++;
    if (renews > sessions) throw MobilePairingException(code);
    return MobileSession(
      instanceId: instanceId ?? 'instance',
      deviceId: 'device',
      deviceToken: null,
      sessionToken: 'session-$renews',
      csrfToken: 'csrf-$renews',
      sessionExpiresAt: DateTime.now().add(const Duration(hours: 1)),
    );
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('mobileError', () {
    test('a revoked or expired device asks for a new pairing instead of retrying', () {
      for (final code in ['device_revoked', 'device_expired']) {
        final error = mobileError(MobilePairingException(code));
        expect(error.retryable, isFalse, reason: code);
        expect(error.kind, HostLinkErrorKind.authFailed, reason: code);
      }
    });

    test('an untrusted source network and an identity mismatch stay terminal', () {
      expect(mobileError(const MobilePairingException('source_network_untrusted')).retryable, isFalse);
      final mismatch = mobileError(const MobilePairingException('identity_mismatch'));
      expect(mismatch.retryable, isFalse);
      expect(mismatch.kind, HostLinkErrorKind.authFailed);
    });

    test('a TLS failure reads as a changed fingerprint, never as trust-on-first-use', () {
      final error = mobileError(const MobilePairingException('tls'));
      expect(error.kind, HostLinkErrorKind.hostKeyMismatch);
      expect(error.retryable, isFalse);
    });

    test('rate limiting and unknown transport codes retry', () {
      expect(mobileError(const MobilePairingException('rate_limited')).retryable, isTrue);
      final unknown = mobileError(const MobilePairingException('network'));
      expect(unknown.retryable, isTrue);
      expect(unknown.kind, HostLinkErrorKind.unreachable);
      expect(unknown.detail, 'network');
    });
  });

  group('MobileHostLink', () {
    MobileHostLink link({MobilePairingClient? pairing, MobileSecrets? secrets, Backoff? backoff}) => MobileHostLink(
      config: _host,
      loadSecrets: () async => secrets ?? const MobileSecrets(deviceToken: 'tok', caPem: ''),
      pairing: pairing,
      kicks: const Stream.empty(),
      backoff: backoff ?? Backoff(initial: const Duration(milliseconds: 5), maxAttempts: 2),
    );

    test('a host without a device token fails as a sign-in problem without retrying', () async {
      final l = link(secrets: const MobileSecrets(deviceToken: '', caPem: ''));
      addTearDown(l.close);

      await expectLater(l.open(), throwsA(isA<HostLinkError>()));

      expect(l.status.phase, HostLinkPhase.failed);
      expect(l.status.error!.kind, HostLinkErrorKind.authFailed);
      expect(l.status.error!.retryable, isFalse);
      expect(l.currentClient, isNull);
    });

    test('a revoked device ends in failed and does not keep retrying', () async {
      final pairing = _FailingPairing('device_revoked');
      final l = link(pairing: pairing);
      addTearDown(l.close);

      await expectLater(l.open(), throwsA(isA<HostLinkError>()));

      expect(l.status.phase, HostLinkPhase.failed);
      expect(l.status.error!.retryable, isFalse);
      expect(pairing.renews, 1, reason: 'a terminal code must not be retried');
    });

    test('a transient failure backs off, then gives up with the attempt count', () async {
      final pairing = _FailingPairing('network');
      final l = link(pairing: pairing);
      addTearDown(l.close);

      final sawReconnecting = nextStatus(l, (s) => s.phase == HostLinkPhase.reconnecting, what: 'reconnecting');
      await expectLater(l.open(), throwsA(isA<HostLinkError>()));

      expect((await sawReconnecting).attempt, greaterThan(0));
      expect(l.status.phase, HostLinkPhase.failed);
      expect(l.status.error!.retryable, isTrue);
      expect(pairing.renews, greaterThan(1), reason: 'transient failures are retried while backoff lasts');
    });

    test('close emits idle and refuses to open again', () async {
      final l = link();
      final idle = l.statuses.firstWhere((s) => s.phase == HostLinkPhase.idle);
      await l.close();
      await idle;
      expect(l.status.phase, HostLinkPhase.idle);
      expect(l.open(), throwsA(isA<StateError>()));
    });

    test('kick while reconnecting skips the remaining wait', () async {
      final pairing = _FailingPairing('network');
      final l = MobileHostLink(
        config: _host,
        loadSecrets: () async => const MobileSecrets(deviceToken: 'tok', caPem: ''),
        pairing: pairing,
        kicks: const Stream.empty(),
        // A long first wait: only a kick gets past it quickly.
        backoff: Backoff(initial: const Duration(seconds: 30), maxAttempts: 2),
      );
      addTearDown(l.close);

      unawaited(l.open().then((_) {}, onError: (_) {}));
      await nextStatus(l, (s) => s.phase == HostLinkPhase.reconnecting, what: 'reconnecting');
      l.kick();

      // The skipped wait is observable as a second attempt well under 30 s.
      await nextStatus(l, (s) => s.phase == HostLinkPhase.reconnecting && s.attempt >= 2, what: 'second attempt');
      expect(pairing.renews, greaterThan(1));
    });
  });

  group('connection providers', () {
    late MemorySecretStore secrets;

    ProviderContainer container() {
      final c = ProviderContainer(
        overrides: [
          secretStoreProvider.overrideWithValue(secrets),
          networkKicksProvider.overrideWithValue(const Stream.empty()),
        ],
      );
      addTearDown(c.dispose);
      return c;
    }

    setUp(() {
      SharedPreferences.setMockInitialValues({});
      secrets = MemorySecretStore();
    });

    test('a saved dsh-mobile host resolves to its own link and name', () async {
      final c = container();
      final hosts = c.read(hostsProvider.notifier);
      await hosts.ready;
      await hosts.saveMobile(_host, secrets: const MobileSecrets(deviceToken: 'tok', caPem: ''));

      const ref = HostRef.mobile('mobile-1');
      final link = c.read(hostLinkProvider(ref));
      expect(link, isA<MobileHostLink>());
      expect((link! as MobileHostLink).config.origin, _host.origin);
      expect(c.read(hostNameProvider(ref)), '电脑');
    });

    test('a host that was removed has no link, and 本机 never has one', () async {
      final c = container();
      final hosts = c.read(hostsProvider.notifier);
      await hosts.ready;

      expect(c.read(hostLinkProvider(const HostRef.mobile('gone'))), isNull);
      expect(c.read(hostLinkProvider(HostRef.local)), isNull);
    });

    test('the link status starts idle and never connects on its own', () async {
      final c = container();
      final hosts = c.read(hostsProvider.notifier);
      await hosts.ready;
      await hosts.saveMobile(_host, secrets: const MobileSecrets(deviceToken: 'tok', caPem: ''));

      final status = c.read(hostLinkStatusProvider(const HostRef.mobile('mobile-1'))).value;
      expect(status?.phase, HostLinkPhase.idle);
    });

    test('dsh-mobile hosts are listed apart from SSH hosts', () async {
      final c = container();
      final hosts = c.read(hostsProvider.notifier);
      await hosts.ready;

      expect(c.read(hostsProvider).mobile, isEmpty);
      await hosts.saveMobile(_host);
      expect(c.read(hostsProvider).mobile.single.id, 'mobile-1');
      expect(c.read(hostsProvider).ssh, isEmpty);
      expect(c.read(hostsProvider).mobileById('mobile-1')!.name, '电脑');
    });
  });
}
