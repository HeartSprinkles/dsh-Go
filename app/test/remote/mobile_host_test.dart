// dsh-mobile host: the pairing link parser, the saved-host config round trip,
// and the secrets split (device token + pinned CA in the secret store, the rest
// in preferences).

import 'dart:convert';

import 'package:dsh_app/remote/mobile/mobile_config.dart';
import 'package:dsh_app/remote/mobile/mobile_pairing.dart';
import 'package:dsh_app/remote/secret_store.dart';
import 'package:dsh_app/state/hosts_state.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/wait.dart';

const _lanInvite = 'https://192.168.1.20:3443/mobile-access/pair#instance=abc123def456&token=pair-token-1';
const _remoteInvite = 'https://box.example.com/mobile-access/pair#key=dsh2.abc123def456.pair-token-2';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('MobilePairingInvite', () {
    test('parses a LAN pairing link into origin, instance and token', () {
      final invite = MobilePairingInvite.tryParse(_lanInvite)!;
      expect(invite.origin, 'https://192.168.1.20:3443');
      expect(invite.instanceId, 'abc123def456');
      expect(invite.token, 'pair-token-1');
      expect(invite.requiresRemoteCa, isFalse);
    });

    test('parses a self-signed remote link and marks the CA as required', () {
      final invite = MobilePairingInvite.tryParse(_remoteInvite)!;
      expect(invite.origin, 'https://box.example.com');
      expect(invite.instanceId, 'abc123def456');
      expect(invite.token, 'pair-token-2');
      expect(invite.requiresRemoteCa, isTrue);
    });

    test('parses a bare key without an origin', () {
      final one = MobilePairingInvite.tryParse('dsh1.abc123def456.pair-token-3')!;
      expect(one.origin, isNull);
      expect(one.instanceId, 'abc123def456');
      expect(one.token, 'pair-token-3');
      expect(one.requiresRemoteCa, isFalse);

      final two = MobilePairingInvite.tryParse('dsh2.abc123def456.pair-token-4')!;
      expect(two.requiresRemoteCa, isTrue);
    });

    test('rejects text that carries no pairing secret', () {
      expect(MobilePairingInvite.tryParse(''), isNull);
      expect(MobilePairingInvite.tryParse('   '), isNull);
      expect(MobilePairingInvite.tryParse('https://host/mobile-access/pair'), isNull);
      expect(MobilePairingInvite.tryParse('https://host/mobile-access/pair#token=only'), isNull);
      expect(MobilePairingInvite.tryParse('https://host/mobile-access/pair#instance=only'), isNull);
      expect(MobilePairingInvite.tryParse('dsh1..pair-token-3'), isNull);
      expect(MobilePairingInvite.tryParse('dsh1.abc123def456.'), isNull);
      expect(MobilePairingInvite.tryParse('key=dsh2..pair-token-3'), isNull);
      expect(MobilePairingInvite.tryParse('dsh3.a.b.c'), isNull);
    });
  });

  group('MobileHostConfig', () {
    final full = MobileHostConfig(
      id: 'mobile-0123456789abcdef',
      name: '家里的电脑',
      origin: 'https://192.168.1.20:3443',
      workingDirectory: '~/code',
      instanceId: 'abc123def456',
      caFingerprint: 'ff00aa11',
      deviceId: 'device-1',
      deviceExpiresAt: DateTime.fromMillisecondsSinceEpoch(1800000000000),
    );

    test('json round-trip keeps every non-secret field', () {
      expect(MobileHostConfig.fromJson(jsonDecode(jsonEncode(full.toJson()))), full);
    });

    test('rejects entries without the fields that identify a host', () {
      expect(MobileHostConfig.fromJson({'name': 'n', 'origin': 'o'}), isNull);
      expect(MobileHostConfig.fromJson({'id': 'i', 'origin': 'o'}), isNull);
      expect(MobileHostConfig.fromJson({'id': 'i', 'name': 'n'}), isNull);
      expect(MobileHostConfig.fromJson(jsonDecode('"a string"')), isNull);
      expect(MobileHostConfig.fromJson(null), isNull);
    });

    test('newId is prefixed and hex, and copyWith does not change identity', () {
      expect(MobileHostConfig.newId(), matches(RegExp(r'^mobile-[0-9a-f]{16}$')));
      final renamed = full.copyWith(name: '新名字');
      expect(renamed.id, full.id);
      expect(renamed.origin, full.origin);
      expect(renamed.name, '新名字');
      expect(renamed.instanceId, full.instanceId);
    });

    test('an iroh host round-trips its transport and endpoint id', () {
      final iroh = full.copyWith(
        transport: MobileTransport.iroh,
        endpointId: 'a' * 64,
        localPort: 25443,
        origin: 'https://${'a' * 32}.${'b' * 32}.iroh.localhost:25443',
      );
      final back = MobileHostConfig.fromJson(jsonDecode(jsonEncode(iroh.toJson())))!;
      expect(back, iroh);
      expect(back.isIroh, isTrue);
      expect(back.endpointId, 'a' * 64);
      expect(back.localPort, 25443);
    });

    test('address hints survive the save/load round trip', () {
      final hints = full.copyWith(
        transport: MobileTransport.iroh,
        endpointId: 'a' * 64,
        localPort: 25443,
        relayUrls: const <String>['https://relay.example.net/'],
        directAddresses: const <String>['192.168.1.20:55555'],
      );
      final back = MobileHostConfig.fromJson(jsonDecode(jsonEncode(hints.toJson())))!;

      expect(back, hints);
      expect(back.relayUrls, ['https://relay.example.net/']);
      expect(back.directAddresses, ['192.168.1.20:55555']);
      // Equality is list-aware, so a differing hint is a different host state.
      expect(back.copyWith(relayUrls: const <String>[]), isNot(hints));
    });

    test('a host saved before the hints existed has empty lists', () {
      final legacy = jsonDecode(jsonEncode({'id': 'mobile-old', 'name': '电脑', 'origin': 'https://10.0.0.5:3443'}));
      final parsed = MobileHostConfig.fromJson(legacy)!;

      expect(parsed.relayUrls, isEmpty);
      expect(parsed.directAddresses, isEmpty);
      expect(parsed.toJson().keys, isNot(contains('relayUrls')));
    });

    test('a LAN host writes no transport field, and old entries read as LAN', () {
      expect(full.toJson().keys, isNot(contains('transport')));
      expect(full.toJson().keys, isNot(contains('endpointId')));
      final legacy = jsonDecode(jsonEncode({'id': 'mobile-old', 'name': '电脑', 'origin': 'https://10.0.0.5:3443'}));
      final parsed = MobileHostConfig.fromJson(legacy)!;
      expect(parsed.transport, MobileTransport.lan);
      expect(parsed.isIroh, isFalse);
      expect(parsed.endpointId, isNull);
    });

    test('an iroh entry without an endpoint id is dropped, not kept as unopenable', () {
      expect(
        MobileHostConfig.fromJson({
          'id': 'mobile-x',
          'name': 'n',
          'origin': 'https://a.example.com',
          'transport': 'iroh',
        }),
        isNull,
      );
      expect(
        MobileHostConfig.fromJson({'id': 'i', 'name': 'n', 'origin': 'o', 'transport': 'quic'}),
        isNotNull,
        reason: 'an unknown transport falls back to LAN',
      );
    });

    test('the tile subtitle tells iroh from LAN', () {
      expect(mobileHostSubtitle(full), full.origin);
      expect(
        mobileHostSubtitle(full.copyWith(transport: MobileTransport.iroh, endpointId: 'a' * 64)),
        'iroh · ${full.origin}',
      );
    });

    test('a host never serializes its device token or CA', () {
      final json = full.toJson();
      expect(json.keys, isNot(contains('deviceToken')));
      expect(json.keys, isNot(contains('caPem')));
    });
  });

  group('HostsController dsh-mobile storage', () {
    late MemorySecretStore secrets;

    ProviderContainer container() {
      final c = ProviderContainer(overrides: [secretStoreProvider.overrideWithValue(secrets)]);
      addTearDown(c.dispose);
      return c;
    }

    setUp(() {
      SharedPreferences.setMockInitialValues({});
      secrets = MemorySecretStore();
    });

    Future<HostsController> ready(ProviderContainer c) async {
      final hosts = c.read(hostsProvider.notifier);
      await hosts.ready;
      await Future<void>.delayed(Duration.zero);
      return hosts;
    }

    test('saves the config to preferences and the token + CA to the secret store', () async {
      final c = container();
      final hosts = await ready(c);
      final config = const MobileHostConfig(
        id: 'mobile-h1',
        name: '电脑',
        origin: 'https://10.0.0.5:3443',
      );

      expect(await hosts.saveMobile(config, secrets: const MobileSecrets(deviceToken: 'tok-1', caPem: 'PEM-1')), isTrue);

      expect(c.read(hostsProvider).mobileById('mobile-h1'), config);
      expect(secrets.values[MobileSecrets.deviceTokenKey('mobile-h1')], 'tok-1');
      expect(secrets.values[MobileSecrets.caPemKey('mobile-h1')], 'PEM-1');
      final loaded = await hosts.loadMobileSecrets('mobile-h1');
      expect(loaded.deviceToken, 'tok-1');
      expect(loaded.caPem, 'PEM-1');
    });

    test('an empty CA means public trust, so the key is removed', () async {
      final c = container();
      final hosts = await ready(c);
      const config = MobileHostConfig(id: 'mobile-h2', name: '电脑', origin: 'https://box.example.com');

      await hosts.saveMobile(config, secrets: const MobileSecrets(deviceToken: 'tok', caPem: 'PEM'));
      expect(secrets.values.containsKey(MobileSecrets.caPemKey('mobile-h2')), isTrue);

      await hosts.saveMobile(config, secrets: const MobileSecrets(deviceToken: 'tok', caPem: ''));
      expect(secrets.values.containsKey(MobileSecrets.caPemKey('mobile-h2')), isFalse);
      expect((await hosts.loadMobileSecrets('mobile-h2')).caPem, '');
    });

    test('the iroh identity is a secret too: stored, replaced and removed', () async {
      final c = container();
      final hosts = await ready(c);
      final config = MobileHostConfig(
        id: 'mobile-i1',
        name: '电脑',
        origin: 'https://a.example.com',
        transport: MobileTransport.iroh,
        endpointId: 'b' * 64,
        localPort: 25443,
      );

      await hosts.saveMobile(
        config,
        secrets: const MobileSecrets(deviceToken: 'tok', caPem: 'PEM', irohSecretKey: 'key-1'),
      );
      expect(secrets.values[MobileSecrets.irohSecretKeyKey('mobile-i1')], 'key-1');
      expect((await hosts.loadMobileSecrets('mobile-i1')).irohSecretKey, 'key-1');

      // A re-pair writes the new key; an empty one drops the entry.
      await hosts.saveMobile(
        config,
        secrets: const MobileSecrets(deviceToken: 'tok', caPem: 'PEM', irohSecretKey: ''),
      );
      expect(secrets.values.containsKey(MobileSecrets.irohSecretKeyKey('mobile-i1')), isFalse);

      await hosts.saveMobile(
        config,
        secrets: const MobileSecrets(deviceToken: 'tok', caPem: 'PEM', irohSecretKey: 'key-2'),
      );
      await hosts.removeMobile('mobile-i1');
      expect(secrets.values.containsKey(MobileSecrets.irohSecretKeyKey('mobile-i1')), isFalse);
    });

    test('re-saving the same id replaces instead of appending', () async {
      final c = container();
      final hosts = await ready(c);
      const first = MobileHostConfig(id: 'mobile-h3', name: '旧名字', origin: 'https://a.example.com');
      const second = MobileHostConfig(id: 'mobile-h3', name: '新名字', origin: 'https://a.example.com');

      await hosts.saveMobile(first);
      await hosts.saveMobile(second);

      final saved = c.read(hostsProvider).mobile;
      expect(saved.length, 1);
      expect(saved.single.name, '新名字');
    });

    test('removing a host drops its secrets and falls back to 本机 when active', () async {
      final c = container();
      final hosts = await ready(c);
      const config = MobileHostConfig(id: 'mobile-h4', name: '电脑', origin: 'https://a.example.com');
      await hosts.saveMobile(config, secrets: const MobileSecrets(deviceToken: 'tok', caPem: 'PEM'));
      c.read(activeHostProvider.notifier).select(const HostRef.mobile('mobile-h4'));
      expect(c.read(activeHostProvider).kind, HostKind.mobile);

      await hosts.removeMobile('mobile-h4');

      expect(c.read(hostsProvider).mobileById('mobile-h4'), isNull);
      expect(secrets.values.containsKey(MobileSecrets.deviceTokenKey('mobile-h4')), isFalse);
      expect(secrets.values.containsKey(MobileSecrets.caPemKey('mobile-h4')), isFalse);
      expect(c.read(activeHostProvider), HostRef.local);
    });

    test('saved hosts survive a fresh container (preferences round trip)', () async {
      final first = container();
      final hosts = await ready(first);
      const config = MobileHostConfig(
        id: 'mobile-h5',
        name: '电脑',
        origin: 'https://a.example.com',
        instanceId: 'abc',
        caFingerprint: 'ff',
      );
      await hosts.saveMobile(config, secrets: const MobileSecrets(deviceToken: 'tok', caPem: 'PEM'));

      final second = container();
      await ready(second);
      expect(second.read(hostsProvider).mobileById('mobile-h5'), config);
    });

    test('a corrupt preference entry is ignored, not fatal', () async {
      SharedPreferences.setMockInitialValues({HostsController.mobilePrefsKey: '{not json'});
      final c = container();
      final hosts = await ready(c);
      expect(c.read(hostsProvider).mobile, isEmpty);
      expect(c.read(hostsProvider).loaded, isTrue);
      // Writes still work after the bad read.
      expect(await hosts.saveMobile(const MobileHostConfig(id: 'mobile-h6', name: 'n', origin: 'https://a.example.com')), isTrue);
      expect(c.read(hostsProvider).mobile.single.id, 'mobile-h6');
    });
  });

  group('HostRef for dsh-mobile', () {
    test('encodes, decodes and compares by id', () {
      const ref = HostRef.mobile('mobile-1', name: '电脑');
      expect(HostRef.decode(ref.encode()), ref);
      expect(HostRef.decode(ref.encode()).name, '电脑');
      expect(const HostRef.mobile('mobile-1', name: 'A'), const HostRef.mobile('mobile-1', name: 'B'));
      expect(const HostRef.mobile('mobile-1'), isNot(const HostRef.ssh('mobile-1')));
    });

    test('the chat header labels it apart from SSH and Remote', () {
      expect(hostLabel(HostKind.mobile, '家里的电脑'), '家里的电脑 · dsh-mobile');
      expect(hostLabel(HostKind.mobile, null), 'dsh-mobile · dsh-mobile');
      expect(hostLabel(HostKind.mobile, '一个名字特别特别特别特别长的电脑'), endsWith('… · dsh-mobile'));
    });
  });

  group('CA helpers', () {
    test('DER becomes a PEM block the TLS stack accepts', () {
      // A tiny DER payload: only the encoding shape matters here.
      final pem = caDerToPem(const [0x30, 0x03, 0x02, 0x01, 0x01]);
      expect(pem, startsWith('-----BEGIN CERTIFICATE-----\n'));
      expect(pem, endsWith('\n-----END CERTIFICATE-----\n'));
      expect(pem.split('\n').where((l) => l.isNotEmpty).length, 3);
    });

    test('long DER wraps at 64 columns', () {
      final pem = caDerToPem(List<int>.generate(200, (i) => i % 256));
      final body = pem.split('\n').where((l) => l.isNotEmpty && !l.startsWith('-----'));
      expect(body.every((l) => l.length <= 64), isTrue);
      expect(body.length, greaterThan(1));
    });

    test('the fingerprint is the SHA-256 of the DER, as hex', () {
      final fingerprint = caFingerprint(const [1, 2, 3]);
      expect(fingerprint, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(caFingerprint(const [1, 2, 3]), fingerprint);
      expect(caFingerprint(const [1, 2, 4]), isNot(fingerprint));
    });
  });

  group('MobilePairingException', () {
    test('terminal device errors never retry; transport ones do', () {
      for (final code in [
        'device_revoked',
        'device_expired',
        'source_network_untrusted',
        'device_limit',
        'invalid_request',
      ]) {
        expect(MobilePairingException(code).retryable, isFalse, reason: code);
      }
      for (final code in ['network', 'tls', 'rate_limited', 'authentication_failed', 'invalid_response']) {
        expect(MobilePairingException(code).retryable, isTrue, reason: code);
      }
    });
  });

  group('wait helper', () {
    test('until observes and returns the first value that matches', () async {
      final c = ProviderContainer();
      addTearDown(c.dispose);
      final value = await until<HostsState>(c, hostsProvider, (s) => s.loaded, what: 'hosts loaded');
      expect(value.loaded, isTrue);
    });
  });
}
