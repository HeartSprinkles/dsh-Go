import 'dart:convert';
import 'dart:math' as math;

/// A saved dsh-mobile gateway host. Non-secret fields only; the device token
/// and the pinned CA live in the [SecretStore] (see [MobileSecrets]).
class MobileHostConfig {
  const MobileHostConfig({
    required this.id,
    required this.name,
    required this.origin,
    this.workingDirectory,
    this.instanceId,
    this.caFingerprint,
    this.deviceId,
    this.deviceExpiresAt,
  });

  final String id;
  final String name;

  /// `https://host:port` (no trailing slash). The pairing token and device
  /// credentials are bound to this exact origin.
  final String origin;

  /// New sessions' default directory on the remote (absolute, `~` resolved by
  /// the remote DSH), or null to let it pick.
  final String? workingDirectory;

  /// Gateway installation identity shown in the trust prompt; also part of the
  /// pairing link (`dsh1.<instanceId>.<token>`).
  final String? instanceId;

  /// SHA-256 of the pinned CA (PEM decoded), for the trust prompt; null until
  /// first pairing (or when the entry uses a public certificate).
  final String? caFingerprint;

  /// The paired device id; set after the first successful pair.
  final String? deviceId;
  final DateTime? deviceExpiresAt;

  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'origin': origin,
    if (workingDirectory != null) 'workingDirectory': workingDirectory,
    if (instanceId != null) 'instanceId': instanceId,
    if (caFingerprint != null) 'caFingerprint': caFingerprint,
    if (deviceId != null) 'deviceId': deviceId,
    if (deviceExpiresAt != null) 'deviceExpiresAt': deviceExpiresAt!.millisecondsSinceEpoch,
  };

  static MobileHostConfig? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id'];
    final name = raw['name'];
    final origin = raw['origin'];
    if (id is! String || id.isEmpty || name is! String || origin is! String || origin.isEmpty) return null;
    final expires = raw['deviceExpiresAt'];
    return MobileHostConfig(
      id: id,
      name: name,
      origin: origin,
      workingDirectory: raw['workingDirectory'] is String ? raw['workingDirectory'] as String : null,
      instanceId: raw['instanceId'] is String ? raw['instanceId'] as String : null,
      caFingerprint: raw['caFingerprint'] is String ? raw['caFingerprint'] as String : null,
      deviceId: raw['deviceId'] is String ? raw['deviceId'] as String : null,
      deviceExpiresAt: expires is int ? DateTime.fromMillisecondsSinceEpoch(expires) : null,
    );
  }

  MobileHostConfig copyWith({
    String? name,
    String? workingDirectory,
    String? instanceId,
    String? caFingerprint,
    String? deviceId,
    DateTime? Function()? deviceExpiresAt,
  }) => MobileHostConfig(
    id: id,
    name: name ?? this.name,
    origin: origin,
    workingDirectory: workingDirectory ?? this.workingDirectory,
    instanceId: instanceId ?? this.instanceId,
    caFingerprint: caFingerprint ?? this.caFingerprint,
    deviceId: deviceId ?? this.deviceId,
    deviceExpiresAt: deviceExpiresAt != null ? deviceExpiresAt() : this.deviceExpiresAt,
  );

  static String newId([math.Random? random]) {
    final r = random ?? math.Random.secure();
    final hex = List.generate(8, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    return 'mobile-$hex';
  }

  @override
  String toString() => 'MobileHostConfig($id $origin)';
}

/// [SecretStore] keys and the secret values for one dsh-mobile host.
class MobileSecrets {
  const MobileSecrets({required this.deviceToken, required this.caPem});

  static String deviceTokenKey(String id) => 'mobile_device_token_$id';
  static String caPemKey(String id) => 'mobile_ca_pem_$id';

  /// Persistent device credential issued by `native-pair`; used to renew the
  /// short session.
  final String deviceToken;

  /// The pinned CA in PEM. Empty means "public certificate, use system trust".
  final String caPem;
}

/// What a pairing link or key carries, parsed from the QR/link/paste.
class MobilePairingInvite {
  const MobilePairingInvite({
    required this.instanceId,
    required this.token,
    this.origin,
    this.requiresRemoteCa = false,
  });

  /// Gateway installation id.
  final String instanceId;

  /// One-time pairing secret.
  final String token;

  /// The gateway HTTPS origin; null when a bare key was pasted (the origin is
  /// entered separately).
  final String? origin;

  /// True for `dsh2.` entries: a self-signed remote CA must be pinned and can
  /// never fall back to public-CA trust.
  final bool requiresRemoteCa;

  /// Parses a pairing URL (`https://<origin>/mobile-access/pair#instance=<id>&token=<t>`
  /// or `...#key=dsh2.<id>.<t>`) or a bare key (`dsh1.<id>.<t>` / `dsh2.<id>.<t>`).
  static MobilePairingInvite? tryParse(String text) {
    final t = text.trim();
    if (t.isEmpty) return null;

    String fragment;
    String? origin;
    final uri = Uri.tryParse(t);
    if (uri != null && (uri.scheme == 'https' || uri.scheme == 'http')) {
      origin = '${uri.scheme}://${uri.host}${uri.hasPort ? ':${uri.port}' : ''}';
      fragment = uri.fragment;
    } else {
      fragment = t;
    }

    // A bare key (dsh1.<instanceId>.<token> or dsh2.<instanceId>.<token>).
    if (fragment.startsWith('dsh1.') || fragment.startsWith('dsh2.')) {
      final parts = fragment.split('.');
      if (parts.length != 3) return null;
      return MobilePairingInvite(
        instanceId: parts[1],
        token: parts[2],
        origin: origin,
        requiresRemoteCa: fragment.startsWith('dsh2.'),
      );
    }

    // A self-signed remote entry puts the key in the fragment as `key=dsh2.…`.
    if (fragment.startsWith('key=')) {
      final parts = fragment.substring('key='.length).split('.');
      if (parts.length != 3) return null;
      return MobilePairingInvite(
        instanceId: parts[1],
        token: parts[2],
        origin: origin,
        requiresRemoteCa: parts[0] == 'dsh2',
      );
    }

    // A LAN entry: `instance=<id>&token=<t>`.
    final params = Uri.splitQueryString(fragment);
    final instance = params['instance'];
    final token = params['token'];
    if (instance == null || instance.isEmpty || token == null || token.isEmpty) return null;
    return MobilePairingInvite(instanceId: instance, token: token, origin: origin);
  }
}

/// Serializes [MobilePairingInvite] for the pairing page (origin, instanceId,
/// token are all kept in memory, never persisted as plaintext).
String mobilePairingInviteEncode(MobilePairingInvite invite) => jsonEncode({
  'origin': invite.origin,
  'instanceId': invite.instanceId,
  'token': invite.token,
  'requiresRemoteCa': invite.requiresRemoteCa,
});
