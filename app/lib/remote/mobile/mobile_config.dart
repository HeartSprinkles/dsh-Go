import 'dart:convert';
import 'dart:math' as math;

/// How a dsh-mobile host is reached.
///
/// [lan] is the gateway's own HTTPS listener (self-signed CA pinned at pairing).
/// [iroh] reaches the same gateway through an iroh QUIC tunnel that terminates
/// on the computer, so the phone needs no route to it and no open port — but it
/// does need the gateway's iroh companion to be running there.
enum MobileTransport {
  lan,
  iroh;

  String get wire => name;

  static MobileTransport fromWire(Object? raw) {
    for (final t in MobileTransport.values) {
      if (t.wire == raw) return t;
    }
    // Configs written before iroh existed have no `transport`; they are LAN.
    return MobileTransport.lan;
  }
}

/// A saved dsh-mobile gateway host. Non-secret fields only; the device token,
/// the pinned CA and the iroh secret key live in the [SecretStore] (see
/// [MobileSecrets]).
class MobileHostConfig {
  const MobileHostConfig({
    required this.id,
    required this.name,
    required this.origin,
    this.transport = MobileTransport.lan,
    this.workingDirectory,
    this.instanceId,
    this.caFingerprint,
    this.deviceId,
    this.deviceExpiresAt,
    this.endpointId,
    this.localPort,
  });

  final String id;
  final String name;

  /// The gateway's own origin: `https://host:port` (no trailing slash). For an
  /// [MobileTransport.iroh] host this is the derived
  /// `https://<half>.<half>.iroh.localhost:<localPort>` the gateway pins its
  /// `Host`/`Origin` checks to, not an address the phone resolves.
  final String origin;

  /// Which data plane carries the HTTPS bytes.
  final MobileTransport transport;

  /// New sessions' default directory on the remote (absolute, `~` resolved by
  /// the remote DSH), or null to let it pick.
  final String? workingDirectory;

  /// Gateway installation identity shown in the trust prompt; also part of the
  /// pairing link (`dsh1.<instanceId>.<token>`) and, for iroh, the SHA-256 of
  /// the gateway's CA.
  final String? instanceId;

  /// SHA-256 of the pinned CA (PEM decoded), for the trust prompt; null until
  /// first pairing (or when the entry uses a public certificate).
  final String? caFingerprint;

  /// The paired device id; set after the first successful pair.
  final String? deviceId;
  final DateTime? deviceExpiresAt;

  /// The gateway's iroh endpoint id, 64 lowercase hex. Required for
  /// [MobileTransport.iroh].
  final String? endpointId;

  /// The gateway's loopback port behind the iroh tunnel, from the descriptor.
  final int? localPort;

  bool get isIroh => transport == MobileTransport.iroh;

  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'origin': origin,
    if (transport != MobileTransport.lan) 'transport': transport.wire,
    if (workingDirectory != null) 'workingDirectory': workingDirectory,
    if (instanceId != null) 'instanceId': instanceId,
    if (caFingerprint != null) 'caFingerprint': caFingerprint,
    if (deviceId != null) 'deviceId': deviceId,
    if (deviceExpiresAt != null) 'deviceExpiresAt': deviceExpiresAt!.millisecondsSinceEpoch,
    if (endpointId != null) 'endpointId': endpointId,
    if (localPort != null) 'localPort': localPort,
  };

  static MobileHostConfig? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id'];
    final name = raw['name'];
    final origin = raw['origin'];
    if (id is! String || id.isEmpty || name is! String || origin is! String || origin.isEmpty) return null;
    final expires = raw['deviceExpiresAt'];
    final endpointId = raw['endpointId'];
    final localPort = raw['localPort'];
    final transport = MobileTransport.fromWire(raw['transport']);
    // An iroh host without its endpoint id cannot dial; drop it rather than
    // keep a tile that can only fail.
    if (transport == MobileTransport.iroh && (endpointId is! String || endpointId.isEmpty)) return null;
    return MobileHostConfig(
      id: id,
      name: name,
      origin: origin,
      transport: transport,
      workingDirectory: raw['workingDirectory'] is String ? raw['workingDirectory'] as String : null,
      instanceId: raw['instanceId'] is String ? raw['instanceId'] as String : null,
      caFingerprint: raw['caFingerprint'] is String ? raw['caFingerprint'] as String : null,
      deviceId: raw['deviceId'] is String ? raw['deviceId'] as String : null,
      deviceExpiresAt: expires is int ? DateTime.fromMillisecondsSinceEpoch(expires) : null,
      endpointId: endpointId is String ? endpointId : null,
      localPort: localPort is int ? localPort : null,
    );
  }

  MobileHostConfig copyWith({
    String? name,
    String? origin,
    MobileTransport? transport,
    String? workingDirectory,
    String? instanceId,
    String? caFingerprint,
    String? deviceId,
    DateTime? Function()? deviceExpiresAt,
    String? endpointId,
    int? localPort,
  }) => MobileHostConfig(
    id: id,
    name: name ?? this.name,
    origin: origin ?? this.origin,
    transport: transport ?? this.transport,
    workingDirectory: workingDirectory ?? this.workingDirectory,
    instanceId: instanceId ?? this.instanceId,
    caFingerprint: caFingerprint ?? this.caFingerprint,
    deviceId: deviceId ?? this.deviceId,
    deviceExpiresAt: deviceExpiresAt != null ? deviceExpiresAt() : this.deviceExpiresAt,
    endpointId: endpointId ?? this.endpointId,
    localPort: localPort ?? this.localPort,
  );

  static String newId([math.Random? random]) {
    final r = random ?? math.Random.secure();
    final hex = List.generate(8, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
    return 'mobile-$hex';
  }

  @override
  bool operator ==(Object other) =>
      other is MobileHostConfig &&
      other.id == id &&
      other.name == name &&
      other.origin == origin &&
      other.transport == transport &&
      other.workingDirectory == workingDirectory &&
      other.instanceId == instanceId &&
      other.caFingerprint == caFingerprint &&
      other.deviceId == deviceId &&
      other.deviceExpiresAt == deviceExpiresAt &&
      other.endpointId == endpointId &&
      other.localPort == localPort;

  @override
  int get hashCode => Object.hash(
    id,
    name,
    origin,
    transport,
    workingDirectory,
    instanceId,
    caFingerprint,
    deviceId,
    deviceExpiresAt,
    endpointId,
    localPort,
  );

  @override
  String toString() => 'MobileHostConfig($id $transport $origin)';
}

/// [SecretStore] keys and the secret values for one dsh-mobile host.
class MobileSecrets {
  const MobileSecrets({required this.deviceToken, required this.caPem, this.irohSecretKey = ''});

  static String deviceTokenKey(String id) => 'mobile_device_token_$id';
  static String caPemKey(String id) => 'mobile_ca_pem_$id';
  static String irohSecretKeyKey(String id) => 'mobile_iroh_key_$id';

  /// Persistent device credential issued by `native-pair`; used to renew the
  /// short session.
  final String deviceToken;

  /// The pinned CA in PEM. Empty means "public certificate, use system trust".
  final String caPem;

  /// Base64 of the 32-byte iroh secret key this phone introduced itself with.
  /// It is the device's stable iroh identity: the host remembers the endpoint id
  /// it pairs, so losing the key means pairing again.
  final String irohSecretKey;
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
      if (parts.length != 3 || parts[1].isEmpty || parts[2].isEmpty) return null;
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
      if (parts.length != 3 || parts[1].isEmpty || parts[2].isEmpty) return null;
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
