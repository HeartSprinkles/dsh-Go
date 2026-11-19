/// The pairing descriptor the DSH Mobile plugin prints as a QR code.
///
/// `dsh-mobile` validates this object field by field before it hands the gateway
/// token to a peer, so the decoder here mirrors `validatePairingDescriptor` in
/// the plugin: an exact field set, a self-signed CA whose SHA-256 equals
/// `instanceId`, and the origin rebuilt from the endpoint id and port. Anything
/// off is rejected rather than repaired — a wrong descriptor would otherwise
/// point the tunnel at an unverified origin.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Thrown when a scanned descriptor is not a usable iroh pairing payload.
class IrohDescriptorException implements Exception {
  const IrohDescriptorException(this.reason);

  /// Machine-readable reason, stable enough to show to the user.
  final String reason;

  @override
  String toString() => 'IrohDescriptorException($reason)';
}

/// A validated iroh pairing descriptor.
class IrohPairingDescriptor {
  const IrohPairingDescriptor({
    required this.endpointId,
    required this.localPort,
    required this.irohCode,
    required this.gatewayToken,
    required this.caCertificateDer,
    required this.instanceId,
    required this.expiresAt,
    this.relayUrls = const <String>[],
    this.directAddresses = const <String>[],
  });

  /// The peer's 64-character lowercase hex endpoint id.
  final String endpointId;

  /// The loopback port the gateway listens on at the computer.
  final int localPort;

  /// The six-digit code the host is showing, echoed back during pairing.
  final String irohCode;

  /// The 43-character base64url gateway token.
  final String gatewayToken;

  /// The DER bytes of the gateway's self-signed CA.
  final List<int> caCertificateDer;

  /// SHA-256 of [caCertificateDer], lowercase hex.
  final String instanceId;

  /// When the descriptor stops being usable.
  final DateTime expiresAt;

  /// Relay URLs the host is currently reachable through, from the host's own
  /// `EndpointAddr`. Empty means "let iroh resolve it" (the legacy behaviour).
  ///
  /// dsh-mobile does not emit these yet; the client already accepts and stores
  /// them so an upgraded host needs no client change.
  final List<String> relayUrls;

  /// Direct socket addresses (`ip:port`) the host published. Same story as
  /// [relayUrls]: optional, and empty falls back to discovery.
  final List<String> directAddresses;

  /// `https://<half1>.<half2>.iroh.localhost:<port>`, the only origin the
  /// gateway accepts for this endpoint.
  String get origin => 'https://$hostname:$localPort';

  /// The split hostname `dsh-mobile` uses, so a request can carry it as `Host`.
  String get hostname => '${endpointId.substring(0, 32)}.${endpointId.substring(32)}.iroh.localhost';

  /// Whether this descriptor is still inside its validity window.
  bool isFreshAt(DateTime now) => now.isBefore(expiresAt) && expiresAt.difference(now) <= const Duration(minutes: 10);

  static final _hexId = RegExp(r'^[a-f0-9]{64}$');
  static final _code = RegExp(r'^[0-9]{6}$');
  static final _token = RegExp(r'^[A-Za-z0-9_-]{43}$');

  /// The exact key set every descriptor carries; see `validatePairingDescriptor`.
  ///
  /// [optionalFields] are additions the plugin may emit later. They are allowed
  /// but never required, so an older host keeps working and a newer one needs no
  /// client release.
  static const _fields = <String>{
    'version',
    'type',
    'endpointId',
    'origin',
    'localPort',
    'irohCode',
    'gatewayToken',
    'caCertificate',
    'instanceId',
    'expiresAt',
  };

  /// Keys accepted in addition to [_fields]; anything else is a different
  /// producer and cannot be trusted.
  static const optionalFields = <String>{'relayUrls', 'directAddresses'};

  /// Parses the JSON text the QR code carries.
  static IrohPairingDescriptor decode(String raw) {
    if (utf8.encode(raw).length > 2200) {
      throw const IrohDescriptorException('descriptor_too_large');
    }
    final Object? parsed;
    try {
      parsed = jsonDecode(raw);
    } on FormatException {
      throw const IrohDescriptorException('not_json');
    }
    if (parsed is! Map<String, Object?>) {
      throw const IrohDescriptorException('not_object');
    }
    // The required keys must all be there, and nothing outside the required set
    // plus the documented optional ones: guessing which unknown field to trust is
    // how an origin check gets bypassed.
    final keys = parsed.keys.toSet();
    if (!keys.containsAll(_fields) ||
        keys.any((key) => !_fields.contains(key) && !optionalFields.contains(key))) {
      throw const IrohDescriptorException('unexpected_fields');
    }
    if (parsed['version'] != 1 || parsed['type'] != 'dsh-mobile-iroh-pairing') {
      throw const IrohDescriptorException('unsupported_descriptor');
    }

    final endpointId = parsed['endpointId'];
    final localPort = parsed['localPort'];
    final irohCode = parsed['irohCode'];
    final gatewayToken = parsed['gatewayToken'];
    final ca = parsed['caCertificate'];
    final instanceId = parsed['instanceId'];
    final expiresAt = parsed['expiresAt'];
    final origin = parsed['origin'];

    if (endpointId is! String || !_hexId.hasMatch(endpointId)) {
      throw const IrohDescriptorException('invalid_endpoint');
    }
    if (localPort is! int || localPort < 1024 || localPort > 65535) {
      throw const IrohDescriptorException('invalid_port');
    }
    if (irohCode is! String || !_code.hasMatch(irohCode)) {
      throw const IrohDescriptorException('invalid_code');
    }
    if (gatewayToken is! String || !_token.hasMatch(gatewayToken)) {
      throw const IrohDescriptorException('invalid_token');
    }
    if (instanceId is! String || !_hexId.hasMatch(instanceId)) {
      throw const IrohDescriptorException('invalid_instance');
    }
    if (expiresAt is! int) {
      throw const IrohDescriptorException('invalid_expiry');
    }
    if (ca is! String) {
      throw const IrohDescriptorException('invalid_ca');
    }

    final List<int> der;
    try {
      der = base64Decode(ca);
    } on FormatException {
      throw const IrohDescriptorException('invalid_ca');
    }

    if (der.isEmpty || der.length > 1536) {
      throw const IrohDescriptorException('invalid_ca');
    }
    final DateTime expiry;
    try {
      expiry = DateTime.fromMillisecondsSinceEpoch(expiresAt);
    } on ArgumentError {
      throw const IrohDescriptorException('invalid_expiry');
    }
    if (expiry.difference(DateTime.now()) > const Duration(minutes: 10)) {
      throw const IrohDescriptorException('invalid_expiry');
    }

    final descriptor = IrohPairingDescriptor(
      endpointId: endpointId,
      localPort: localPort,
      irohCode: irohCode,
      gatewayToken: gatewayToken,
      caCertificateDer: der,
      instanceId: instanceId,
      expiresAt: expiry,
      relayUrls: _readAddresses(parsed['relayUrls']),
      directAddresses: _readAddresses(parsed['directAddresses']),
    );

    // The origin is derived, never taken from the payload: it is what the
    // gateway pins its Host check to.
    if (origin is! String || origin != descriptor.origin) {
      throw const IrohDescriptorException('invalid_origin');
    }
    // The CA fingerprint is the instance id, so a swapped certificate cannot be
    // paired against a descriptor for a different instance.
    if (sha256Hex(der) != instanceId) {
      throw const IrohDescriptorException('ca_fingerprint_mismatch');
    }
    return descriptor;
  }

  /// Reads one optional address list. A missing key means "no hints" and keeps
  /// the descriptor compatible with hosts that predate the field; a list that is
  /// present but malformed is rejected outright rather than silently ignored,
  /// because a half-trusted address list is worse than discovery.
  static List<String> _readAddresses(Object? raw) {
    if (raw == null) return const <String>[];
    if (raw is! List) throw const IrohDescriptorException('invalid_addresses');
    final out = <String>[];
    for (final item in raw) {
      if (item is! String || item.trim().isEmpty) {
        throw const IrohDescriptorException('invalid_addresses');
      }
      out.add(item);
    }
    return List<String>.unmodifiable(out);
  }
}

/// Lowercase hex SHA-256 of [bytes].
String sha256Hex(List<int> bytes) => sha256.convert(bytes).toString();
