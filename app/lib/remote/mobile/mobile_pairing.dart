import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// A short dsh-mobile session (or the outcome of a pair/renew).
class MobileSession {
  const MobileSession({
    required this.instanceId,
    required this.deviceId,
    required this.deviceToken,
    required this.sessionToken,
    required this.csrfToken,
    required this.sessionExpiresAt,
    this.deviceExpiresAt,
  });

  final String instanceId;
  final String deviceId;

  /// Present after `native-pair`; null after `native-renew`.
  final String? deviceToken;
  final String sessionToken;
  final String csrfToken;
  final DateTime sessionExpiresAt;
  final DateTime? deviceExpiresAt;
}

/// A failed pairing/renew/probe with a stable code (see the contract doc §2.2).
class MobilePairingException implements Exception {
  const MobilePairingException(this.code, {this.status});

  final String code;
  final int? status;

  bool get retryable =>
      code != 'device_revoked' &&
      code != 'device_expired' &&
      code != 'source_network_untrusted' &&
      code != 'device_limit' &&
      code != 'invalid_request';

  @override
  String toString() => 'MobilePairingException($code, status: $status)';
}

/// Converts the DER served by `/mobile-access/ca.cer` to PEM for
/// `SecurityContext.setTrustedCertificatesBytes`.
String caDerToPem(List<int> der) {
  final encoded = base64Encode(der);
  final lines = <String>[];
  for (var i = 0; i < encoded.length; i += 64) {
    lines.add(encoded.substring(i, i + 64 > encoded.length ? encoded.length : i + 64));
  }
  return '-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n';
}

/// SHA-256 of the DER certificate, for the trust prompt.
String caFingerprint(List<int> der) => sha256.convert(der).toString();

/// Native HTTPS pairing, renewal and probe for a dsh-mobile gateway.
class MobilePairingClient {
  MobilePairingClient({this.label = 'DeepSeek Harness (dsh-go)'});

  final String label;

  HttpClient _client({String? trustedPem}) {
    if (trustedPem != null && trustedPem.isNotEmpty) {
      final context = SecurityContext(withTrustedRoots: true)
        ..setTrustedCertificatesBytes(utf8.encode(trustedPem));
      final http = HttpClient(context: context);
      http.connectionTimeout = const Duration(seconds: 10);
      return http;
    }
    final http = HttpClient();
    http.connectionTimeout = const Duration(seconds: 10);
    return http;
  }

  /// Fetches the gateway's private CA, trusting it once (TOFU) so the caller
  /// can show its fingerprint before pinning. Returns null on 404 (the entry
  /// uses a public certificate and system trust).
  Future<List<int>?> fetchCa(String origin) async {
    final http = HttpClient()..badCertificateCallback = (_, _, _) => true;
    http.connectionTimeout = const Duration(seconds: 10);
    try {
      final request = await http.getUrl(Uri.parse('$origin/mobile-access/ca.cer'));
      final response = await request.close();
      final status = response.statusCode;
      if (status == 404) return null;
      if (status != 200) {
        final bytes = await _body(response);
        throw MobilePairingException(_readCode(_decode(bytes)) ?? 'authentication_failed', status: status);
      }
      final bytes = await _collect(response, 16 * 1024);
      if (bytes == null) throw MobilePairingException('invalid_response', status: status);
      return bytes;
    } on MobilePairingException {
      rethrow;
    } on HandshakeException {
      throw const MobilePairingException('tls');
    } on SocketException {
      throw const MobilePairingException('network');
    } finally {
      http.close(force: true);
    }
  }

  /// `POST /mobile-access/auth/native-pair`.
  Future<MobileSession> pair(
    String origin,
    String token, {
    String? instanceId,
    String? trustedPem,
  }) async {
    final json = await _post(
      origin,
      '/mobile-access/auth/native-pair',
      {'token': token, 'label': label},
      trustedPem: trustedPem,
    );
    return _parseSession(json, instanceId: instanceId);
  }

  /// `POST /mobile-access/auth/native-renew`.
  Future<MobileSession> renew(
    String origin,
    String deviceToken, {
    String? instanceId,
    String? trustedPem,
  }) async {
    final json = await _post(
      origin,
      '/mobile-access/auth/native-renew',
      {'deviceToken': deviceToken},
      trustedPem: trustedPem,
    );
    return _parseSession(json, instanceId: instanceId, requireDeviceToken: false);
  }

  /// `POST /mobile-access/auth/native-probe` (no session is opened).
  Future<DateTime> probe(
    String origin,
    String deviceToken, {
    String? trustedPem,
  }) async {
    final json = await _post(
      origin,
      '/mobile-access/auth/native-probe',
      {'deviceToken': deviceToken},
      trustedPem: trustedPem,
    );
    final expires = json['deviceExpiresAt'];
    if (expires is! int) throw const MobilePairingException('invalid_response');
    return DateTime.fromMillisecondsSinceEpoch(expires);
  }

  Future<Map<String, Object?>> _post(
    String origin,
    String path,
    Map<String, Object?> body, {
    String? trustedPem,
  }) async {
    final http = _client(trustedPem: trustedPem);
    try {
      final request = await http.postUrl(Uri.parse('$origin$path'));
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(body));
      final response = await request.close();
      final status = response.statusCode;
      final bytes = await _collect(response, 64 * 1024);
      final decoded = bytes == null ? const <String, Object?>{} : _decode(bytes);
      if (status != 200) {
        final code = _readCode(decoded) ?? 'authentication_failed';
        throw MobilePairingException(code, status: status);
      }
      return decoded;
    } on MobilePairingException {
      rethrow;
    } on HandshakeException {
      throw const MobilePairingException('tls');
    } on SocketException {
      throw const MobilePairingException('network');
    } on TimeoutException {
      throw const MobilePairingException('network');
    } finally {
      http.close(force: true);
    }
  }

  MobileSession _parseSession(
    Map<String, Object?> json, {
    String? instanceId,
    bool requireDeviceToken = true,
  }) {
    final deviceToken = json['deviceToken'];
    final sessionToken = json['sessionToken'];
    final csrfToken = json['csrfToken'];
    final sessionExpires = json['sessionExpiresAt'];
    final deviceExpires = json['deviceExpiresAt'];
    if (sessionToken is! String ||
        sessionToken.isEmpty ||
        csrfToken is! String ||
        sessionExpires is! int) {
      throw const MobilePairingException('invalid_response');
    }
    if (requireDeviceToken && (deviceToken is! String || deviceToken.isEmpty)) {
      throw const MobilePairingException('invalid_response');
    }
    final responseInstance = json['instanceId'];
    if (instanceId != null && responseInstance is String && responseInstance.isNotEmpty && responseInstance != instanceId) {
      throw const MobilePairingException('identity_mismatch');
    }
    final deviceId = json['deviceId'];
    return MobileSession(
      instanceId: responseInstance is String ? responseInstance : (instanceId ?? ''),
      deviceId: deviceId is String ? deviceId : '',
      deviceToken: deviceToken is String ? deviceToken : null,
      sessionToken: sessionToken,
      csrfToken: csrfToken,
      sessionExpiresAt: DateTime.fromMillisecondsSinceEpoch(sessionExpires),
      deviceExpiresAt: deviceExpires is int ? DateTime.fromMillisecondsSinceEpoch(deviceExpires) : null,
    );
  }

  String? _readCode(Map<String, Object?> json) {
    final error = json['error'];
    return error is String ? error : null;
  }

  Map<String, Object?> _decode(List<int> bytes) {
    try {
      final decoded = jsonDecode(utf8.decode(bytes));
      return decoded is Map<String, Object?> ? decoded : const {};
    } catch (_) {
      return const {};
    }
  }

  Future<List<int>?> _collect(HttpClientResponse response, int maxBytes) async {
    final builder = BytesBuilder(copy: false);
    await for (final chunk in response) {
      builder.add(chunk);
      if (builder.length > maxBytes) return null;
    }
    return builder.takeBytes();
  }

  Future<List<int>> _body(HttpClientResponse response) async {
    final builder = BytesBuilder(copy: false);
    await for (final chunk in response) {
      builder.add(chunk);
    }
    return builder.takeBytes();
  }
}
