/// The control-plane lines the iroh host speaks, kept free of any native type
/// so the wire format can be unit-tested without loading the iroh library.
///
/// See `dsh-mobile-iroh-host`'s README: ALPN `dsh-mobile-iroh/0`, one
/// long-lived control stream that authenticates the peer with `pair` or
/// `hello`, and one bidirectional stream per proxied TCP connection whose first
/// line is `{"version":1,"type":"proxy"}`.
library;

import 'dart:convert';

/// ALPN every iroh host accepts for this transport.
const irohAlpn = 'dsh-mobile-iroh/0';

/// Wire version of every control message.
const irohWireVersion = 1;

/// The largest control line the host accepts.
const irohMaxControlLine = 64 * 1024;

/// The handshake message for a new (`pair`, with [code]) or known (`hello`)
/// peer, as the JSON line the host expects.
String irohHandshakeLine({required String name, String? code}) => _line({
  'version': irohWireVersion,
  'type': code == null ? 'hello' : 'pair',
  'code': ?code,
  'name': name,
});

/// The line that turns a fresh bidirectional stream into a proxy stream.
String get irohProxyLine => _line({'version': irohWireVersion, 'type': 'proxy'});

String _line(Map<String, Object?> message) => '${jsonEncode(message)}\n';

/// Outcome of reading the host's handshake reply.
sealed class IrohHandshakeReply {
  const IrohHandshakeReply();
}

/// The host accepted the peer; [name] is the label it stored for this device.
class IrohHandshakeOk extends IrohHandshakeReply {
  const IrohHandshakeOk(this.name);

  final String? name;
}

/// The host refused the peer with a stable [reason] (`pair-fail`).
class IrohHandshakeFailed extends IrohHandshakeReply {
  const IrohHandshakeFailed(this.reason);

  final String reason;
}

/// Parses the reply line. [expectPair] selects which acceptance type is valid,
/// so a `hello-ok` cannot answer a `pair` (the host keeps the two apart).
IrohHandshakeReply parseIrohHandshakeReply(String line, {required bool expectPair}) {
  final Object? decoded;
  try {
    decoded = jsonDecode(line);
  } on FormatException {
    return const IrohHandshakeFailed('bad_handshake');
  }
  if (decoded is! Map<String, Object?> || decoded['version'] != irohWireVersion) {
    return const IrohHandshakeFailed('bad_handshake');
  }
  final type = decoded['type'];
  switch (type) {
    case 'pair-ok' when expectPair:
      return IrohHandshakeOk(decoded['name'] as String?);
    case 'hello-ok' when !expectPair:
      return IrohHandshakeOk(decoded['name'] as String?);
    case 'pair-fail':
      final reason = decoded['reason'];
      return IrohHandshakeFailed(reason is String && reason.isNotEmpty ? reason : 'handshake_refused');
    default:
      return IrohHandshakeFailed('handshake_refused');
  }
}
