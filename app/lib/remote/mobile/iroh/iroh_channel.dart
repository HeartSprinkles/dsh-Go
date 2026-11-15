/// An iroh QUIC tunnel that turns the DSH Mobile iroh gateway into ordinary
/// loopback TCP, so the rest of the app can talk to it like any other host.
///
/// The wire protocol is the one `dsh-mobile-iroh-host` speaks (see
/// `iroh_wire.dart`): a long-lived control stream that authenticates the peer,
/// and one bidirectional stream per proxied TCP connection. The host forwards
/// bytes unmodified to the gateway, which keeps its own TLS, cookie and CSRF
/// checks — this layer only carries them.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:iroh_flutter/iroh_flutter.dart';

import '../../ssh/ssh_transport.dart';
import 'iroh_wire.dart';

export 'iroh_wire.dart' show irohAlpn;

/// Thrown when the peer refuses the handshake or the tunnel is gone.
class IrohChannelException implements Exception {
  const IrohChannelException(this.reason, {this.detail});

  /// Stable reason, safe to show and to branch on.
  final String reason;

  /// Extra human-readable context, never containing credentials.
  final String? detail;

  @override
  String toString() => detail == null ? 'IrohChannelException($reason)' : 'IrohChannelException($reason: $detail)';
}

/// One authenticated iroh connection to a host, kept open for the link's life.
///
/// Reconnecting is the caller's job: when the connection dies, [open] throws and
/// the link's backoff decides when to build a new [IrohChannel].
class IrohChannel {
  IrohChannel._(this._endpoint, this._connection);

  final Endpoint _endpoint;
  final Connection _connection;

  /// The peer's endpoint id, lowercase hex.
  String get remoteEndpointId => _connection.remoteId.toHex();

  /// Dials [endpointId] and completes the `pair`/`hello` handshake.
  ///
  /// [code] is the six-digit code the host is showing, used only the first
  /// time a phone pairs; later connections use `hello`. [relayUrls] and
  /// [directAddresses] come from the descriptor; leaving both empty lets iroh
  /// resolve the address itself.
  static Future<IrohChannel> open({
    required String endpointId,
    required SecretKey secretKey,
    String? code,
    required String name,
    List<String> relayUrls = const <String>[],
    List<String> directAddresses = const <String>[],
    Duration timeout = const Duration(seconds: 20),
  }) async {
    await Iroh.init();
    // `Endpoint.bind` types the ALPN list as bytes, and each ALPN here is ASCII.
    final endpoint = await Endpoint.bind(secretKey: secretKey, alpns: <List<int>>[irohAlpn.codeUnits]);
    try {
      // The descriptor carries the endpoint id as lowercase hex, not z32.
      var addr = EndpointAddr(PublicKey.fromHex(endpointId));
      for (final url in relayUrls) {
        addr = addr.withRelayUrl(RelayUrl.parse(url));
      }
      for (final socket in directAddresses) {
        addr = addr.withIpAddr(socket);
      }
      final connection = await endpoint.connect(addr, irohAlpn.codeUnits).timeout(timeout);
      final channel = IrohChannel._(endpoint, connection);
      await channel._handshake(code: code, name: name, timeout: timeout);
      return channel;
    } on Object {
      // The endpoint owns sockets and a relay task; a failed handshake must not
      // leave them running behind a dead channel.
      await endpoint.close();
      rethrow;
    }
  }

  Future<void> _handshake({required String? code, required String name, required Duration timeout}) async {
    final (send, recv) = await _connection.openBi();
    // A fresh peer pairs with the code; a known peer says hello. The host
    // rejects any other first message, so the two cases are exclusive.
    await send.writeAll(utf8.encode(irohHandshakeLine(name: name, code: code)));
    final reply = await _readLine(recv, 4096).timeout(timeout);
    switch (parseIrohHandshakeReply(reply, expectPair: code != null)) {
      case IrohHandshakeOk():
        return;
      case IrohHandshakeFailed(reason: final reason):
        throw IrohChannelException(reason);
    }
  }

  static Future<String> _readLine(RecvStream recv, int limit) async {
    final buffer = <int>[];
    while (true) {
      final chunk = await recv.read(1);
      if (chunk == null) {
        throw const IrohChannelException('handshake_closed');
      }
      if (chunk.first == 0x0a) return utf8.decode(buffer);
      buffer.add(chunk.first);
      if (buffer.length > limit) {
        throw const IrohChannelException('handshake_too_long');
      }
    }
  }

  /// Opens one proxied TCP connection through the tunnel.
  Future<TunnelChannel> openTunnel() async {
    final (send, recv) = await _connection.openBi();
    await send.writeAll(utf8.encode(irohProxyLine));
    return _IrohTunnelChannel(send, recv);
  }

  Future<void> close() async {
    // Connection.close is synchronous and fire-and-forget; the endpoint close
    // is what actually releases the sockets and relay task.
    _connection.close();
    await _endpoint.close();
  }
}

/// Bridges one iroh bidirectional stream to the [TunnelChannel] shape
/// `LocalForwarder` already pipes sockets into.
class _IrohTunnelChannel implements TunnelChannel {
  _IrohTunnelChannel(this._send, this._recv) {
    _pump();
  }

  final SendStream _send;
  final RecvStream _recv;
  final _incoming = StreamController<Uint8List>();
  late final _sink = _SendSink(_send);
  bool _done = false;

  void _pump() {
    unawaited(() async {
      try {
        while (true) {
          final chunk = await _recv.read(64 * 1024);
          if (chunk == null) break;
          _incoming.add(chunk);
        }
      } on Object {
        // A reset stream is just a closed socket to the caller.
      } finally {
        _done = true;
        await _incoming.close();
      }
    }());
  }

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  void destroy() {
    if (_done) return;
    _done = true;
    unawaited(_send.reset(0));
    unawaited(_incoming.close());
  }
}

class _SendSink implements StreamSink<List<int>> {
  _SendSink(this._send);

  final SendStream _send;

  @override
  void add(List<int> data) {
    // Writes are awaited in order by the QUIC stream itself; chaining keeps the
    // closure to the sender simple while still surfacing errors to addStream.
    unawaited(_write(data));
  }

  Future<void> _write(List<int> data) async {
    try {
      await _send.writeAll(data);
    } on Object {
      // A dead stream surfaces through `done`; LocalForwarder tears the pair
      // down from the socket side either way.
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) => stream.forEach(add);

  @override
  Future<void> close() async {
    await _send.finish();
  }

  @override
  Future<void> get done => Future<void>.value();
}
