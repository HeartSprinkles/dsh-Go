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
import 'iroh_endpoint_pool.dart';
import 'iroh_wire.dart';
import 'iroh_send_sink.dart';

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

/// Maps a failed dial onto [IrohChannelException].
///
/// A native dial failure (no route, QUIC timeout, refused) arrives as the
/// plugin's own exception type. Re-throwing those as this class's type keeps the
/// caller's error mapping to one shape, so the user sees the iroh cause instead
/// of the page's generic failure text.
IrohChannelException irohDialFailure(Object error) {
  if (error is IrohChannelException) return error;
  if (error is TimeoutException) return const IrohChannelException('connect_timeout');
  return IrohChannelException('connect_failed', detail: '$error');
}

/// Builds this device's iroh identity, starting the native runtime first.
///
/// [SecretKey.generate] and [SecretKey.fromBytes] call straight into the Rust
/// core, so they fail if the runtime is not up yet. Every caller goes through
/// here instead of touching the constructors directly, so the ordering cannot be
/// got wrong at a call site again.
Future<SecretKey> irohSecretKey({List<int>? bytes}) async {
  await Iroh.init();
  return bytes == null ? SecretKey.generate() : SecretKey.fromBytes(bytes);
}

/// One authenticated iroh connection to a host, kept open for the link's life.
///
/// Reconnecting is the caller's job: when the connection dies, [open] throws and
/// the link's backoff decides when to build a new [IrohChannel].
class IrohChannel {
  IrohChannel._(this._connection, this._lease);

  final Connection _connection;

  /// Set only when this channel created the endpoint lease itself; a borrowed
  /// endpoint stays alive for its owner after [close].
  final IrohEndpointOwner? _lease;

  /// The peer's endpoint id, lowercase hex.
  String get remoteEndpointId => _connection.remoteId.toHex();

  /// Dials [endpointId] and completes the `pair`/`hello` handshake.
  ///
  /// [code] is the six-digit code the host is showing, used only the first
  /// time a phone pairs; later connections use `hello`. [relayUrls] and
  /// [directAddresses] come from the descriptor; leaving both empty lets iroh
  /// resolve the address itself.
  ///
  /// [endpointOwner] lets a long-lived link keep one [Endpoint] — and with it
  /// the relay connection and address cache — across reconnects. Without one
  /// the channel binds and closes its own endpoint, which is what pairing wants.
  static Future<IrohChannel> open({
    required String endpointId,
    required SecretKey secretKey,
    String? code,
    required String name,
    List<String> relayUrls = const <String>[],
    List<String> directAddresses = const <String>[],
    Duration timeout = const Duration(seconds: 20),
    IrohEndpointOwner? endpointOwner,
  }) async {
    // Both of these can throw before a single packet leaves the device (no
    // native library, no relay credentials, a key the core refuses), and the
    // caller has to name that cause rather than fall back to generic text.
    final borrowed = endpointOwner != null;
    IrohEndpointOwner? acquired;
    late final IrohEndpointOwner owner;
    try {
      await Iroh.init();
      if (endpointOwner != null) {
        if (!endpointOwner.isActive) throw const IrohChannelException('endpoint_closed');
        // A shared endpoint speaks for exactly one identity; dialing a different
        // host with it would send the wrong key to the peer.
        if (endpointOwner.identityHex != secretKey.publicKey.toHex()) {
          throw const IrohChannelException('endpoint_identity_mismatch');
        }
        owner = endpointOwner;
      } else {
        owner = acquired = await IrohEndpointOwner.acquire(secretKey);
      }
      // The descriptor carries the endpoint id as lowercase hex, not z32.
      var addr = EndpointAddr(PublicKey.fromHex(endpointId));
      for (final url in relayUrls) {
        addr = addr.withRelayUrl(RelayUrl.parse(url));
      }
      for (final socket in directAddresses) {
        addr = addr.withIpAddr(socket);
      }
      final connection = await owner.endpoint.connect(addr, irohAlpn.codeUnits).timeout(timeout);
      // Only a lease this call took is released by close(); a borrowed endpoint
      // belongs to the caller.
      final channel = IrohChannel._(connection, acquired);
      // Bound opening/writing the control stream too, not only reading its reply.
      await channel._handshake(code: code, name: name, timeout: timeout).timeout(timeout);
      return channel;
    } on Object catch (error) {
      // The endpoint owns sockets and a relay task; a failed dial must not leak
      // a lease that nothing will release. A borrowed endpoint belongs to the
      // caller and is left alone.
      if (!borrowed) {
        try {
          await acquired?.release();
        } on Object {
          // Releasing a half-built endpoint must not hide the real failure.
        }
      }
      throw irohDialFailure(error);
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
    // Connection.close is synchronous and fire-and-forget; releasing the lease
    // is what actually closes the endpoint (and its sockets and relay task) once
    // no other link shares it.
    _connection.close();
    final lease = _lease;
    if (lease != null) await lease.release();
  }
}

/// Shares one [Endpoint] per iroh identity across every link that uses it.
///
/// The native endpoint keeps the relay connection, the QUIC sockets and the
/// address cache; iroh's own docs ask for one per application, and rebuilding it
/// on every reconnect throws that work away. Identity matters: two phone
/// identities must never share, because the endpoint signs with the key it was
/// bound to. A network change is handled by [invalidate], since the binding
/// (iroh_quic 1.4.0) does not expose `Endpoint.network_change()`.
class IrohEndpointOwner {
  IrohEndpointOwner._(this._lease);

  final IrohEndpointLease<Endpoint> _lease;

  /// Process-wide pool, keyed by the identity's public key (lowercase hex).
  static final IrohEndpointPool<Endpoint> pool = IrohEndpointPool<Endpoint>(
    dispose: (endpoint) async {
      try {
        await endpoint.close();
      } on Object {
        // An endpoint whose sockets are already gone must not fail teardown.
      }
    },
  );

  /// The endpoint this owner holds, or null when another holder already closed
  /// it (a release that raced this acquisition).
  Endpoint? get _endpoint => _lease.isActive ? _lease.value : null;

  /// The identity this endpoint speaks for, lowercase hex.
  String get identityHex => _lease.value.id.toHex();

  /// Whether this owner can still be used to dial.
  bool get isActive => _lease.isActive;

  /// The bound endpoint; throws when the lease went stale (network change).
  Endpoint get endpoint {
    final value = _endpoint;
    if (value == null) throw const IrohChannelException('endpoint_closed');
    return value;
  }

  /// Takes (or joins) the endpoint for [secretKey]'s identity.
  static Future<IrohEndpointOwner> acquire(SecretKey secretKey) async {
    final identity = secretKey.publicKey.toHex();
    final lease = await pool.acquire(
      identity,
      createOverride: () => Endpoint.bind(secretKey: secretKey, alpns: <List<int>>[irohAlpn.codeUnits]),
    );
    return IrohEndpointOwner._(lease);
  }

  /// Drops one reference. The endpoint closes when the last one goes.
  Future<void> release() => _lease.release();

  /// Closes this identity's endpoint now and rebinds on the next dial. Used
  /// after a network change: the old sockets are bound to an interface that is
  /// gone, and the binding cannot re-bind them in place.
  Future<void> invalidate() => _lease.invalidate();
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
  late final _sink = IrohSendSink(
    write: _send.writeAll,
    finish: _send.finish,
    onError: (error, stack) {
      if (!_done && !_incoming.isClosed) _incoming.addError(error, stack);
      destroy();
    },
  );
  bool _done = false;

  void _pump() {
    unawaited(() async {
      try {
        while (true) {
          final chunk = await _recv.read(64 * 1024);
          if (chunk == null || _done) break;
          _incoming.add(chunk);
        }
      } catch (error, stack) {
        if (!_done && !_incoming.isClosed) _incoming.addError(error, stack);
      } finally {
        // EOF still needs destroy() to reset the other half of the stream.
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
    _sink.addError(StateError('iroh tunnel closed'));
    unawaited(_send.reset(0).catchError((Object _) {}));
    unawaited(_recv.stop(0).catchError((Object _) {}));
    unawaited(_incoming.close());
  }
}
