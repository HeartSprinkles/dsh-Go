import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dsh_client/dsh_client.dart';

import '../../l10n/l10n.dart';
import '../link_status.dart';
import '../ssh/local_forward.dart';
import 'iroh/iroh_channel.dart';
import 'iroh/iroh_http_client.dart';
import 'mobile_config.dart';
import 'mobile_pairing.dart';

/// Maps a dsh-mobile pairing/renew failure to a [HostLinkError] the person can
/// act on. Codes come from the gateway (contract doc §2.2).
HostLinkError mobileError(MobilePairingException e) {
  final code = e.code;
  return switch (code) {
    'device_revoked' || 'device_expired' => HostLinkError(
      HostLinkErrorKind.authFailed,
      appL10n.remoteErrDshSignInExpired,
      retryable: false,
    ),
    'device_limit' => HostLinkError(HostLinkErrorKind.authFailed, appL10n.commonConnectionFailed, retryable: false),
    'source_network_untrusted' => HostLinkError(
      HostLinkErrorKind.authFailed,
      appL10n.remoteErrHostUnreachable,
      retryable: false,
    ),
    'identity_mismatch' => HostLinkError(
      HostLinkErrorKind.authFailed,
      appL10n.remoteErrFingerprintChanged,
      retryable: false,
    ),
    'pairing_expired' || 'authentication_failed' => HostLinkError(
      HostLinkErrorKind.authFailed,
      appL10n.remoteErrDshSignInExpired,
      retryable: false,
    ),
    'rate_limited' => HostLinkError(HostLinkErrorKind.other, appL10n.remoteErrTooManyRequests, retryable: true),
    'tls' => HostLinkError(HostLinkErrorKind.hostKeyMismatch, appL10n.remoteErrFingerprintChanged, retryable: false),
    _ => HostLinkError(HostLinkErrorKind.unreachable, appL10n.commonConnectionFailed, detail: code, retryable: true),
  };
}

/// Maps an iroh transport failure to a [HostLinkError].
///
/// The distinction that matters to the person is "the computer is not reachable
/// right now" (retryable, the companion may be down or the path not yet found)
/// versus "the host will not talk to this phone" (not retryable: the pairing was
/// revoked or this phone's identity is not recognised).
HostLinkError irohError(IrohChannelException e) {
  final retryable = switch (e.reason) {
    'handshake_refused' => false,
    'pair-fail' || 'not_paired' || 'unknown_endpoint' || 'endpoint_mismatch' => false,
    'bad_handshake' => false,
    _ => true,
  };
  return HostLinkError(
    retryable ? HostLinkErrorKind.unreachable : HostLinkErrorKind.authFailed,
    retryable ? appL10n.remoteErrHostUnreachable : appL10n.remoteErrDshSignInExpired,
    detail: e.detail == null ? e.reason : '${e.reason}: ${e.detail}',
    retryable: retryable,
    diagnosticCode: retryable ? HostLinkDiagnosticCode.irohTunnelFailed : HostLinkDiagnosticCode.irohPeerRefused,
  );
}

/// A dsh-mobile gateway host: renew the short session, then talk to the
/// upstream `dsh web` through the gateway's HTTPS proxy with a pinned CA.
///
/// A [MobileTransport.iroh] host reaches the same gateway through an iroh QUIC
/// tunnel instead of a route to the computer: the link owns one endpoint and one
/// loopback forwarder for its whole life, and a reconnect rebuilds both.
class MobileHostLink implements HostLink {
  MobileHostLink({
    required this.config,
    required this.loadSecrets,
    MobilePairingClient? pairing,
    Stream<void>? kicks,
    Backoff? backoff,
  }) : _pairing = pairing ?? MobilePairingClient(),
       _backoff = backoff ?? Backoff() {
    _kickSub = kicks?.listen((_) => _onNetworkKick());
  }

  MobileHostConfig config;
  final Future<MobileSecrets> Function() loadSecrets;
  final MobilePairingClient _pairing;
  final Backoff _backoff;

  final _statuses = StreamController<HostLinkStatus>.broadcast(sync: true);
  final _clients = StreamController<DshClient>.broadcast();
  final _delay = InterruptibleDelay();
  StreamSubscription<void>? _kickSub;
  StreamSubscription<DshConnectionState>? _muxSub;
  HostLinkStatus _status = HostLinkStatus.idle;

  DshClient? _client;
  Future<DshClient>? _opening;
  Future<void>? _closing;
  final _closedSignal = Completer<void>();
  HttpClient? _renewHttpClient;
  bool _closed = false;
  bool _recovering = false;

  /// The iroh data plane for the current attempt: the endpoint itself is shared
  /// per identity through [IrohEndpointOwner], but the tunnel and the loopback
  /// forwarder are rebuilt on every attempt.
  _IrohTransport? _iroh;

  /// The identity-scoped endpoint this link holds while it is iroh, and the
  /// public key it belongs to. Kept across reconnects so the relay connection
  /// and address cache survive; released on teardown or a network change.
  IrohEndpointOwner? _irohOwner;
  String? _irohOwnerKey;

  /// Bumped on every network change, so a dial that was already in flight can
  /// notice its endpoint is stale and throw the transport away.
  int _networkGeneration = 0;
  Future<void>? _networkRestart;

  @override
  HostLinkStatus get status => _status;

  @override
  DshClient? get currentClient => _status.isConnected ? _client : null;

  @override
  Stream<HostLinkStatus> get statuses => _statuses.stream;

  @override
  Stream<DshClient> get clients => _clients.stream;

  void _emit(HostLinkStatus next) {
    if (_closed && next.phase != HostLinkPhase.idle) return;
    _status = next;
    _statuses.add(next);
  }

  @override
  Future<DshClient> open() {
    if (_closed) return Future.error(StateError('link closed'));
    final opening = _opening;
    if (opening != null) return opening;
    final client = _client;
    if (client != null && _status.isConnected) return Future.value(client);
    return _opening ??= _startOpening(_openFirst);
  }

  // Install the single flight before notifying synchronous status listeners.
  Future<DshClient> _startOpening(Future<DshClient> Function() work) =>
      Future<DshClient>.microtask(work).whenComplete(() => _opening = null);

  void _checkOpen() {
    if (_closed) throw StateError('link closed');
  }

  // Only for operations that cannot create a late native resource. Native
  // channel creation is awaited to completion and cleaned up before close ends.
  Future<T> _untilClosed<T>(Future<T> work) =>
      Future.any([work, _closedSignal.future.then<T>((_) => throw StateError('link closed'))]);

  Future<DshClient> _openFirst() async {
    _checkOpen();
    _backoff.reset();
    _emit(const HostLinkStatus(HostLinkPhase.connecting, step: HostLinkStep.connect));
    try {
      return await _connectOnce();
    } on HostLinkError catch (e) {
      if (!e.retryable) {
        _fail(e);
        rethrow;
      }
      return _recover(e);
    } catch (e) {
      return _recover(
        HostLinkError(HostLinkErrorKind.other, appL10n.commonConnectionFailed, detail: '$e', retryable: true),
      );
    }
  }

  void _fail(HostLinkError error) {
    _emit(HostLinkStatus(HostLinkPhase.failed, step: _status.step, completed: _status.completed, error: error));
  }

  /// One full attempt: build the data plane, renew a session, build the client,
  /// wait for the mux.
  Future<DshClient> _connectOnce() async {
    _checkOpen();
    final attemptConfig = config;
    final secrets = await _untilClosed(loadSecrets());
    _checkOpen();
    _validateIrohBinding(attemptConfig, secrets);
    if (secrets.deviceToken.isEmpty) {
      throw HostLinkError(HostLinkErrorKind.authFailed, appL10n.remoteErrSignIn, retryable: false);
    }

    // Tear the previous data plane down before a new one exists: two endpoints
    // would both hold sockets and relay connections.
    await _closeIroh();
    _checkOpen();
    if (!attemptConfig.isIroh) {
      // Switching this host to LAN (or it was never iroh): no endpoint needed.
      await _releaseIrohOwner();
    }

    final transport = attemptConfig.isIroh ? await _openIroh(attemptConfig, secrets) : null;
    _checkOpen();
    final pairing = transport == null
        ? _pairing
        : MobilePairingClient(
            label: _pairing.label,
            clientFactory: ({String? trustedPem}) =>
                _renewHttpClient = IrohTunnelHttpClient(caCertificatePem: secrets.caPem, tunnelPort: transport.port),
          );

    final MobileSession session;
    try {
      _checkOpen();
      session = await _untilClosed(
        pairing.renew(
          attemptConfig.origin,
          secrets.deviceToken,
          instanceId: attemptConfig.instanceId,
          trustedPem: secrets.caPem.isEmpty ? null : secrets.caPem,
        ),
      );
      _checkOpen();
    } on MobilePairingException catch (e) {
      await _closeIroh();
      throw mobileError(e);
    } on Object {
      await _closeIroh();
      rethrow;
    } finally {
      _renewHttpClient?.close(force: true);
      _renewHttpClient = null;
    }

    final connection = DshConnection(
      Uri.parse(attemptConfig.origin),
      // An iroh tunnel already pins the CA on its own HttpClient; setting a
      // securityContext as well would override the client and drop the
      // connectionFactory that points TLS at the tunnel.
      httpClient: transport?.httpClient,
      securityContext: transport == null && secrets.caPem.isNotEmpty ? _securityContext(secrets.caPem) : null,
      extraCookies: {'dsh_ma_session': session.sessionToken, 'dsh_ma_device': secrets.deviceToken},
      // The gateway's external-trust gate refuses a request without Origin on
      // both /api/* and the /api/remote.mux upgrade (403, not 401). The stock
      // dsh_client never sends one because the local engine rejects it; this
      // gateway is the opposite case and wants its own origin on every request.
      extraHeaders: {'x-dsh-mobile-csrf': session.csrfToken, originHeaderName: _originOf(attemptConfig.origin)},
    );
    final client = DshClient(connection);
    try {
      await _untilClosed(client.mux.ready(timeout: const Duration(seconds: 20)));
    } on Object {
      await client.close().catchError((_) {});
      await _closeIroh();
      throw HostLinkError(HostLinkErrorKind.unreachable, appL10n.commonConnectionFailed, retryable: true);
    }

    if (_closed) {
      await client.close().catchError((_) {});
      await _closeIroh();
      throw StateError('link closed');
    }
    final previous = _client;
    _client = client;
    _watchMux(client);
    if (previous != null) {
      _clients.add(client);
      unawaited(previous.close().catchError((_) {}));
    }
    _emit(const HostLinkStatus(HostLinkPhase.connected, completed: {HostLinkStep.connect, HostLinkStep.login}));
    return client;
  }

  /// Dials the iroh host, forwards a loopback port to it, and returns the two
  /// pieces the client needs. Kept on the link so [close] can release them.
  // The config is non-secret and may have been edited since pairing. Never
  // send SecretStore credentials before reconstructing the endpoint/CA binding.
  void _validateIrohBinding(MobileHostConfig host, MobileSecrets secrets) {
    if (!host.isIroh && secrets.irohSecretKey.isEmpty) return;
    Never reject(String reason) => throw HostLinkError(
      HostLinkErrorKind.hostKeyMismatch,
      appL10n.mobileIrohNeedRepair,
      detail: reason,
      retryable: false,
      diagnosticCode: HostLinkDiagnosticCode.irohPeerRefused,
    );
    if (!host.isIroh) reject('iroh_transport_changed');
    final endpoint = host.endpointId;
    final port = host.localPort;
    if (endpoint == null || endpoint.length != 64 || !RegExp(r'^[a-f0-9]{64}$').hasMatch(endpoint)) {
      reject('iroh_invalid_endpoint');
    }
    if (port == null || port < 1024 || port > 65535) reject('iroh_invalid_port');
    final expectedOrigin = 'https://${endpoint.substring(0, 32)}.${endpoint.substring(32)}.iroh.localhost:$port';
    if (host.origin != expectedOrigin) reject('iroh_origin_mismatch');
    if (secrets.caPem.isEmpty) reject('iroh_missing_ca');
    try {
      final match = RegExp(r'^\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*$')
          .firstMatch(secrets.caPem);
      if (match == null) reject('iroh_invalid_ca');
      final der = base64Decode(match.group(1)!.replaceAll(RegExp(r'\s'), ''));
      final fingerprint = caFingerprint(der);
      if (der.isEmpty || fingerprint != host.instanceId || fingerprint != host.caFingerprint) {
        reject('iroh_ca_identity_mismatch');
      }
      // Reject malformed X.509 before opening native resources as well.
      SecurityContext(withTrustedRoots: false).setTrustedCertificatesBytes(utf8.encode(secrets.caPem));
    } on HostLinkError {
      rethrow;
    } on Object {
      reject('iroh_invalid_ca');
    }
  }

  Future<_IrohTransport> _openIroh(MobileHostConfig host, MobileSecrets secrets) async {
    final endpointId = host.endpointId;
    if (endpointId == null || endpointId.isEmpty) {
      throw HostLinkError(
        HostLinkErrorKind.other,
        appL10n.mobileIrohMissingEndpoint,
        retryable: false,
        diagnosticCode: HostLinkDiagnosticCode.irohPeerRefused,
      );
    }
    final encodedKey = secrets.irohSecretKey;
    if (encodedKey.isEmpty) {
      // Without the identity the host paired, a `hello` can never succeed; the
      // person has to pair again, which is a fresh descriptor on the computer.
      throw HostLinkError(
        HostLinkErrorKind.authFailed,
        appL10n.mobileIrohNeedRepair,
        retryable: false,
        diagnosticCode: HostLinkDiagnosticCode.irohPeerRefused,
      );
    }
    final List<int> keyBytes;
    try {
      keyBytes = base64Decode(encodedKey);
      if (keyBytes.length != 32) throw const FormatException('invalid identity length');
    } on FormatException {
      throw HostLinkError(
        HostLinkErrorKind.authFailed,
        appL10n.mobileIrohNeedRepair,
        retryable: false,
        diagnosticCode: HostLinkDiagnosticCode.irohPeerRefused,
      );
    }

    final IrohChannel channel;
    final generation = _networkGeneration;
    try {
      final secretKey = await irohSecretKey(bytes: keyBytes);
      // Reuse this link's endpoint when it still belongs to the same identity:
      // rebinding costs a relay handshake and throws away the address cache.
      var owner = _irohOwner;
      final identity = secretKey.publicKey.toHex();
      if (owner != null && (!owner.isActive || _irohOwnerKey != identity)) {
        await _releaseIrohOwner();
        owner = null;
      }
      owner ??= await IrohEndpointOwner.acquire(secretKey);
      _irohOwner = owner;
      _irohOwnerKey = identity;
      channel = await IrohChannel.open(
        endpointId: endpointId,
        secretKey: secretKey,
        // A stored host is a known peer: `hello`, never a code the person would
        // have to read off the computer on every reconnect.
        name: host.name,
        relayUrls: host.relayUrls,
        directAddresses: host.directAddresses,
        endpointOwner: owner,
      );
    } on IrohChannelException catch (e) {
      throw irohError(e);
    } on Object catch (e) {
      throw HostLinkError(
        HostLinkErrorKind.unreachable,
        appL10n.remoteErrHostUnreachable,
        detail: '$e',
        retryable: true,
        diagnosticCode: HostLinkDiagnosticCode.irohTunnelFailed,
      );
    }
    if (generation != _networkGeneration) {
      // The network changed while this dial was in flight: the sockets it just
      // opened belong to the old interface, so do not hand them to the client.
      await channel.close();
      throw HostLinkError(
        HostLinkErrorKind.unreachable,
        appL10n.remoteErrHostUnreachable,
        detail: 'network_changed',
        retryable: true,
        diagnosticCode: HostLinkDiagnosticCode.irohTunnelFailed,
      );
    }

    LocalForwarder? forwarder;
    HttpClient? httpClient;
    var transferred = false;
    try {
      _checkOpen();
      _emit(HostLinkStatus(HostLinkPhase.connecting, step: HostLinkStep.tunnel));
      forwarder = await LocalForwarder.bind(channel.openTunnel);
      _checkOpen();
      httpClient = IrohTunnelHttpClient(caCertificatePem: secrets.caPem, tunnelPort: forwarder.port);
      final transport = _IrohTransport(channel: channel, forwarder: forwarder, httpClient: httpClient);
      _iroh = transport;
      transferred = true;
      return transport;
    } on Object {
      _checkOpen();
      throw HostLinkError(
        HostLinkErrorKind.tunnelFailed,
        appL10n.commonConnectionFailed,
        retryable: true,
        diagnosticCode: HostLinkDiagnosticCode.irohTunnelFailed,
      );
    } finally {
      if (!transferred) {
        try {
          httpClient?.close(force: true);
        } finally {
          try {
            await forwarder?.close();
          } finally {
            await channel.close();
          }
        }
      }
    }
  }

  Future<void> _closeIroh() async {
    final transport = _iroh;
    _iroh = null;
    await transport?.close();
  }

  /// Drops this link's reference on the shared endpoint.
  ///
  /// Reconnects keep it (that is the point of sharing); the link's teardown and a
  /// network change release it.
  Future<void> _releaseIrohOwner() async {
    final owner = _irohOwner;
    _irohOwner = null;
    _irohOwnerKey = null;
    await owner?.release();
  }

  /// A network change invalidated every socket the endpoint holds.
  ///
  /// iroh asks Android apps to call `Endpoint::network_change()`; `iroh_quic`
  /// 1.4.0 does not expose it, so the fallback is to close this identity's
  /// endpoint and let the next dial bind a new one. Single-flight: repeated
  /// connectivity events coalesce into one restart.
  Future<void> _restartForNetworkChange() {
    final running = _networkRestart;
    if (running != null) return running;
    _networkGeneration++;
    return _networkRestart = _doNetworkRestart().whenComplete(() => _networkRestart = null);
  }

  Future<void> _doNetworkRestart() async {
    final owner = _irohOwner;
    await _closeIroh();
    if (owner != null) {
      // Invalidate closes the endpoint for every link sharing this identity and
      // waits until its sockets are gone, so the next bind cannot collide.
      await owner.invalidate();
      await _releaseIrohOwner();
    }
  }

  SecurityContext _securityContext(String pem) =>
      SecurityContext(withTrustedRoots: true)..setTrustedCertificatesBytes(utf8.encode(pem));

  /// The gateway's own origin (`scheme://host:port`), which its trust gate
  /// compares the Origin header against.
  static String _originOf(String origin) {
    final uri = Uri.parse(origin);
    final port = uri.hasPort ? ':${uri.port}' : '';
    return '${uri.scheme}://${uri.host}$port';
  }

  void _watchMux(DshClient client) {
    unawaited(_muxSub?.cancel());
    _muxSub = client.mux.states.listen((state) {
      if (state == DshConnectionState.unauthorized && identical(client, _client)) {
        // The short session expired or the device was revoked mid-flight. A
        // fresh renew on the next attempt distinguishes the two.
        _lost(HostLinkError(HostLinkErrorKind.authFailed, appL10n.remoteErrDshSignInExpired, retryable: true));
      }
    });
  }

  void _lost(HostLinkError reason) {
    if (_closed || _recovering || _status.phase == HostLinkPhase.failed) return;
    if (_status.phase != HostLinkPhase.connected) return;
    if (_opening != null) return;
    final opening = _opening = _startOpening(() => _recover(reason));
    unawaited(opening.then((_) {}, onError: (_) {}));
  }

  Future<DshClient> _recover(HostLinkError reason) async {
    _recovering = true;
    var last = reason;
    try {
      while (!_closed) {
        if (_backoff.exhausted) {
          final error = HostLinkError(
            last.kind,
            last.message,
            detail: [if (last.detail != null) last.detail!, appL10n.remoteRetryCount(_backoff.attempt)].join('\n'),
            retryable: true,
            diagnosticCode: last.diagnosticCode,
          );
          _fail(error);
          throw error;
        }
        final delay = _backoff.next();
        // Arm the wait *before* announcing the attempt: a kick that lands in
        // between would otherwise hit an idle timer and be lost, leaving the
        // full delay to run out anyway.
        final wait = _delay.wait(delay);
        _emit(
          HostLinkStatus(
            HostLinkPhase.reconnecting,
            attempt: _backoff.attempt,
            error: last,
            nextRetryAt: DateTime.now().add(delay),
          ),
        );
        await wait;
        if (_closed) break;
        try {
          final client = await _connectOnce();
          _backoff.reset();
          return client;
        } on HostLinkError catch (e) {
          if (_closed) break;
          if (!e.retryable) {
            _fail(e);
            rethrow;
          }
          last = e;
        } catch (e) {
          if (_closed) break;
          last = HostLinkError(HostLinkErrorKind.other, appL10n.commonConnectionFailed, detail: '$e', retryable: true);
        }
      }
      throw StateError('link closed');
    } finally {
      _recovering = false;
    }
  }

  /// Connectivity events: a live iroh link cannot keep its sockets, so it
  /// restarts its endpoint; everything else just gets the ordinary nudge.
  void _onNetworkKick() {
    if (_closed) return;
    if (_iroh != null || _irohOwner != null) {
      // Restart in the background: the listener is synchronous and the
      // invalidation awaits native closes.
      unawaited(
        _restartForNetworkChange().then((_) {
          if (_closed) return;
          final error = HostLinkError(
            HostLinkErrorKind.unreachable,
            appL10n.remoteErrHostUnreachable,
            detail: 'network_changed',
            retryable: true,
            diagnosticCode: HostLinkDiagnosticCode.irohTunnelFailed,
          );
          if (_status.phase == HostLinkPhase.connected) {
            _lost(error);
          } else {
            kick();
          }
        }, onError: (_) {}),
      );
      return;
    }
    kick();
  }

  @override
  void kick() {
    if (_closed) return;
    switch (_status.phase) {
      case HostLinkPhase.reconnecting:
        // Cut the wait short but keep the attempt count: a network that keeps
        // changing must still run out of attempts instead of retrying forever.
        _delay.skip();
      case HostLinkPhase.failed:
        if (_status.error?.retryable ?? false) retry();
      case HostLinkPhase.connected || HostLinkPhase.idle || HostLinkPhase.connecting:
        break;
    }
  }

  @override
  void retry() {
    if (_closed || _status.isBusy && _status.phase != HostLinkPhase.reconnecting) return;
    if (_status.phase == HostLinkPhase.reconnecting) {
      _backoff.reset();
      _delay.skip();
      return;
    }
    if (_status.phase == HostLinkPhase.failed || _status.phase == HostLinkPhase.idle) {
      unawaited(open().then((_) {}, onError: (_) {}));
    }
  }

  @override
  Future<void> close() {
    final closing = _closing;
    if (closing != null) return closing;
    _closed = true;
    _closedSignal.complete();
    _delay.cancel();
    _renewHttpClient?.close(force: true);
    // Publish the future before synchronous idle listeners can re-enter close.
    return _closing = Future<void>.microtask(_closeResources);
  }

  Future<void> _closeResources() async {
    _emit(HostLinkStatus.idle);
    await _kickSub?.cancel();
    await _muxSub?.cancel();
    // No attempt may assign a new transport after close has completed. Native
    // opens are deliberately awaited; their post-await checks release locals.
    await _opening?.then<void>((_) {}, onError: (_) {});
    final client = _client;
    _client = null;
    try {
      if (client != null) await client.close().catchError((_) {});
      await _closeIroh();
      await _networkRestart;
      await _releaseIrohOwner();
    } finally {
      await _statuses.close();
      await _clients.close();
    }
  }
}

/// The live iroh data plane for one attempt.
class _IrohTransport {
  _IrohTransport({required this.channel, required this.forwarder, required this.httpClient});

  final IrohChannel channel;
  final LocalForwarder forwarder;
  final HttpClient httpClient;

  int get port => forwarder.port;

  Future<void> close() async {
    // Order matters: the forwarder pipes sockets into streams this channel owns,
    // so it goes first, then the client that dials the forwarder.
    try {
      httpClient.close(force: true);
    } finally {
      try {
        await forwarder.close();
      } finally {
        await channel.close();
      }
    }
  }
}
