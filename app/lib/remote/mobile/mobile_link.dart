import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dsh_client/dsh_client.dart';
import 'package:iroh_flutter/iroh_flutter.dart';

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
    'device_limit' => HostLinkError(
      HostLinkErrorKind.authFailed,
      appL10n.commonConnectionFailed,
      retryable: false,
    ),
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
    _ => HostLinkError(
      HostLinkErrorKind.unreachable,
      appL10n.commonConnectionFailed,
      detail: code,
      retryable: true,
    ),
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
    diagnosticCode: retryable
        ? HostLinkDiagnosticCode.irohTunnelFailed
        : HostLinkDiagnosticCode.irohPeerRefused,
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
    _kickSub = kicks?.listen((_) => kick());
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
  bool _closed = false;
  bool _recovering = false;

  /// The iroh data plane, rebuilt on every attempt: [Endpoint]s own sockets and
  /// a relay task, so the previous one is always torn down first.
  _IrohTransport? _iroh;

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
    final client = _client;
    if (client != null && _status.isConnected) return Future.value(client);
    return _opening ??= _openFirst().whenComplete(() => _opening = null);
  }

  Future<DshClient> _openFirst() async {
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
    final secrets = await loadSecrets();
    if (secrets.deviceToken.isEmpty) {
      throw HostLinkError(HostLinkErrorKind.authFailed, appL10n.remoteErrSignIn, retryable: false);
    }

    // Tear the previous data plane down before a new one exists: two endpoints
    // would both hold sockets and relay connections.
    await _closeIroh();

    final transport = config.isIroh ? await _openIroh(secrets) : null;
    final pairing = transport == null
        ? _pairing
        : MobilePairingClient(
            label: _pairing.label,
            clientFactory: ({String? trustedPem}) =>
                IrohTunnelHttpClient(caCertificatePem: secrets.caPem, tunnelPort: transport.port),
          );

    final MobileSession session;
    try {
      session = await pairing.renew(
        config.origin,
        secrets.deviceToken,
        instanceId: config.instanceId,
        trustedPem: secrets.caPem.isEmpty ? null : secrets.caPem,
      );
    } on MobilePairingException catch (e) {
      await _closeIroh();
      throw mobileError(e);
    } on Object {
      await _closeIroh();
      rethrow;
    }

    final connection = DshConnection(
      Uri.parse(config.origin),
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
      extraHeaders: {
        'x-dsh-mobile-csrf': session.csrfToken,
        originHeaderName: _originOf(config.origin),
      },
    );
    final client = DshClient(connection);
    try {
      await client.mux.ready(timeout: const Duration(seconds: 20));
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
  Future<_IrohTransport> _openIroh(MobileSecrets secrets) async {
    final endpointId = config.endpointId;
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
    } on FormatException {
      throw HostLinkError(
        HostLinkErrorKind.authFailed,
        appL10n.mobileIrohNeedRepair,
        retryable: false,
        diagnosticCode: HostLinkDiagnosticCode.irohPeerRefused,
      );
    }

    final IrohChannel channel;
    try {
      channel = await IrohChannel.open(
        endpointId: endpointId,
        secretKey: SecretKey.fromBytes(keyBytes),
        // A stored host is a known peer: `hello`, never a code the person would
        // have to read off the computer on every reconnect.
        name: config.name,
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

    LocalForwarder? forwarder;
    try {
      _emit(HostLinkStatus(HostLinkPhase.connecting, step: HostLinkStep.tunnel));
      forwarder = await LocalForwarder.bind(channel.openTunnel);
    } on Object {
      await channel.close();
      throw HostLinkError(
        HostLinkErrorKind.tunnelFailed,
        appL10n.commonConnectionFailed,
        retryable: true,
        diagnosticCode: HostLinkDiagnosticCode.irohTunnelFailed,
      );
    }
    final httpClient = IrohTunnelHttpClient(caCertificatePem: secrets.caPem, tunnelPort: forwarder.port);
    return _iroh = _IrohTransport(channel: channel, forwarder: forwarder, httpClient: httpClient);
  }

  Future<void> _closeIroh() async {
    final transport = _iroh;
    _iroh = null;
    await transport?.close();
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
    unawaited(_recover(reason).then((_) {}, onError: (_) {}));
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
  Future<void> close() async {
    if (_closed) return;
    _emit(HostLinkStatus.idle);
    _closed = true;
    _delay.cancel();
    await _kickSub?.cancel();
    await _muxSub?.cancel();
    final client = _client;
    _client = null;
    if (client != null) await client.close().catchError((_) {});
    await _closeIroh();
    await _statuses.close();
    await _clients.close();
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
    httpClient.close(force: true);
    await forwarder.close();
    await channel.close();
  }
}
