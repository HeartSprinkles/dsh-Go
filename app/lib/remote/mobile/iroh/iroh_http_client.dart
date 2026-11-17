/// The HTTP/TLS plumbing an iroh-tunnelled DSH Mobile gateway needs, on top of
/// the ordinary [DshConnection] path.
///
/// Two things differ from a plain host:
///  * the socket is a loopback tunnel, but the gateway pins its `Host` header to
///    `<half>.<half>.iroh.localhost:<localPort>`, so the request has to present
///    that authority while the bytes travel over `127.0.0.1:<forwarded port>`;
///  * the gateway serves its own self-signed CA, so the client trusts exactly
///    that certificate alone, without the system roots.
///
/// A [connectionFactory] override resolves both without a certificate bypass:
/// the URL keeps the gateway's name (so TLS SNI and hostname verification use
/// it) while the TCP socket goes to the tunnel's local port, and no DNS lookup
/// for the pseudo-TLD is ever attempted. `Origin` and the CSRF header are not
/// this class's business: `DshConnection.extraHeaders` carries them, so the
/// pairing and mux paths agree on one place.
library;

import 'dart:convert';
import 'dart:io';

/// An [HttpClient] that dials a loopback tunnel and trusts one extra CA.
class IrohTunnelHttpClient implements HttpClient {
  IrohTunnelHttpClient({required String caCertificatePem, required int tunnelPort})
    : _inner = buildIrohHttpClient(caCertificatePem, tunnelPort);

  final HttpClient _inner;

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) => _inner.openUrl(method, url);

  @override
  Future<HttpClientRequest> open(String method, String host, int port, String path) =>
      _inner.open(method, host, port, path);

  @override
  Future<HttpClientRequest> get(String host, int port, String path) => _inner.get(host, port, path);

  @override
  Future<HttpClientRequest> getUrl(Uri url) => _inner.getUrl(url);

  @override
  Future<HttpClientRequest> post(String host, int port, String path) => _inner.post(host, port, path);

  @override
  Future<HttpClientRequest> postUrl(Uri url) => _inner.postUrl(url);

  @override
  Future<HttpClientRequest> put(String host, int port, String path) => _inner.put(host, port, path);

  @override
  Future<HttpClientRequest> putUrl(Uri url) => _inner.putUrl(url);

  @override
  Future<HttpClientRequest> delete(String host, int port, String path) => _inner.delete(host, port, path);

  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => _inner.deleteUrl(url);

  @override
  Future<HttpClientRequest> patch(String host, int port, String path) => _inner.patch(host, port, path);

  @override
  Future<HttpClientRequest> patchUrl(Uri url) => _inner.patchUrl(url);

  @override
  Future<HttpClientRequest> head(String host, int port, String path) => _inner.head(host, port, path);

  @override
  Future<HttpClientRequest> headUrl(Uri url) => _inner.headUrl(url);

  @override
  void close({bool force = false}) => _inner.close(force: force);

  // The remaining members only configure the wrapped client. They are forwarded
  // by hand on purpose: a noSuchMethod fallback could silently drop the two
  // overrides (connectionFactory/findProxy) this class exists to install.
  @override
  Duration get idleTimeout => _inner.idleTimeout;

  @override
  set idleTimeout(Duration value) => _inner.idleTimeout = value;

  @override
  Duration? get connectionTimeout => _inner.connectionTimeout;

  @override
  set connectionTimeout(Duration? value) => _inner.connectionTimeout = value;

  @override
  bool get autoUncompress => _inner.autoUncompress;

  @override
  set autoUncompress(bool value) => _inner.autoUncompress = value;

  @override
  int? get maxConnectionsPerHost => _inner.maxConnectionsPerHost;

  @override
  set maxConnectionsPerHost(int? value) => _inner.maxConnectionsPerHost = value;

  @override
  String? get userAgent => _inner.userAgent;

  @override
  set userAgent(String? value) => _inner.userAgent = value;

  @override
  set authenticate(Future<bool> Function(Uri url, String scheme, String? realm)? f) => _inner.authenticate = f;

  @override
  void addCredentials(Uri url, String realm, HttpClientCredentials credentials) =>
      _inner.addCredentials(url, realm, credentials);

  @override
  set connectionFactory(Future<ConnectionTask<Socket>> Function(Uri url, String? proxyHost, int? proxyPort)? f) =>
      _inner.connectionFactory = f;

  @override
  set findProxy(String Function(Uri url)? f) => _inner.findProxy = f;

  @override
  set authenticateProxy(Future<bool> Function(String host, int port, String scheme, String? realm)? f) =>
      _inner.authenticateProxy = f;

  @override
  void addProxyCredentials(String host, int port, String realm, HttpClientCredentials credentials) =>
      _inner.addProxyCredentials(host, port, realm, credentials);

  @override
  set badCertificateCallback(bool Function(X509Certificate cert, String host, int port)? callback) =>
      _inner.badCertificateCallback = callback;

  @override
  set keyLog(Function(String line)? callback) => _inner.keyLog = callback;
}

/// Builds the redirecting client. Kept separate so a test can inspect the two
/// hooks without an iroh endpoint.
HttpClient buildIrohHttpClient(String caCertificatePem, int tunnelPort) {
  if (caCertificatePem.trim().isEmpty) {
    throw ArgumentError.value(caCertificatePem, 'caCertificatePem', 'A pinned gateway CA is required');
  }
  // This client is dedicated to one gateway, not general-purpose HTTPS. Trust
  // only its paired CA, never the platform's unrelated public roots.
  final context = SecurityContext(withTrustedRoots: false);
  context.setTrustedCertificatesBytes(utf8.encode(caCertificatePem));
  final client = HttpClient(context: context);
  // The URI keeps the gateway's own name so TLS checks it; only the TCP socket
  // is redirected, which is what makes the tunnel transparent.
  client.connectionFactory = (Uri uri, String? proxyHost, int? proxyPort) =>
      Socket.startConnect(InternetAddress.loopbackIPv4, tunnelPort);
  // A proxy would take over the connection and defeat the redirect above.
  client.findProxy = (Uri url) => 'DIRECT';
  return client;
}
