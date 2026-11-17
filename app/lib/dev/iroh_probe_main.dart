// Development entrypoint: proves the iroh transport end to end without the UI.
//   flutter build apk --debug --flavor arm64 -t lib/dev/iroh_probe_main.dart
//
// Paste the iroh pairing descriptor JSON that the computer shows, then run the
// probe. It pairs over iroh, authorizes at the gateway, and runs one real RPC
// through the tunnel.
import 'dart:convert';
import 'dart:io';

import 'package:dsh_client/dsh_client.dart';
import 'package:flutter/material.dart';
import 'package:iroh_flutter/iroh_flutter.dart';

import '../remote/mobile/iroh/iroh_channel.dart';
import '../remote/mobile/iroh/iroh_descriptor.dart';
import '../remote/mobile/iroh/iroh_http_client.dart';
import '../remote/mobile/mobile_pairing.dart';
import '../remote/ssh/local_forward.dart';

void main() => runApp(const MaterialApp(home: _Probe()));

class _Probe extends StatefulWidget {
  const _Probe();

  @override
  State<_Probe> createState() => _ProbeState();
}

class _ProbeState extends State<_Probe> {
  final _descriptor = TextEditingController();
  final _code = TextEditingController();
  final _lines = <String>[];
  bool _running = false;

  void _log(String line) {
    debugPrint('[iroh] $line');
    if (mounted) setState(() => _lines.add(line));
  }

  @override
  void dispose() {
    _descriptor.dispose();
    _code.dispose();
    super.dispose();
  }

  Future<void> _run() async {
    if (_running) return;
    setState(() => _running = true);
    final sw = Stopwatch()..start();
    IrohChannel? channel;
    LocalForwarder? forwarder;
    try {
      final descriptor = IrohPairingDescriptor.decode(_descriptor.text.trim());
      _log('descriptor ok: endpoint ${descriptor.endpointId.substring(0, 8)}… '
          'port ${descriptor.localPort} code ${descriptor.irohCode}');
      if (!descriptor.isFreshAt(DateTime.now())) {
        throw StateError('descriptor expired; generate a new one on the computer');
      }

      // A fresh identity per run keeps the probe from reusing a stored pairing;
      // the host treats an unknown endpoint as a new peer and asks for the code.
      final secret = SecretKey.generate();
      _log('dialing iroh…');
      channel = await IrohChannel.open(
        endpointId: descriptor.endpointId,
        secretKey: secret,
        code: _code.text.trim().isEmpty ? descriptor.irohCode : _code.text.trim(),
        name: 'dsh-go-probe',
      );
      _log('transport paired in ${sw.elapsedMilliseconds} ms');

      forwarder = await LocalForwarder.bind(channel.openTunnel);
      _log('forwarding 127.0.0.1:${forwarder.port} → gateway');

      // Step one: authorize at the gateway with the descriptor's pairing token.
      final http = IrohTunnelHttpClient(
        caCertificatePem: caDerToPem(descriptor.caCertificateDer),
        tunnelPort: forwarder.port,
      );
      final pairResponse = await _postJson(
        http,
        Uri.parse('${descriptor.origin}/mobile-access/auth/native-pair'),
        <String, Object?>{'token': descriptor.gatewayToken, 'label': 'dsh-go-probe'},
      );
      final sessionToken = pairResponse['sessionToken'];
      final csrfToken = pairResponse['csrfToken'];
      if (sessionToken is! String || csrfToken is! String) {
        throw StateError('pair response missing tokens: ${pairResponse.keys.join(",")}');
      }
      _log('gateway authorized: device ${pairResponse['deviceId']}');

      // Step two: talk to the harness the way every other host is talked to.
      final connection = DshConnection(
        Uri.parse(descriptor.origin),
        httpClient: http,
        extraCookies: {'dsh_ma_session': sessionToken, 'dsh_ma_device': pairResponse['deviceToken'] as String? ?? ''},
        extraHeaders: {'x-dsh-mobile-csrf': csrfToken, originHeaderName: descriptor.origin},
      );
      final health = await connection.checkHealth();
      _log('health: $health');
      if (health != DshHealth.unreachable) {
        final client = DshClient(connection);
        await client.mux.ready(timeout: const Duration(seconds: 20));
        _log('mux ready');
        final sessions = await client.listSessions();
        _log('sessions: ${sessions.length}');
        _log('PASS in ${sw.elapsedMilliseconds} ms');
      } else {
        _log('FAIL: gateway unreachable over the tunnel');
      }
    } on IrohChannelException catch (e) {
      _log('FAIL: iroh ${e.reason}${e.detail == null ? '' : ' (${e.detail})'}');
    } on IrohDescriptorException catch (e) {
      _log('FAIL: descriptor ${e.reason}');
    } on Object catch (e, s) {
      _log('FAIL: $e');
      _log(s.toString().split('\n').take(4).join(' | '));
    } finally {
      await forwarder?.close();
      await channel?.close();
      if (mounted) setState(() => _running = false);
    }
  }

  static Future<Map<String, Object?>> _postJson(
    HttpClient http,
    Uri uri,
    Map<String, Object?> body,
  ) async {
    final request = await http.postUrl(uri);
    request.headers.contentType = ContentType.json;
    request.headers.set(originHeaderName, '${uri.scheme}://${uri.host}${uri.hasPort ? ':${uri.port}' : ''}');
    request.write(jsonEncode(body));
    final response = await request.close();
    final text = await response.transform(utf8.decoder).join();
    if (response.statusCode >= 400) {
      throw HttpException('HTTP ${response.statusCode}: $text');
    }
    final decoded = jsonDecode(text);
    if (decoded is! Map<String, Object?>) throw StateError('unexpected body: $text');
    return decoded;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('iroh probe')),
      body: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _descriptor,
              maxLines: 4,
              decoration: const InputDecoration(labelText: 'pairing descriptor JSON'),
            ),
            TextField(
              controller: _code,
              decoration: const InputDecoration(labelText: 'six-digit code (optional)'),
            ),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: _running ? null : _run,
              child: Text(_running ? 'running…' : 'run probe'),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: ListView.builder(
                itemCount: _lines.length,
                itemBuilder: (context, i) => Text(_lines[i], style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
