/// Pairing a phone with a DSH Mobile gateway over iroh.
///
/// The descriptor the host shows already carries everything the first
/// connection needs (endpoint id, six-digit code, gateway token, CA), so pairing
/// is: take this device's iroh identity (or make one), dial, authorize at the
/// gateway with the descriptor's token, and hand the caller the same
/// [MobileSession] the LAN path produces. Nothing here is iroh-specific after
/// [IrohChannel].
library;

import 'dart:convert';

import 'package:iroh_flutter/iroh_flutter.dart';

import '../../ssh/local_forward.dart';
import '../mobile_config.dart';
import '../mobile_pairing.dart';
import 'iroh_channel.dart';
import 'iroh_descriptor.dart';
import 'iroh_http_client.dart';

/// What one successful iroh pairing produced, before anything is persisted.
///
/// [secretKeyBytes] is the identity to store: reusing it on the next attempt is
/// what keeps the host's device list from filling up with one entry per try.
class IrohPairingOutcome {
  const IrohPairingOutcome({
    required this.descriptor,
    required this.session,
    required this.secretKeyBytes,
    required this.deviceLabel,
  });

  final IrohPairingDescriptor descriptor;
  final MobileSession session;
  final List<int> secretKeyBytes;
  final String deviceLabel;

  /// The config to save. [id] is supplied by the caller so re-pairing an
  /// existing host keeps its id, and with it its sessions and secret keys.
  MobileHostConfig toConfig({required String id, required String name}) => MobileHostConfig(
    id: id,
    name: name,
    origin: descriptor.origin,
    transport: MobileTransport.iroh,
    instanceId: session.instanceId.isEmpty ? descriptor.instanceId : session.instanceId,
    caFingerprint: descriptor.instanceId,
    deviceId: session.deviceId.isEmpty ? null : session.deviceId,
    deviceExpiresAt: session.deviceExpiresAt,
    endpointId: descriptor.endpointId,
    localPort: descriptor.localPort,
  );

  MobileSecrets toSecrets() => MobileSecrets(
    deviceToken: session.deviceToken ?? '',
    caPem: caDerToPem(descriptor.caCertificateDer),
    irohSecretKey: base64Encode(secretKeyBytes),
  );
}

/// Pairs with the gateway behind [descriptor] over iroh.
///
/// [secretKeyBytes] is this device's stored iroh identity (32 bytes); when it is
/// null a new one is generated and returned in the outcome, so the caller can
/// persist it before the next attempt.
Future<IrohPairingOutcome> pairOverIroh({
  required IrohPairingDescriptor descriptor,
  required List<int>? secretKeyBytes,
  String deviceLabel = 'DSH Go',
  Duration timeout = const Duration(seconds: 30),
}) async {
  // Recheck here after the UI's trust dialog, before loading the native core or
  // sending either one-time pairing credential.
  if (!descriptor.isFreshAt(DateTime.now())) {
    throw const IrohDescriptorException('invalid_expiry');
  }
  final secret = secretKeyBytes == null ? SecretKey.generate() : SecretKey.fromBytes(secretKeyBytes);
  final channel = await IrohChannel.open(
    endpointId: descriptor.endpointId,
    secretKey: secret,
    // Pairing always sends the code: the phone is introducing itself, so it has
    // no paired endpoint id for the host to recognise yet.
    code: descriptor.irohCode,
    name: deviceLabel,
    timeout: timeout,
  );
  try {
    final forwarder = await LocalForwarder.bind(channel.openTunnel);
    try {
      final client = MobilePairingClient(
        label: deviceLabel,
        clientFactory: ({String? trustedPem}) =>
            IrohTunnelHttpClient(caCertificatePem: caDerToPem(descriptor.caCertificateDer), tunnelPort: forwarder.port),
      );
      // The token is the one-time secret from the descriptor; the host binds the
      // device token it returns to the endpoint id this phone just used.
      final session = await client.pair(descriptor.origin, descriptor.gatewayToken, instanceId: descriptor.instanceId);
      return IrohPairingOutcome(
        descriptor: descriptor,
        session: session,
        secretKeyBytes: secret.toBytes(),
        deviceLabel: deviceLabel,
      );
    } finally {
      await forwarder.close();
    }
  } finally {
    await channel.close();
  }
}
