import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/l10n.dart';
import '../../remote/mobile/iroh/iroh_channel.dart';
import '../../remote/mobile/iroh/iroh_descriptor.dart';
import '../../remote/mobile/iroh/iroh_pairing.dart';
import '../../remote/mobile/mobile_config.dart';
import '../../remote/mobile/mobile_link.dart';
import '../../remote/mobile/mobile_pairing.dart';
import '../../state/hosts_state.dart';
import '../common/app_dialog.dart';
import '../shell/page_frame.dart';
import '../theme/app_icons.dart';
import '../theme/theme.dart';
import 'host_key_dialog.dart';

/// How the person is about to pair.
enum _PairingMode { lan, iroh }

/// Pastes a dsh-mobile pairing link/key (LAN) or the iroh pairing description
/// and pairs this phone with the gateway.
class MobilePairingPage extends ConsumerStatefulWidget {
  const MobilePairingPage({super.key});

  @override
  ConsumerState<MobilePairingPage> createState() => _MobilePairingPageState();
}

class _MobilePairingPageState extends ConsumerState<MobilePairingPage> {
  final _text = TextEditingController();
  final _origin = TextEditingController();
  _PairingMode _mode = _PairingMode.lan;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _text.dispose();
    _origin.dispose();
    super.dispose();
  }

  Future<void> _pair() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      switch (_mode) {
        case _PairingMode.lan:
          await _pairLan();
        case _PairingMode.iroh:
          await _pairIroh();
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _pairLan() async {
    final invite = MobilePairingInvite.tryParse(_text.text);
    if (invite == null) {
      setState(() => _error = context.l10n.mobilePairInvalidLink);
      return;
    }
    final origin = (invite.origin ?? _origin.text).trim();
    if (origin.isEmpty || (!origin.startsWith('https://') && !origin.startsWith('http://'))) {
      setState(() => _error = context.l10n.mobilePairNeedOrigin);
      return;
    }
    try {
      final client = MobilePairingClient();
      var caPem = '';
      String? fingerprint;
      final der = await client.fetchCa(origin);
      if (der != null) {
        caPem = caDerToPem(der);
        fingerprint = caFingerprint(der);
        if (!mounted) return;
        final ok = await _confirmTrust(context, origin, invite.instanceId, fingerprint);
        if (!ok) return;
      }

      final session = await client.pair(
        origin,
        invite.token,
        instanceId: invite.instanceId,
        trustedPem: caPem.isEmpty ? null : caPem,
      );
      final config = MobileHostConfig(
        id: MobileHostConfig.newId(),
        name: origin,
        origin: origin,
        instanceId: session.instanceId.isEmpty ? invite.instanceId : session.instanceId,
        caFingerprint: fingerprint,
        deviceId: session.deviceId.isEmpty ? null : session.deviceId,
        deviceExpiresAt: session.deviceExpiresAt,
      );
      await ref
          .read(hostsProvider.notifier)
          .saveMobile(config, secrets: MobileSecrets(deviceToken: session.deviceToken ?? '', caPem: caPem));
      if (!mounted) return;
      await activateHost(context, ref, HostRef.mobile(config.id));
      if (mounted) Navigator.of(context).pop();
    } on MobilePairingException catch (e) {
      // Map to the same sentences the link uses, so the page never shows a raw
      // gateway code like "device_revoked".
      if (mounted) setState(() => _error = mobileError(e).message);
    } catch (e) {
      if (mounted) setState(() => _error = context.l10n.mobilePairFailed);
    }
  }

  Future<void> _pairIroh() async {
    final IrohPairingDescriptor descriptor;
    try {
      descriptor = IrohPairingDescriptor.decode(_text.text.trim());
    } on IrohDescriptorException {
      setState(() => _error = context.l10n.mobilePairIrohInvalid);
      return;
    }
    if (!descriptor.isFreshAt(DateTime.now())) {
      setState(() => _error = context.l10n.mobilePairIrohStale);
      return;
    }
    try {
      if (!mounted) return;
      final ok = await _confirmTrust(context, descriptor.origin, descriptor.instanceId, descriptor.instanceId);
      if (!ok) return;
      final outcome = await pairOverIroh(descriptor: descriptor, secretKeyBytes: null);
      final config = outcome.toConfig(id: MobileHostConfig.newId(), name: descriptor.endpointId.substring(0, 8));
      await ref.read(hostsProvider.notifier).saveMobile(config, secrets: outcome.toSecrets());
      if (!mounted) return;
      await activateHost(context, ref, HostRef.mobile(config.id));
      if (mounted) Navigator.of(context).pop();
    } on IrohChannelException catch (e) {
      // Keep the reason visible: `irohError` already turns it into a sentence,
      // and the raw text is the only clue a LAN-blocked or QUIC-blocked network
      // leaves behind.
      if (mounted) {
        final error = irohError(e);
        setState(() => _error = error.detail == null ? error.message : context.l10n.remoteErrorDetail(error.message, error.detail!));
      }
    } on MobilePairingException catch (e) {
      if (mounted) setState(() => _error = mobileError(e).message);
    } on IrohDescriptorException {
      if (mounted) setState(() => _error = context.l10n.mobilePairIrohInvalid);
    } catch (e) {
      if (mounted) setState(() => _error = context.l10n.mobilePairFailed);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final iroh = _mode == _PairingMode.iroh;
    return AppPage.list(
      title: 'dsh-mobile',
      subtitle: Text(l10n.remoteHostsIntro),
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              SegmentedButton<_PairingMode>(
                segments: [
                  ButtonSegment(value: _PairingMode.lan, label: Text(l10n.mobileTransportLan)),
                  ButtonSegment(value: _PairingMode.iroh, label: Text(l10n.mobileTransportIroh)),
                ],
                selected: {_mode},
                onSelectionChanged: _busy
                    ? null
                    : (selection) => setState(() {
                        _mode = selection.first;
                        _error = null;
                      }),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _text,
                enabled: !_busy,
                minLines: iroh ? 3 : 1,
                maxLines: iroh ? 6 : 1,
                decoration: InputDecoration(
                  labelText: iroh ? l10n.mobilePairIrohDescriptorHint : l10n.remotePairPasteLink,
                  hintText: iroh ? null : 'https://…/mobile-access/pair#… 或 dsh1.…',
                ),
              ),
              // The iroh description carries the endpoint, port, six-digit code
              // and CA, so there is nothing else to enter; the LAN path still
              // needs the server address for a bare `dsh1.` key.
              if (!iroh) ...[
                const SizedBox(height: 12),
                TextField(
                  controller: _origin,
                  enabled: !_busy,
                  keyboardType: TextInputType.url,
                  decoration: InputDecoration(labelText: l10n.remoteServerAddress),
                ),
              ],
              if (_error case final e?) ...[
                const SizedBox(height: 12),
                Text(e, style: Theme.of(context).textTheme.bodySmall?.copyWith(color: DshColors.of(context).danger)),
              ],
              const SizedBox(height: 20),
              FilledButton.icon(
                onPressed: _busy ? null : _pair,
                icon: _busy
                    ? const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(AppIcons.qrCode, size: 18),
                label: Text(l10n.mobilePairButton),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

Future<bool> _confirmTrust(BuildContext context, String origin, String instanceId, String fingerprint) {
  return showAppDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (dialog) => AlertDialog(
      title: Text(context.l10n.remoteHostKeyTrustTitle),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              context.l10n.remoteHostKeyFirstConnection(origin, origin),
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 14),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
              decoration: ShapeDecoration(
                color: DshColors.of(context).codeWellBg,
                shape: Squircle.border(
                  AppShape.md,
                  side: BorderSide(color: DshColors.of(context).codeWellBorder, width: 0.5),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('instanceId: $instanceId', style: AppType.monoLabel(color: DshColors.of(context).textTertiary)),
                  const SizedBox(height: 4),
                  SelectableText(fingerprint, style: AppType.mono(size: 13, color: DshColors.of(context).codeWellFg)),
                ],
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(dialog, false), child: Text(context.l10n.commonCancel)),
        FilledButton(onPressed: () => Navigator.pop(dialog, true), child: Text(context.l10n.remoteHostKeyTrustConnect)),
      ],
    ),
  ).then((ok) => ok ?? false);
}
