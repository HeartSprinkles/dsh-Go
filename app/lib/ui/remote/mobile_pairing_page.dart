import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/l10n.dart';
import '../../remote/mobile/mobile_config.dart';
import '../../remote/mobile/mobile_pairing.dart';
import '../../state/hosts_state.dart';
import '../common/app_dialog.dart';
import '../shell/page_frame.dart';
import '../theme/app_icons.dart';
import '../theme/theme.dart';
import 'host_key_dialog.dart';

/// Pastes a dsh-mobile pairing link/key and pairs this phone with the gateway.
class MobilePairingPage extends ConsumerStatefulWidget {
  const MobilePairingPage({super.key});

  @override
  ConsumerState<MobilePairingPage> createState() => _MobilePairingPageState();
}

class _MobilePairingPageState extends ConsumerState<MobilePairingPage> {
  final _text = TextEditingController();
  final _origin = TextEditingController();
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
    final invite = MobilePairingInvite.tryParse(_text.text);
    if (invite == null) {
      setState(() => _error = context.l10n.remoteErrHostNotFound);
      return;
    }
    final origin = (invite.origin ?? _origin.text).trim();
    if (origin.isEmpty || (!origin.startsWith('https://') && !origin.startsWith('http://'))) {
      setState(() => _error = context.l10n.remoteErrInvalidServer);
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });
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
      if (mounted) setState(() => _error = e.code);
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return AppPage.list(
      title: 'dsh-mobile',
      subtitle: Text(l10n.remoteHostsIntro),
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _text,
                enabled: !_busy,
                decoration: const InputDecoration(
                  labelText: '配对链接 / 密钥',
                  hintText: 'https://…/mobile-access/pair#… 或 dsh1.…',
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _origin,
                enabled: !_busy,
                keyboardType: TextInputType.url,
                decoration: InputDecoration(labelText: l10n.remoteServerAddress),
              ),
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
                label: Text(l10n.remotePairEntry),
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
