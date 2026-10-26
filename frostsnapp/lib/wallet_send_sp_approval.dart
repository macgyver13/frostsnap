import 'dart:async';

import 'package:flutter/material.dart';
import 'package:frostsnap/animated_check.dart';
import 'package:frostsnap/global.dart';
import 'package:frostsnap/secure_key_provider.dart';
import 'package:frostsnap/snackbar.dart';
import 'package:frostsnap/src/rust/api.dart';
import 'package:frostsnap/src/rust/api/bitcoin.dart';
import 'package:frostsnap/src/rust/api/device_list.dart';
import 'package:frostsnap/src/rust/api/signing.dart';
import 'package:frostsnap/theme.dart';
import 'package:frostsnap/wallet_tx_details.dart';

/// Runs the ECDH round of a send with silent payment outputs: each selected device reviews the
/// send and contributes its shares. Once a threshold have, signing is opened from them and its
/// session id is returned. Null if the user cancels or the round cannot start.
Future<SignSessionId?> showSilentPaymentApproval(
  BuildContext context, {
  required AccessStructureRef accessStructureRef,
  required UnsignedTx unsignedTx,
  required List<DeviceId> devices,
  required int threshold,
  required BitcoinNetwork network,
}) async {
  final encryptionKey = await SecureKeyProvider.getEncryptionKey();
  if (!context.mounted) return null;
  return showBottomSheetOrDialog<SignSessionId>(
    context,
    title: const Text('Approve silent payment'),
    builder: (context, scrollController) => _SilentPaymentApproval(
      accessStructureRef: accessStructureRef,
      unsignedTx: unsignedTx,
      devices: devices,
      threshold: threshold,
      encryptionKey: encryptionKey,
      checkCode: unsignedTx.outputsCheckCode(network: network),
      scrollController: scrollController,
    ),
  );
}

class _SilentPaymentApproval extends StatefulWidget {
  final AccessStructureRef accessStructureRef;
  final UnsignedTx unsignedTx;
  final List<DeviceId> devices;
  final int threshold;
  final SymmetricKey encryptionKey;
  final String checkCode;
  final ScrollController scrollController;

  const _SilentPaymentApproval({
    required this.accessStructureRef,
    required this.unsignedTx,
    required this.devices,
    required this.threshold,
    required this.encryptionKey,
    required this.checkCode,
    required this.scrollController,
  });

  @override
  State<_SilentPaymentApproval> createState() => _SilentPaymentApprovalState();
}

class _SilentPaymentApprovalState extends State<_SilentPaymentApproval> {
  StreamSubscription<SpEcdhState>? _sub;
  StreamSubscription<DeviceListUpdate>? _devicesSub;
  SpEcdhState? _state;
  final Set<DeviceId> _connected = {};

  /// Set once signing is open, so leaving the sheet does not drop the round's result.
  bool _opened = false;

  /// Set while signing is being opened. A sheet left in the meantime is cleaned up when the
  /// attempt ends.
  bool _opening = false;

  /// Why opening signing last failed, so the user can try again.
  String? _openError;

  @override
  void initState() {
    super.initState();
    _devicesSub = GlobalStreams.deviceListSubject.listen((update) {
      _connected
        ..clear()
        ..addAll(update.state.devices.map((device) => device.id));
      if (mounted) setState(() {});
    });
    _sub = coord
        .startSpSend(
          accessStructureRef: widget.accessStructureRef,
          unsignedTx: widget.unsignedTx,
          devices: widget.devices,
          encryptionKey: widget.encryptionKey,
        )
        .listen(_onState, onError: _onError);
  }

  @override
  void dispose() {
    _devicesSub?.cancel();
    final sub = _sub;
    if (sub != null) {
      sub.cancel();
      if (!_opened && !_opening) _cancelRound();
    }
    super.dispose();
  }

  /// Cancelled or dismissed: take the devices off the approval screen and drop the shares.
  void _cancelRound() {
    coord.cancelProtocol();
    final sessionId = _state?.sessionId;
    if (sessionId != null) coord.cancelSpEcdh(sessionId: sessionId);
  }

  void _onError(Object error) {
    if (!mounted) return;
    showErrorSnackbar(context, 'Silent payment approval failed: $error');
    Navigator.pop(context);
  }

  void _onState(SpEcdhState state) {
    if (!mounted || _opened || _opening) return;
    setState(() => _state = state);
    for (final deviceId in state.connectedButNeedRequest) {
      try {
        coord.requestSpEcdh(
          sessionId: state.sessionId,
          deviceId: deviceId,
          encryptionKey: widget.encryptionKey,
        );
      } catch (e) {
        debugPrint('silent payment ECDH request failed: $e');
      }
    }
    if (state.confirmed.length >= widget.threshold && _openError == null) {
      _openSigning(state);
    }
  }

  Future<void> _openSigning(SpEcdhState state) async {
    setState(() {
      _opening = true;
      _openError = null;
    });
    try {
      final signSessionId = await coord.startSignSp(sessionId: state.sessionId);
      _opened = true;
      if (mounted) {
        Navigator.pop(context, signSessionId);
      } else {
        // Left while signing was opening: nobody is there to follow the session.
        await coord.cancelSignSession(ssid: signSessionId);
      }
    } catch (e) {
      if (!mounted) {
        _cancelRound();
        return;
      }
      setState(() => _openError = '$e');
      showErrorSnackbar(context, 'Could not open signing: $e');
    } finally {
      _opening = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final confirmed = _state?.confirmed ?? const [];
    return ListView(
      controller: widget.scrollController,
      shrinkWrap: true,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
          child: Text(
            'Check the silent payment address on each device and hold to contribute. This is not signing yet.',
            style: theme.textTheme.bodyMedium,
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: DialogCheckCode(widget.checkCode),
        ),
        ListTile(
          title: const Text('Devices'),
          subtitle: const Text('Connect a device to approve'),
          trailing: Text('${confirmed.length}/${widget.threshold}'),
        ),
        for (final deviceId in widget.devices)
          ListTile(
            enabled: _connected.contains(deviceId),
            title: Text(coord.getDeviceName(id: deviceId) ?? '<no-name>'),
            trailing: confirmed.contains(deviceId)
                ? const AnimatedCheckCircle()
                : Text(
                    _connected.contains(deviceId) ? 'Waiting for approval' : '',
                    style: TextStyle(color: theme.colorScheme.primary),
                  ),
          ),
        if (_openError != null && _state != null)
          Align(
            alignment: AlignmentDirectional.centerStart,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
              child: TextButton(
                onPressed: _opening ? null : () => _openSigning(_state!),
                child: const Text('Try opening signing again'),
              ),
            ),
          ),
        Align(
          alignment: AlignmentDirectional.centerStart,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: TextButton(
              onPressed: () => Navigator.pop(context),
              style: TextButton.styleFrom(
                foregroundColor: theme.colorScheme.error,
              ),
              child: const Text('Cancel'),
            ),
          ),
        ),
      ],
    );
  }
}
