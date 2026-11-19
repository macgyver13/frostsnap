import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:frostsnap/device_selector.dart';
import 'package:frostsnap/global.dart';
import 'package:frostsnap/nostr_chat/nostr_profile.dart';
import 'package:frostsnap/nostr_chat/nostr_state.dart';
import 'package:frostsnap/secure_key_provider.dart';
import 'package:frostsnap/snackbar.dart';
import 'package:frostsnap/src/rust/api.dart';
import 'package:frostsnap/src/rust/api/nostr.dart';
import 'package:frostsnap/src/rust/api/nostr/contacts.dart';
import 'package:frostsnap/theme.dart';
import 'package:frostsnap/wallet_contacts.dart';

/// A wallet's shared contact book on its nostr channel: the channel, and the book and change set
/// ceremonies as last reported. The channel takes one subscriber, so the chat page makes this
/// once and hands it to every page that shows contacts.
class ChannelContacts {
  final ChannelHandle handle;
  final AccessStructureRef accessStructureRef;
  final ValueNotifier<ContactsState?> state = ValueNotifier(null);
  late final StreamSubscription<ContactsState> _sub;

  ChannelContacts(this.handle, this.accessStructureRef) {
    _sub = handle.subContacts().listen(
      (update) => state.value = update,
      // A wallet that is not a bitcoin wallet has no book.
      onError: (Object e) => debugPrint('no contact book: $e'),
    );
  }

  void dispose() {
    _sub.cancel();
    state.dispose();
  }

  ContactCeremonyView? ceremony(EventId requestId) => state.value?.ceremonies
      .where((ceremony) => ceremony.requestId == requestId)
      .firstOrNull;

  /// Asks the group to confirm [changes], then shows the ceremony until it is published or
  /// dropped, or the user closes it. Whether it was published.
  Future<bool> askGroup(
    BuildContext context,
    List<ContactChangeView> changes,
  ) async {
    final EventId requestId;
    try {
      requestId = await handle.startContactChanges(changes: changes);
    } catch (e) {
      if (context.mounted) {
        showErrorSnackbar(context, contactErrorMessage(e));
      }
      return false;
    }
    if (!context.mounted) return false;
    await showContactCeremony(context, this, requestId);
    return ceremony(requestId)?.status is CeremonyStatus_Published;
  }

  /// Whether another ceremony of this member's with the same changes is open or published, so
  /// they need not be asked for again.
  bool askedAgain(List<ContactChangeView> changes, {EventId? except}) =>
      state.value?.ceremonies.any(
        (ceremony) =>
            ceremony.mine &&
            ceremony.requestId != except &&
            ceremony.status is! CeremonyStatus_Dropped &&
            listEquals(ceremony.changes, changes),
      ) ??
      false;
}

/// The ceremony [requestId] in a sheet, closed once it is published.
Future<void> showContactCeremony(
  BuildContext context,
  ChannelContacts contacts,
  EventId requestId,
) {
  // The book keeps changing while the sheet closes, so it closes once.
  var closing = false;
  return showBottomSheetOrDialog<void>(
    context,
    title: const Text('Contact changes'),
    builder: (context, scrollController) => ValueListenableBuilder(
      valueListenable: contacts.state,
      builder: (context, _, _) {
        final ceremony = contacts.ceremony(requestId);
        if (ceremony?.status is CeremonyStatus_Published && !closing) {
          closing = true;
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (context.mounted) Navigator.pop(context);
          });
        }
        return ListView(
          controller: scrollController,
          shrinkWrap: true,
          padding: const EdgeInsets.all(16),
          children: [
            if (ceremony == null)
              const Text('Waiting for the request to reach the group...')
            else
              ContactCeremonyCard(contacts: contacts, ceremony: ceremony),
          ],
        );
      },
    ),
  );
}

/// One line per change: what it does, the name, and the start and end of the address.
class ContactChangeTile extends StatelessWidget {
  final ContactChangeView change;

  const ContactChangeTile({super.key, required this.change});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      leading: Icon(
        change.remove ? Icons.person_remove_outlined : Icons.person_add_alt,
      ),
      title: Text('${change.remove ? 'Remove' : 'Add'} ${change.name}'),
      subtitle: SelectableText(
        spacedHex(change.address, groupSize: 4),
        style: monospaceTextStyle,
      ),
    );
  }
}

/// What a ceremony is waiting for, in a sentence.
String ceremonyStatusText(
  ContactCeremonyView ceremony,
) => switch (ceremony.status) {
  CeremonyStatus_Syncing() =>
    'Waiting for contacts to sync before it can be confirmed.',
  CeremonyStatus_WaitingForConfirmations(:final offers, :final threshold) =>
    'Confirmed on $offers of $threshold devices.',
  CeremonyStatus_BlockedByOpenRequest() =>
    'Another contact change from the same book is still open. This one waits until it '
        'lands or is cancelled.',
  CeremonyStatus_Confirmed() =>
    ceremony.mine
        ? 'Confirmed. Waiting for the devices to sign. If it stays here, a member whose '
              'device confirmed may have restarted their app: cancel and ask again.'
        : 'Confirmed. Waiting for the devices to sign.',
  CeremonyStatus_PendingDeviceRestart() =>
    'Your device forgot its approval before it signed. Confirm on it again.',
  CeremonyStatus_Published() =>
    'Done. Every member\'s contacts have these changes.',
  CeremonyStatus_Dropped() =>
    'Dropped. It was cancelled, or another change to the contacts landed first.',
};

/// A change set ceremony: its changes, who has confirmed, its status, and what this member can
/// do about it.
class ContactCeremonyCard extends StatefulWidget {
  final ChannelContacts contacts;
  final ContactCeremonyView ceremony;

  const ContactCeremonyCard({
    super.key,
    required this.contacts,
    required this.ceremony,
  });

  @override
  State<ContactCeremonyCard> createState() => _ContactCeremonyCardState();
}

class _ContactCeremonyCardState extends State<ContactCeremonyCard> {
  /// The device this card asked to confirm, until this member's offer arrives.
  DeviceId? _asked;
  bool _busy = false;

  ContactCeremonyView get _ceremony => widget.ceremony;

  Future<void> _confirm(DeviceId deviceId) async {
    final encryptionKey = await SecureKeyProvider.getEncryptionKey();
    try {
      await widget.contacts.handle.confirmContactChanges(
        requestId: _ceremony.requestId,
        deviceId: deviceId,
        encryptionKey: encryptionKey,
      );
      if (mounted) setState(() => _asked = deviceId);
    } catch (e) {
      if (mounted) showErrorSnackbar(context, contactErrorMessage(e));
    }
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
    } catch (e) {
      if (mounted) showErrorSnackbar(context, contactErrorMessage(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _cancel() => _run(
    () => widget.contacts.handle.cancelContactChanges(
      requestId: _ceremony.requestId,
    ),
  );

  /// Withdraws this request, if it is still open, and asks for the same changes from the book
  /// as it is now.
  Future<void> _askAgain() => _run(() async {
    if (_ceremony.status is! CeremonyStatus_Dropped) {
      await widget.contacts.handle.cancelContactChanges(
        requestId: _ceremony.requestId,
      );
    }
    if (!mounted) return;
    await widget.contacts.askGroup(context, _ceremony.changes);
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final nostr = NostrContext.of(context);
    final me = nostr.myPubkey;
    final status = _ceremony.status;
    final iOffered = _ceremony.offeredBy.contains(me);
    final open =
        status is! CeremonyStatus_Published &&
        status is! CeremonyStatus_Dropped;
    final canConfirm =
        (status is CeremonyStatus_WaitingForConfirmations && !iOffered) ||
        status is CeremonyStatus_PendingDeviceRestart;
    final accessStructure = coord.getAccessStructure(
      asRef: widget.contacts.accessStructureRef,
    );
    final devices = canConfirm && accessStructure != null
        ? DeviceItem.fromAccessStructure(
            accessStructure,
          ).where((device) => device.enabled).toList()
        : <DeviceItem>[];
    final asked = _asked;
    final author = _ceremony.mine
        ? 'You asked'
        : '${getDisplayName(nostr.getProfile(_ceremony.author), _ceremony.author)} asked';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(
          '$author for ${_ceremony.changes.length} '
          '${_ceremony.changes.length == 1 ? 'change' : 'changes'}',
          style: theme.textTheme.titleSmall,
        ),
        for (final change in _ceremony.changes)
          ContactChangeTile(change: change),
        const SizedBox(height: 8),
        Text(ceremonyStatusText(_ceremony)),
        if (_ceremony.offeredBy.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text(
              'Confirmed by ${_ceremony.offeredBy.map((member) => member == me ? 'you' : getDisplayName(nostr.getProfile(member), member)).join(', ')}',
              style: theme.textTheme.bodySmall,
            ),
          ),
        if (_ceremony.error case final error?)
          Padding(
            padding: const EdgeInsets.only(top: 4),
            child: Text(
              'Your device: $error',
              style: TextStyle(color: theme.colorScheme.error),
            ),
          ),
        if (canConfirm) ...[
          const SizedBox(height: 12),
          Text(
            'Check each name and address against your own records, not only against this '
            'screen, before you confirm. Your device shows every change, and one hold accepts '
            'them all.',
            style: theme.textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          if (asked != null && status is! CeremonyStatus_PendingDeviceRestart)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                'Check and hold to confirm on ${coord.getDeviceName(id: asked) ?? 'your device'}. '
                'Plug it in if it is not connected.',
                style: TextStyle(color: theme.colorScheme.primary),
              ),
            ),
          if (devices.isEmpty)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'None of your devices in this wallet can confirm now.',
              ),
            ),
          for (final device in devices)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: OutlinedButton(
                onPressed: () => _confirm(device.id),
                child: Text('Confirm on ${device.name}'),
              ),
            ),
        ],
        if (_ceremony.mine)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: Wrap(
              spacing: 8,
              children: [
                if (open)
                  TextButton(
                    onPressed: _busy ? null : _cancel,
                    style: TextButton.styleFrom(
                      foregroundColor: theme.colorScheme.error,
                    ),
                    child: const Text('Cancel'),
                  ),
                if (status is CeremonyStatus_Confirmed ||
                    status is CeremonyStatus_PendingDeviceRestart ||
                    (status is CeremonyStatus_Dropped &&
                        !widget.contacts.askedAgain(
                          _ceremony.changes,
                          except: _ceremony.requestId,
                        )))
                  TextButton(
                    onPressed: _busy ? null : _askAgain,
                    child: Text(
                      status is CeremonyStatus_Dropped
                          ? 'Ask again'
                          : 'Cancel and ask again',
                    ),
                  ),
              ],
            ),
          ),
      ],
    );
  }
}

/// Why a sign request can't be offered on yet, as far as contacts go, or null if it can.
String? signGateText(SignGate? gate) => switch (gate) {
  null => 'Checking contacts...',
  SignGate_Allowed() => null,
  SignGate_WaitingForSync() =>
    'Waiting for contacts to sync. You can offer once your contacts match the requester\'s.',
  SignGate_RequesterBehind() =>
    'The requester\'s contacts are out of date. They need to sync and ask again.',
  SignGate_NotInBook(:final name) =>
    'This send pays $name, who is not in this wallet\'s contacts, so it can\'t be signed.',
  SignGate_MissingHead() =>
    'This send pays a contact but doesn\'t say which contacts it was built from, so it '
        'can\'t be signed.',
};
