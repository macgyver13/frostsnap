import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:frostsnap/animated_check.dart';
import 'package:frostsnap/copy_feedback.dart';
import 'package:frostsnap/global.dart';
import 'package:frostsnap/nostr_chat/contact_book.dart';
import 'package:frostsnap/snackbar.dart';
import 'package:frostsnap/src/rust/api.dart';
import 'package:frostsnap/src/rust/api/device_list.dart';
import 'package:frostsnap/src/rust/api/nostr/contacts.dart';
import 'package:frostsnap/src/rust/api/signing.dart';
import 'package:frostsnap/theme.dart';
import 'package:frostsnap/secure_key_provider.dart';

/// Why [name] cannot be a new contact's name, or null if it can. An empty name has nothing to
/// report yet.
String? contactNameError(String name, Iterable<String> takenNames) {
  final trimmed = name.trim();
  if (trimmed.isEmpty) return null;
  if (trimmed.runes.any((rune) => rune < 0x20 || rune >= 0x7f)) {
    return 'Names can only use plain letters, numbers and symbols';
  }
  final lower = trimmed.toLowerCase();
  if (takenNames.any((taken) => taken.toLowerCase() == lower)) {
    return 'This wallet already has a contact with this name';
  }
  return null;
}

/// Whether a contact belongs in the results for what the user typed.
bool contactMatches(
  String query, {
  required String name,
  required String address,
}) {
  final lower = query.trim().toLowerCase();
  return name.toLowerCase().contains(lower) ||
      address.toLowerCase().contains(lower);
}

/// Whether what the user typed names exactly this contact, so that submitting it can only mean them.
bool contactIsExactly(
  String query, {
  required String name,
  required String address,
}) {
  final lower = query.trim().toLowerCase();
  return name.toLowerCase() == lower || address.toLowerCase() == lower;
}

/// What to tell the user about a failure, without the backtrace Rust errors carry.
String contactErrorMessage(Object error) {
  if (error is! AnyhowException) return '$error';
  return error.message.split('Stack backtrace:').first.trim();
}

String _shortAddress(String address) => address.length <= 24
    ? address
    : '${address.substring(0, 12)}...${address.substring(address.length - 8)}';

/// The contacts matching what is typed in [query], and the way to add one.
class SpContactSuggestions extends StatelessWidget {
  static const maxShown = 4;
  static const minQueryLength = 2;

  final KeyId keyId;
  final TextEditingController query;
  final bool Function(String) isSilentPaymentAddress;
  final void Function(SpContactEntry) onSelected;
  final void Function(String address) onAdd;

  const SpContactSuggestions({
    super.key,
    required this.keyId,
    required this.query,
    required this.isSilentPaymentAddress,
    required this.onSelected,
    required this.onAdd,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListenableBuilder(
      listenable: query,
      builder: (context, _) {
        final text = query.text.trim();
        final matches = text.length < minQueryLength
            ? <SpContactEntry>[]
            : coord
                  .spContacts(keyId: keyId)
                  .where(
                    (contact) => contactMatches(
                      text,
                      name: contact.name(),
                      address: contact.address(),
                    ),
                  )
                  .toList();
        final newAddress = matches.isEmpty && isSilentPaymentAddress(text);
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            for (final contact in matches.take(maxShown))
              ListTile(
                dense: true,
                contentPadding: const EdgeInsets.symmetric(horizontal: 8),
                leading: const Icon(Icons.person_outline),
                title: Text(contact.name()),
                subtitle: Text(
                  _shortAddress(contact.address()),
                  style: monospaceTextStyle,
                ),
                onTap: () => onSelected(contact),
              ),
            if (matches.length > maxShown)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Text(
                  '${matches.length - maxShown} more, keep typing to narrow it down',
                  style: theme.textTheme.bodySmall,
                ),
              ),
            Align(
              alignment: AlignmentDirectional.centerStart,
              child: TextButton.icon(
                onPressed: () => onAdd(newAddress ? text : ''),
                label: Text(newAddress ? 'Add as contact' : 'Add contact'),
                icon: const Icon(Icons.person_add_alt),
              ),
            ),
          ],
        );
      },
    );
  }
}

/// The wallet's contacts: find, add, check and remove them.
///
/// On a wallet coordinated over nostr, [channel] is its shared book: every change goes to the
/// group as a change set, and the page shows the book's check code and the open requests.
class SpContactsPage extends StatefulWidget {
  final AccessStructureRef accessStructureRef;
  final ChannelContacts? channel;

  const SpContactsPage({
    super.key,
    required this.accessStructureRef,
    this.channel,
  });

  @override
  State<SpContactsPage> createState() => _SpContactsPageState();
}

class _SpContactsPageState extends State<SpContactsPage> {
  final _search = TextEditingController();

  KeyId get _keyId => widget.accessStructureRef.keyId;

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _add() async {
    await showAddSpContact(
      context,
      accessStructureRef: widget.accessStructureRef,
    );
    if (mounted) setState(() {});
  }

  Future<void> _open(SpContactEntry contact) async {
    // A change waits while the shared book syncs.
    final syncing = widget.channel?.state.value?.book.syncing ?? true;
    await showBottomSheetOrDialog<void>(
      context,
      title: Text(contact.name()),
      builder: (context, scrollController) => ListView(
        controller: scrollController,
        shrinkWrap: true,
        padding: const EdgeInsets.all(16),
        children: [
          SelectableText(
            spacedHex(contact.address(), groupSize: 4),
            style: monospaceTextStyle,
          ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              if (widget.channel == null)
                TextButton.icon(
                  onPressed: () => _remove(context, contact),
                  style: TextButton.styleFrom(
                    foregroundColor: Theme.of(context).colorScheme.error,
                  ),
                  label: const Text('Remove from this app'),
                  icon: const Icon(Icons.delete_outline),
                )
              else ...[
                TextButton.icon(
                  onPressed: syncing
                      ? null
                      : () => _removeFromBook(context, contact),
                  style: TextButton.styleFrom(
                    foregroundColor: Theme.of(context).colorScheme.error,
                  ),
                  label: const Text('Remove'),
                  icon: const Icon(Icons.delete_outline),
                ),
                TextButton.icon(
                  onPressed: syncing ? null : () => _rename(context, contact),
                  label: const Text('Rename'),
                  icon: const Icon(Icons.edit_outlined),
                ),
              ],
              TextButton.icon(
                onPressed: () => copyToClipboard(contact.address()),
                label: const Text('Copy'),
                icon: const Icon(Icons.copy),
              ),
            ],
          ),
        ],
      ),
    );
    if (mounted) setState(() {});
  }

  Future<void> _remove(BuildContext sheet, SpContactEntry contact) async {
    final name = contact.name();
    final confirmed = await showDialog<bool>(
      context: sheet,
      builder: (context) => AlertDialog(
        title: Text('Remove $name?'),
        content: const Text(
          'Adding this contact back means confirming the address on a threshold of devices again.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await coord.removeSpContact(keyId: _keyId, name: name);
    if (sheet.mounted) Navigator.pop(sheet);
  }

  /// Asks the group to remove [contact] from the shared book.
  Future<void> _removeFromBook(
    BuildContext sheet,
    SpContactEntry contact,
  ) async {
    final name = contact.name();
    final confirmed = await showDialog<bool>(
      context: sheet,
      builder: (context) => AlertDialog(
        title: Text('Remove $name?'),
        content: const Text(
          'This asks the group to remove the contact from every member\'s contacts. '
          'A threshold of devices confirms it.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Ask to remove'),
          ),
        ],
      ),
    );
    if (confirmed != true || !sheet.mounted) return;
    Navigator.pop(sheet);
    await widget.channel!.askGroup(context, [
      ContactChangeView(remove: true, name: name, address: contact.address()),
    ]);
  }

  /// Asks the group to rename [contact]: one change set that removes it and adds its address
  /// under the new name.
  Future<void> _rename(BuildContext sheet, SpContactEntry contact) async {
    final oldName = contact.name();
    final taken = coord
        .spContacts(keyId: _keyId)
        .map((contact) => contact.name())
        .where((name) => name != oldName)
        .toList();
    final newName = await showDialog<String>(
      context: sheet,
      builder: (context) => _RenameDialog(oldName: oldName, takenNames: taken),
    );
    if (newName == null || !sheet.mounted) return;
    Navigator.pop(sheet);
    await widget.channel!.askGroup(context, [
      ContactChangeView(
        remove: true,
        name: oldName,
        address: contact.address(),
      ),
      ContactChangeView(
        remove: false,
        name: newName,
        address: contact.address(),
      ),
    ]);
  }

  /// Asks the group to add a contact to the shared book.
  Future<void> _addToBook() async {
    final added = await showDialog<ContactChangeView>(
      context: context,
      builder: (context) => _AddToBookDialog(
        takenNames: coord.spContacts(keyId: _keyId).map((c) => c.name()),
      ),
    );
    if (added == null || !mounted) return;
    await widget.channel!.askGroup(context, [added]);
  }

  @override
  Widget build(BuildContext context) {
    final channel = widget.channel;
    if (channel != null) {
      return ValueListenableBuilder(
        valueListenable: channel.state,
        builder: (context, state, _) => _buildBook(channel, state),
      );
    }
    final contacts = coord.spContacts(keyId: _keyId);
    return Scaffold(
      appBar: AppBar(title: const Text('Contacts')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _add,
        label: const Text('Add contact'),
        icon: const Icon(Icons.person_add_alt),
      ),
      body: contacts.isEmpty
          ? const Center(
              child: Padding(
                padding: EdgeInsets.all(32),
                child: Text(
                  'Silent payments go to contacts your devices have confirmed. '
                  'Add one to send a silent payment.',
                  textAlign: TextAlign.center,
                ),
              ),
            )
          : Column(
              children: [
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: TextField(
                    controller: _search,
                    onChanged: (_) => setState(() {}),
                    decoration: const InputDecoration(
                      hintText: 'Search name or address',
                      prefixIcon: Icon(Icons.search),
                    ),
                  ),
                ),
                Expanded(child: _results(contacts)),
              ],
            ),
    );
  }

  Widget _results(List<SpContactEntry> contacts) {
    final matches = contacts
        .where(
          (contact) => contactMatches(
            _search.text,
            name: contact.name(),
            address: contact.address(),
          ),
        )
        .toList();
    if (matches.isEmpty) {
      return const Center(child: Text('No matching contacts'));
    }
    return ListView.builder(
      itemCount: matches.length,
      itemBuilder: (context, index) => _contactTile(matches[index]),
    );
  }

  Widget _contactTile(SpContactEntry contact) => ListTile(
    leading: const Icon(Icons.person_outline),
    title: Text(contact.name()),
    subtitle: Text(_shortAddress(contact.address()), style: monospaceTextStyle),
    onTap: () => _open(contact),
  );

  /// The shared book of a wallet coordinated over nostr.
  Widget _buildBook(ChannelContacts channel, ContactsState? state) {
    final theme = Theme.of(context);
    final book = state?.book;
    final syncing = book?.syncing ?? true;
    final contacts = book?.contacts ?? coord.spContacts(keyId: _keyId);
    final open = (state?.ceremonies ?? const <ContactCeremonyView>[]).where(
      (ceremony) =>
          ceremony.status is! CeremonyStatus_Published &&
          ceremony.status is! CeremonyStatus_Dropped,
    );
    final matches = contacts
        .where(
          (contact) => contactMatches(
            _search.text,
            name: contact.name(),
            address: contact.address(),
          ),
        )
        .toList();
    return Scaffold(
      appBar: AppBar(title: const Text('Contacts')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: syncing ? null : _addToBook,
        label: const Text('Add contact'),
        icon: const Icon(Icons.person_add_alt),
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 96),
        children: [
          ListTile(
            title: const Text('Contacts check code'),
            subtitle: Text(
              book?.head.checkCode() ?? '',
              style: monospaceTextStyle,
            ),
            trailing: syncing
                ? const Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      SizedBox.square(
                        dimension: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                      SizedBox(width: 8),
                      Text('Syncing'),
                    ],
                  )
                : null,
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text(
              'Every member of the group shares these contacts. Compare this code with another '
              'member\'s to check you have the same ones. Changes wait while contacts sync.',
              style: theme.textTheme.bodySmall,
            ),
          ),
          for (final ceremony in open)
            Card(
              margin: const EdgeInsets.all(16),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: ContactCeremonyCard(
                  contacts: channel,
                  ceremony: ceremony,
                ),
              ),
            ),
          for (final dropped
              in book?.dropped ?? const <List<ContactChangeView>>[])
            Card(
              margin: const EdgeInsets.all(16),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text('Dropped changes', style: theme.textTheme.titleSmall),
                    const Text(
                      'These changes were confirmed, but another change to the contacts landed '
                      'first, so they were not applied.',
                    ),
                    for (final change in dropped)
                      ContactChangeTile(change: change),
                    if (_askedFor(state!, dropped) &&
                        !channel.askedAgain(dropped))
                      Align(
                        alignment: AlignmentDirectional.centerStart,
                        child: TextButton(
                          onPressed: syncing
                              ? null
                              : () => channel.askGroup(context, dropped),
                          child: const Text('Ask again'),
                        ),
                      ),
                  ],
                ),
              ),
            ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: TextField(
              controller: _search,
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                hintText: 'Search name or address',
                prefixIcon: Icon(Icons.search),
              ),
            ),
          ),
          if (contacts.isEmpty)
            const Padding(
              padding: EdgeInsets.all(32),
              child: Text(
                'Silent payments go to contacts your devices have confirmed. '
                'Add one to send a silent payment.',
                textAlign: TextAlign.center,
              ),
            )
          else if (matches.isEmpty)
            const Center(child: Text('No matching contacts'))
          else
            for (final contact in matches) _contactTile(contact),
        ],
      ),
    );
  }

  /// Whether this member asked for [changes].
  bool _askedFor(ContactsState state, List<ContactChangeView> changes) =>
      state.ceremonies.any(
        (ceremony) => ceremony.mine && listEquals(ceremony.changes, changes),
      );
}

/// Asks for a contact's new name.
class _RenameDialog extends StatefulWidget {
  final String oldName;
  final List<String> takenNames;

  const _RenameDialog({required this.oldName, required this.takenNames});

  @override
  State<_RenameDialog> createState() => _RenameDialogState();
}

class _RenameDialogState extends State<_RenameDialog> {
  late final _name = TextEditingController(text: widget.oldName);

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final name = _name.text.trim();
    final error = contactNameError(name, widget.takenNames);
    return AlertDialog(
      title: Text('Rename ${widget.oldName}'),
      content: TextField(
        controller: _name,
        maxLength: 20,
        autofocus: true,
        onChanged: (_) => setState(() {}),
        decoration: InputDecoration(labelText: 'New name', errorText: error),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        TextButton(
          onPressed: error != null || name.isEmpty || name == widget.oldName
              ? null
              : () => Navigator.pop(context, name),
          child: const Text('Ask to rename'),
        ),
      ],
    );
  }
}

/// Asks for a new contact's name and address.
class _AddToBookDialog extends StatefulWidget {
  final Iterable<String> takenNames;

  const _AddToBookDialog({required this.takenNames});

  @override
  State<_AddToBookDialog> createState() => _AddToBookDialogState();
}

class _AddToBookDialogState extends State<_AddToBookDialog> {
  final _name = TextEditingController();
  final _address = TextEditingController();

  @override
  void dispose() {
    _name.dispose();
    _address.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final name = _name.text.trim();
    final address = _address.text.trim().toLowerCase();
    final nameError = contactNameError(name, widget.takenNames);
    return AlertDialog(
      title: const Text('Add contact'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: _name,
            maxLength: 20,
            autofocus: true,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              labelText: 'Name',
              errorText: nameError,
            ),
          ),
          TextField(
            controller: _address,
            minLines: 2,
            maxLines: 5,
            onChanged: (_) => setState(() {}),
            decoration: const InputDecoration(
              labelText: 'Silent payment address',
            ),
            style: monospaceTextStyle,
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        TextButton(
          onPressed: nameError != null || name.isEmpty || address.isEmpty
              ? null
              : () => Navigator.pop(
                  context,
                  ContactChangeView(
                    remove: false,
                    name: name,
                    address: address,
                  ),
                ),
          child: const Text('Ask the group'),
        ),
      ],
    );
  }
}

/// Asks for a contact's name and address, then has a threshold of devices confirm and sign it.
/// The name of the contact, if one was added.
Future<String?> showAddSpContact(
  BuildContext context, {
  required AccessStructureRef accessStructureRef,
  String address = '',
}) async {
  final encryptionKey = await SecureKeyProvider.getEncryptionKey();
  if (!context.mounted) return null;
  return showBottomSheetOrDialog<String>(
    context,
    title: const Text('Add contact'),
    builder: (context, scrollController) => _AddSpContact(
      accessStructureRef: accessStructureRef,
      encryptionKey: encryptionKey,
      address: address,
      scrollController: scrollController,
    ),
  );
}

class _AddSpContact extends StatefulWidget {
  final AccessStructureRef accessStructureRef;
  final SymmetricKey encryptionKey;
  final String address;
  final ScrollController scrollController;

  const _AddSpContact({
    required this.accessStructureRef,
    required this.encryptionKey,
    required this.address,
    required this.scrollController,
  });

  @override
  State<_AddSpContact> createState() => _AddSpContactState();
}

class _AddSpContactState extends State<_AddSpContact> {
  final _name = TextEditingController();
  late final _address = TextEditingController(text: widget.address);
  StreamSubscription<SpContactState>? _ecdhSub;
  StreamSubscription<SigningState>? _signSub;
  StreamSubscription<DeviceListUpdate>? _devicesSub;
  SpContactState? _state;
  final Set<DeviceId> _connected = {};

  /// Set once the devices that answered have been asked to sign.
  SignSessionId? _signSession;
  SigningSessionHandle? _signHandle;
  bool _opening = false;
  bool _finished = false;
  String? _error;
  String _submittedAddress = '';

  late final _accessStructure = coord.getAccessStructure(
    asRef: widget.accessStructureRef,
  )!;
  late final _threshold = _accessStructure.threshold();
  late final _devices = _accessStructure.devices();

  @override
  void initState() {
    super.initState();
    _name.addListener(_onFormChanged);
    _address.addListener(_onFormChanged);
    _devicesSub = GlobalStreams.deviceListSubject.listen((update) {
      _connected
        ..clear()
        ..addAll(update.state.devices.map((device) => device.id));
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _devicesSub?.cancel();
    _ecdhSub?.cancel();
    _signSub?.cancel();
    _name.dispose();
    _address.dispose();
    if (!_finished) _cancel();
    super.dispose();
  }

  // The controllers also notify on selection changes, which should not clear the error.
  void _onFormChanged() {
    if (_address.text != _submittedAddress) _error = null;
    if (mounted) setState(() {});
  }

  /// Takes the devices off the prompt and drops whatever was collected.
  void _cancel() {
    if (_state == null && _signSession == null) return;
    coord.cancelProtocol();
    final sessionId = _state?.sessionId;
    if (sessionId != null) coord.cancelSpContact(sessionId: sessionId);
    _signHandle?.cancel();
    final signSession = _signSession;
    if (signSession != null) coord.cancelSignSession(ssid: signSession);
  }

  void _start() {
    _submittedAddress = _address.text;
    setState(() => _error = null);
    _ecdhSub = coord
        .startSpContact(
          accessStructureRef: widget.accessStructureRef,
          name: _name.text.trim(),
          address: _address.text,
          devices: _devices,
          encryptionKey: widget.encryptionKey,
        )
        .listen(_onState, onError: _onError);
  }

  void _onError(Object error) {
    if (!mounted) return;
    _ecdhSub?.cancel();
    setState(() {
      _ecdhSub = null;
      _state = null;
      _error = contactErrorMessage(error);
    });
  }

  void _onState(SpContactState state) {
    if (!mounted || _signSession != null || _opening) return;
    setState(() => _state = state);
    for (final deviceId in state.connectedButNeedRequest) {
      try {
        coord.requestSpContactEcdh(
          sessionId: state.sessionId,
          deviceId: deviceId,
          encryptionKey: widget.encryptionKey,
        );
      } catch (e) {
        debugPrint('contact ECDH request failed: $e');
      }
    }
    if (state.confirmed.length >= _threshold) _sign(state);
  }

  /// A threshold have confirmed, so the devices sign without another hold.
  Future<void> _sign(SpContactState state) async {
    setState(() => _opening = true);
    try {
      final signSession = await coord.startSpContactSign(
        sessionId: state.sessionId,
      );
      if (!mounted) {
        await coord.cancelSignSession(ssid: signSession);
        return;
      }
      final handle = await coord.tryRestoreSigningSession(
        sessionId: signSession,
      );
      if (!mounted) {
        await handle.cancel();
        await coord.cancelSignSession(ssid: signSession);
        return;
      }
      setState(() {
        _signSession = signSession;
        _signHandle = handle;
      });
      _signSub = handle.subState().watch().listen(
        _onSigning,
        onError: _onError,
      );
    } catch (e) {
      if (!mounted) return;
      showErrorSnackbar(
        context,
        'Could not add the contact: ${contactErrorMessage(e)}',
      );
      Navigator.pop(context);
    } finally {
      _opening = false;
    }
  }

  Future<void> _onSigning(SigningState state) async {
    if (!mounted) return;
    final signSession = _signSession!;
    if (state.finishedSignatures != null) {
      await coord.finishSpContact(sessionId: signSession);
      _finished = true;
      if (mounted) Navigator.pop(context, _name.text.trim());
      return;
    }
    for (final deviceId in state.connectedButNeedRequest) {
      _signHandle?.requestDeviceSign(
        deviceId: deviceId,
        encryptionKey: widget.encryptionKey,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final started = _ecdhSub != null;
    final confirmed = _state?.confirmed ?? const [];
    final existing = coord.spContacts(keyId: widget.accessStructureRef.keyId);
    final nameError = contactNameError(
      _name.text,
      existing.map((contact) => contact.name()),
    );
    final address = _address.text.trim().toLowerCase();
    final savedAs = existing
        .where((contact) => contact.address() == address)
        .firstOrNull
        ?.name();
    return ListView(
      controller: widget.scrollController,
      shrinkWrap: true,
      padding: const EdgeInsets.all(16),
      children: [
        if (!started) ...[
          TextField(
            controller: _name,
            maxLength: 20,
            decoration: InputDecoration(
              labelText: 'Name',
              errorText: nameError,
            ),
          ),
          TextField(
            controller: _address,
            minLines: 2,
            maxLines: 5,
            decoration: InputDecoration(
              labelText: 'Silent payment address',
              errorMaxLines: 3,
              helperText: savedAs == null ? null : 'Already saved as $savedAs',
            ),
            style: monospaceTextStyle,
          ),
          if (_error case final error?)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                error,
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ),
          const SizedBox(height: 16),
          FilledButton(
            onPressed:
                nameError != null ||
                    _name.text.trim().isEmpty ||
                    address.isEmpty
                ? null
                : _start,
            child: const Text('Confirm on devices'),
          ),
        ] else ...[
          Text(
            'Check the full address on each device against what the recipient gave you, '
            'then hold to trust it. Later sends to ${_name.text.trim()} rely on this check.',
            style: theme.textTheme.bodyMedium,
          ),
          ListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Devices'),
            subtitle: const Text('Connect a device to confirm'),
            trailing: Text('${confirmed.length}/$_threshold'),
          ),
          for (final deviceId in _devices)
            ListTile(
              contentPadding: EdgeInsets.zero,
              enabled: _connected.contains(deviceId),
              title: Text(coord.getDeviceName(id: deviceId) ?? '<no-name>'),
              trailing: confirmed.contains(deviceId)
                  ? const AnimatedCheckCircle()
                  : Text(
                      _connected.contains(deviceId) ? 'Waiting to confirm' : '',
                      style: TextStyle(color: theme.colorScheme.primary),
                    ),
            ),
          Align(
            alignment: AlignmentDirectional.centerStart,
            child: TextButton(
              onPressed: () => Navigator.pop(context),
              style: TextButton.styleFrom(
                foregroundColor: theme.colorScheme.error,
              ),
              child: const Text('Cancel'),
            ),
          ),
        ],
      ],
    );
  }
}
