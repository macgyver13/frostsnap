import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';

import 'package:frostsnap/camera/camera.dart';
import 'package:frostsnap/wallet_contacts.dart';
import 'package:frostsnap/contexts.dart';
import 'package:frostsnap/device_selector.dart';
import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:frostsnap/global.dart';
import 'package:frostsnap/maybe_fullscreen_dialog.dart';
import 'package:frostsnap/nostr_chat/contact_book.dart';
import 'package:frostsnap/snackbar.dart';
import 'package:frostsnap/src/rust/api.dart';
import 'package:frostsnap/src/rust/api/nostr.dart';
import 'package:frostsnap/src/rust/api/nostr/contacts.dart';
import 'package:frostsnap/src/rust/api/signing.dart';
import 'package:frostsnap/src/rust/api/super_wallet.dart';
import 'package:frostsnap/src/rust/api/transaction.dart';
import 'package:frostsnap/theme.dart';
import 'package:frostsnap/wallet.dart';
import 'package:frostsnap/wallet_send_controllers.dart';
import 'package:frostsnap/wallet_send_feerate_picker.dart';
import 'package:frostsnap/wallet_tx_details.dart';

enum SendPageIndex { recipient, amount, signers }

class WalletSendPage extends StatefulWidget {
  final SuperWallet superWallet;
  final MasterAppkey masterAppkey;
  final double initialFeerate;
  final ScrollController? scrollController;
  final void Function(UnsignedTx, List<DeviceId>)? onTxReady;
  final bool remoteSigning;

  /// The wallet's shared contact book, on a wallet coordinated over nostr. An imported file may
  /// then name new contacts, which the group adds before the send.
  final ChannelContacts? contacts;
  const WalletSendPage({
    super.key,
    required this.superWallet,
    required this.masterAppkey,
    this.initialFeerate = 3.0,
    this.scrollController,
    this.onTxReady,
    this.remoteSigning = false,
    this.contacts,
  });

  BuildTxState buildTx() {
    final state = superWallet.buildTx(coord: coord, masterAppkey: masterAppkey);
    // This can only fail if the wallet does not have a frost key - in which case, we shouldn't even
    // be sending from this wallet!
    return state!;
  }

  @override
  State<WalletSendPage> createState() => _WalletSendPageState();
}

class _WalletSendPageState extends State<WalletSendPage> {
  static const sectionPadding = EdgeInsets.fromLTRB(16.0, 0.0, 16.0, 8.0);

  late final StreamSubscription<void> _sub;

  late final ScrollController scrollController;
  late final BuildTxState state;

  late final AddressInputController addrController;
  String? addrError;

  late final AmountInputController amountController;

  var pageIndex = SendPageIndex.recipient;
  bool estimateRunning = false;
  List<RecipientLine>? importedRecipients;
  // The transaction the imported recipients review shows. Building one shuffles its outputs, so it
  // is built once per feerate and Send signs this same one, keeping the order on screen equal to
  // what the device shows.
  UnsignedTx? _importedTx;
  double? _importedTxFeerate;

  @override
  void initState() {
    super.initState();

    scrollController = widget.scrollController ?? ScrollController();

    state = widget.buildTx();

    // We only support one access structure for now.
    state.setAccessId(
      accessId: state.accessStructures().first.accessStructureId(),
    );
    if (widget.remoteSigning) {
      for (final (id, _) in state.availableSigners()) {
        state.selectSigner(dId: id);
      }
    }
    if (state.confirmationEstimates() == null)
      state.refreshConfirmationEstimates();

    _sub = state.subscribe().watch().listen(
      (_) => mounted ? setState(() {}) : null,
    );

    addrController = AddressInputController(state);
    amountController = AmountInputController(state: state);
  }

  /// The contact being paid. Replaces the recipient field until it is cleared.
  SpContactEntry? get selectedContact => state.recipient(recipient: 0)?.contact;

  AccessStructureRef get _contactsRef => WalletContext.of(
    context,
  )!.wallet.frostKey()!.accessStructures()[0].accessStructureRef();

  @override
  void dispose() {
    amountController.dispose();
    addrController.dispose();
    _sub.cancel();
    state.dispose();
    if (widget.scrollController == null) scrollController.dispose();
    super.dispose();
  }

  bool alreadyRefreshed = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (!mounted) return;
    if (state.confirmationEstimates() == null) {
      try {
        state.refreshConfirmationEstimates();
      } catch (e, _) {
        // Ignore in production, log in debug.
        assert(() {
          print('Ignored exception: $e');
          return true;
        }());
      }
    }
  }

  Widget _buildCompletedAmountAndFee(BuildContext context) {
    final theme = Theme.of(context);

    final isSendMax = state.isSendMax(recipient: 0);

    int? amount;
    try {
      amount = state.amount(recipient: 0);
    } on AmountError catch (e) {
      assert(() {
        print('Must have valid amount at this point: $e');
        return true;
      }());
      prevPageOrPop(null);
    }

    Widget leadingCard(String data) {
      return Card(
        color: theme.colorScheme.secondaryContainer,
        child: Padding(
          padding: EdgeInsets.symmetric(vertical: 2.0, horizontal: 6.0),
          child: Text(
            data,
            style: theme.textTheme.labelSmall?.copyWith(
              color: theme.colorScheme.onSecondaryContainer,
            ),
          ),
        ),
      );
    }

    return Column(
      children: [
        ListTile(
          onTap: () => setState(() => pageIndex = SendPageIndex.amount),
          leading: Row(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            spacing: 4.0,
            children: [
              completedCardLabel(context, 'Amount'),
              if (isSendMax) Flexible(child: leadingCard('Max')),
            ],
          ),
          title: SatoshiText(value: amount),
        ),
        ListTile(
          onTap: () => showFeeRateDialog(context),
          leading: Row(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            spacing: 4.0,
            children: [
              completedCardLabel(context, 'Fee'),
              Flexible(
                child: leadingCard(
                  '${state.feerate()?.toStringAsFixed(1) ?? '~'} sat/vB',
                ),
              ),
            ],
          ),
          title: SatoshiText(
            value: state.fee(),
            style: TextStyle(color: theme.colorScheme.secondary),
          ),
        ),
      ],
    );
  }

  Widget _buildCompletedList(BuildContext context) {
    if (importedRecipients != null) {
      return _buildImportedRecipientsReview(context);
    }
    // TODO: We only support one recipient right now!
    final recipient = state.recipient(recipient: 0);

    return AnimatedSize(
      duration: Durations.short4,
      curve: Curves.easeInOutCubicEmphasized,
      alignment: Alignment.topCenter,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (pageIndex.index > SendPageIndex.recipient.index)
            ListTile(
              onTap: () => setState(() => pageIndex = SendPageIndex.recipient),
              leading: completedCardLabel(context, 'Recipient'),
              title: Text(
                // addressModel.formattedAddress,
                spacedHex(
                  recipient?.contact?.address() ??
                      recipient?.address?.toString() ??
                      '',
                  groupSize: 4,
                ),
                textWidthBasis: TextWidthBasis.longestLine,
                textAlign: TextAlign.right,
                style: monospaceTextStyle,
              ),
              subtitle: switch (recipient?.contact) {
                null => null,
                final contact => Padding(
                  padding: const EdgeInsets.only(top: 4.0),
                  child: Text(
                    'Silent payment to ${contact.name()}',
                    textAlign: TextAlign.right,
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              },
            ),
          if (pageIndex.index > SendPageIndex.amount.index)
            _buildCompletedAmountAndFee(context),
          if (pageIndex.index > SendPageIndex.recipient.index)
            SizedBox(height: 24.0),
        ],
      ),
    );
  }

  UnsignedTx? _importedUnsignedTx() {
    final feerate = state.feerate();
    if (_importedTx == null || _importedTxFeerate != feerate) {
      try {
        _importedTx = state.tryFinish();
      } catch (_) {
        _importedTx = null;
      }
      _importedTxFeerate = feerate;
    }
    return _importedTx;
  }

  void _clearImportedTx() {
    _importedTx = null;
    _importedTxFeerate = null;
  }

  Widget _buildImportedRecipientsReview(BuildContext context) {
    final theme = Theme.of(context);
    final recipients = importedRecipients!;
    final totalSats = recipients.fold<int>(
      0,
      (sum, r) => sum + r.amountSat.toInt(),
    );

    final unsignedTx = _importedUnsignedTx();
    final signTask = unsignedTx == null
        ? null
        : wireSignTaskBitcoinTransaction(unsignedTx: unsignedTx);

    // Rows follow the transaction's output order, numbered as the device numbers them, each with
    // the file line it came from so it can be checked against the file. If the transaction cannot
    // be built, or its outputs do not pair up with the file, they follow the file unnumbered.
    List<({int? number, RecipientLine line})> rows = [
      for (final r in recipients) (number: null, line: r),
    ];
    if (signTask != null) {
      final remaining = List.of(recipients);
      final ordered = <({int? number, RecipientLine line})>[];
      final outputs = sendRecipients(
        signTask: signTask,
        network: widget.superWallet.network,
      );
      for (final (i, output) in outputs.indexed) {
        final match = remaining.indexWhere(
          (r) =>
              r.amountSat.toInt() == output.amountSat.toInt() &&
              r.address.toLowerCase() == output.address.toLowerCase(),
        );
        if (match == -1) break;
        ordered.add((number: i + 1, line: remaining.removeAt(match)));
      }
      if (remaining.isEmpty && ordered.length == outputs.length) {
        rows = ordered;
      }
    }

    return Padding(
      padding: sectionPadding,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'Recipients (${recipients.length})',
                style: theme.textTheme.titleMedium,
              ),
              TextButton(
                onPressed: () {
                  state.clearRecipients();
                  setState(() {
                    importedRecipients = null;
                    _clearImportedTx();
                    pageIndex = SendPageIndex.recipient;
                  });
                },
                child: const Text('Change'),
              ),
            ],
          ),
          const SizedBox(height: 8.0),
          Card.outlined(
            color: theme.colorScheme.surfaceContainerHigh,
            shape: cardShape(context),
            margin: EdgeInsets.zero,
            child: ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: rows.length,
              separatorBuilder: (context, index) => const Divider(height: 1),
              itemBuilder: (context, index) {
                final (:number, line: r) = rows[index];
                // A contact's line goes by the contact's name. The line's own contact was moved
                // into the builder by setRecipients, so read it back from there (same file order).
                final name =
                    state
                        .recipient(
                          recipient: recipients.indexWhere(
                            (l) => l.line == r.line,
                          ),
                        )
                        ?.contact
                        ?.name() ??
                    r.label;
                return Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 16.0,
                    vertical: 12.0,
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Expanded(
                            child: Row(
                              children: [
                                if (number != null) ...[
                                  Text(
                                    '#$number',
                                    style: theme.textTheme.bodyMedium?.copyWith(
                                      fontWeight: FontWeight.bold,
                                      color: theme.colorScheme.primary,
                                    ),
                                  ),
                                  const SizedBox(width: 8.0),
                                ],
                                if (name != null && name.isNotEmpty)
                                  Flexible(
                                    child: Text(
                                      name,
                                      style: theme.textTheme.bodyMedium
                                          ?.copyWith(
                                            fontWeight: FontWeight.bold,
                                          ),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                if (r.isSilentPayment) ...[
                                  if (name != null && name.isNotEmpty)
                                    const SizedBox(width: 8.0),
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 6.0,
                                      vertical: 2.0,
                                    ),
                                    decoration: BoxDecoration(
                                      color:
                                          theme.colorScheme.secondaryContainer,
                                      borderRadius: BorderRadius.circular(4.0),
                                    ),
                                    child: Text(
                                      'Silent payment',
                                      style: theme.textTheme.labelSmall
                                          ?.copyWith(
                                            color: theme
                                                .colorScheme
                                                .onSecondaryContainer,
                                          ),
                                    ),
                                  ),
                                ],
                              ],
                            ),
                          ),
                          SatoshiText(
                            value: r.amountSat.toInt(),
                            style: theme.textTheme.bodyMedium?.copyWith(
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 2.0),
                      Text(
                        'Line ${r.line} of the file',
                        style: theme.textTheme.labelSmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      const SizedBox(height: 6.0),
                      SelectableText(
                        spacedHex(r.address, groupSize: 4),
                        style: monospaceTextStyle.copyWith(fontSize: 12),
                      ),
                    ],
                  ),
                );
              },
            ),
          ),
          const SizedBox(height: 16.0),
          Card.outlined(
            color: theme.colorScheme.surfaceContainerHigh,
            shape: cardShape(context),
            margin: EdgeInsets.zero,
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text('Total', style: theme.textTheme.titleMedium),
                      SatoshiText(
                        value: totalSats,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12.0),
                  InkWell(
                    onTap: () => showFeeRateDialog(context),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Text('Fee', style: theme.textTheme.bodyMedium),
                            const SizedBox(width: 8.0),
                            Card(
                              color: theme.colorScheme.secondaryContainer,
                              child: Padding(
                                padding: const EdgeInsets.symmetric(
                                  vertical: 2.0,
                                  horizontal: 6.0,
                                ),
                                child: Text(
                                  '${state.feerate()?.toStringAsFixed(1) ?? '~'} sat/vB',
                                  style: theme.textTheme.labelSmall?.copyWith(
                                    color:
                                        theme.colorScheme.onSecondaryContainer,
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                        SatoshiText(
                          value: state.fee(),
                          style: TextStyle(color: theme.colorScheme.secondary),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16.0),
        ],
      ),
    );
  }

  void refreshConfirmationEstimates() async {
    if (!mounted) return;
    if (estimateRunning) return;
    setState(() => estimateRunning = true);
    await state.refreshConfirmationEstimates();
    if (mounted) setState(() => estimateRunning = false);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final confirmationBlocks = state.confirmationBlocksOfFeerate();
    final feerate = state.feerate();

    final etaInputCard = TextButton.icon(
      onPressed: pageIndex.index < SendPageIndex.signers.index
          ? () => showFeeRateDialog(context)
          : null,
      icon: Stack(
        alignment: AlignmentDirectional.bottomCenter,
        children: [
          Icon(Icons.speed_rounded),
          if (estimateRunning)
            SizedBox(
              height: 2.0,
              width: 12.0,
              child: LinearProgressIndicator(),
            ),
        ],
      ),
      label: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Flexible(
            child: Text.rich(
              confirmationBlocks != null
                  ? TextSpan(
                      children: [
                        TextSpan(text: 'Confirms in '),
                        TextSpan(
                          text: '~${confirmationBlocks * 10} min',
                          style: TextStyle(fontWeight: FontWeight.bold),
                        ),
                      ],
                    )
                  : TextSpan(text: 'Feerate'),
            ),
          ),
          if (pageIndex.index < SendPageIndex.signers.index && feerate != null)
            Flexible(child: Text('${feerate.toStringAsFixed(1)} sat/vB')),
        ],
      ),
    );

    final cardColor = theme.colorScheme.surfaceContainerHigh;

    final recipientInputCard = Card.outlined(
      color: cardColor,
      shape: cardShape(context),
      margin: EdgeInsets.all(0.0),
      child: Padding(
        padding: EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 12.0,
          children: [
            if (selectedContact case final contact?)
              Align(
                alignment: Alignment.centerLeft,
                child: InputChip(
                  label: Text(contact.name()),
                  avatar: const Icon(Icons.person_outline),
                  onDeleted: () => state.clearAddress(recipient: 0),
                ),
              )
            else ...[
              AddressInput(
                controller: addrController,
                onSubmitted: (_) => recipientDone(context),
                decoration: InputDecoration(
                  filled: false,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8.0),
                    borderSide: BorderSide.none,
                  ),
                  hintText: 'Name or address',
                  errorText: addrError,
                  errorMaxLines: 2,
                ),
              ),
              SpContactSuggestions(
                keyId: _contactsRef.keyId,
                query: addrController.controller,
                isSilentPaymentAddress: (address) =>
                    state.isSilentPaymentAddress(address: address),
                onSelected: (contact) => recipientContact(context, contact),
                onAdd: (address) => recipientAddContact(context, address),
              ),
            ],
            Row(
              spacing: 8.0,
              children: [
                Expanded(
                  child: SizedBox(
                    // Constrain height - horizontal ListView requires fixed vertical height.
                    height: 36,
                    child: ListView(
                      shrinkWrap: true,
                      scrollDirection: Axis.horizontal,
                      children: [
                        if (selectedContact == null) ...[
                          TextButton.icon(
                            onPressed: () => recipientPaste(context),
                            label: Text('Paste'),
                            icon: Icon(Icons.paste),
                          ),
                          TextButton.icon(
                            onPressed: () => recipientScan(context),
                            label: Text('Scan'),
                            icon: Icon(Icons.qr_code),
                          ),
                          TextButton.icon(
                            onPressed: () => recipientImport(context),
                            label: Text('Import recipients'),
                            icon: Icon(Icons.file_upload),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
                IconButton.filled(
                  onPressed: addrController.errorText != null
                      ? null
                      : () => recipientDone(context),
                  icon: Icon(Icons.done),
                ),
              ],
            ),
          ],
        ),
      ),
    );

    final availableAmount = state.availableAmount(recipient: 0);

    int? amount;
    Widget amountDisplay(int sats) {
      return switch (amountController.unit) {
        AmountUnit.satoshi => Text('$sats sat'),
        AmountUnit.bitcoin => SatoshiText(
          value: sats,
          hideLeadingWhitespace: true,
        ),
      };
    }

    Widget? amountErr;
    try {
      amount = state.amount(recipient: 0);
    } on AmountError catch (e) {
      amountErr = switch (e) {
        AmountError_UnspecifiedFeerate() => Text('No feerate set.'),
        AmountError_UnspecifiedAmount() => null,
        AmountError_NoAmountAvailable() => Text('No balance available.'),
        AmountError_TargetExceedsAvailable(:final target, :final available) =>
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('Exceeds max by '),
              amountDisplay(target - available),
            ],
          ),
        AmountError_UnspecifiedAddress() => Text('No recipient address.'),
        AmountError_AmountBelowDust(:final minNonDust) => Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Minimum amount is '),
            amountDisplay(minNonDust.toInt()),
          ],
        ),
      };
    }

    final amountInputCard = Card.outlined(
      color: cardColor,
      shape: cardShape(context),
      margin: EdgeInsets.all(0.0),
      child: Padding(
        padding: EdgeInsets.all(12.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 12.0,
          children: [
            if (!state.isSendMax(recipient: 0))
              AmountInput(
                model: amountController,
                onSubmitted: (_) => amountDone(context),
                decoration: InputDecoration(
                  filled: false,
                  errorMaxLines: 2,
                  hintText: 'Amount',
                  error: amountErr,
                ),
              ),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                TextButton.icon(
                  onPressed: (availableAmount ?? 0) == 0
                      ? null
                      : () => state.toggleSendMax(
                          recipient: 0,
                          fallbackAmount: amountController.amount,
                        ),
                  label: Row(
                    spacing: 4.0,
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text('Send Max'),
                      SatoshiText(value: availableAmount),
                    ],
                  ),
                  icon: Icon(
                    (state.recipient(recipient: 0)?.amount?.isSendMax() ??
                            false)
                        ? Icons.check_box
                        : Icons.check_box_outline_blank,
                  ),
                ),
                IconButton.filled(
                  onPressed: amount == null ? null : () => amountDone(context),
                  icon: Icon(Icons.done),
                ),
              ],
            ),
          ],
        ),
      ),
    );

    final accessStruct = state.accessStruct()!;
    final threshold = accessStruct.threshold();
    final selectedDevices = state.selectedSigners();
    final remaining = threshold - selectedDevices.length;

    final deviceItems = DeviceItem.fromAccessStructure(accessStruct);
    final signersInputCard = Card.outlined(
      color: cardColor,
      shape: cardShape(context),
      margin: EdgeInsets.all(0.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          DeviceSelectorList(
            title: widget.remoteSigning
                ? 'Offer to sign with'
                : 'Select Signers',
            trailing: widget.remoteSigning ? null : '$threshold required',
            devices: deviceItems,
            selected: selectedDevices.toSet(),
            onToggle: (id) {
              if (state.isSignerSelected(dId: id)) {
                state.deselectSigner(dId: id);
              } else if (remaining > 0) {
                state.selectSigner(dId: id);
              }
            },
          ),
          Padding(
            padding: const EdgeInsets.all(12.0),
            child: FilledButton(
              onPressed: widget.remoteSigning
                  ? () => signersDone(context)
                  : remaining == 0
                  ? () => signersDone(context)
                  : null,
              child: Text(
                widget.remoteSigning
                    ? 'Send'
                    : remaining > 0
                    ? 'Select ${remaining} more'
                    : 'Sign transaction',
              ),
            ),
          ),
        ],
      ),
    );

    final mediaQuery = MediaQuery.of(context);
    final scrollView = CustomScrollView(
      controller: scrollController,
      reverse: true,
      shrinkWrap: true,
      slivers: [
        SliverSafeArea(
          sliver: SliverToBoxAdapter(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _buildCompletedList(context),
                Padding(
                  padding: sectionPadding.add(
                    EdgeInsets.only(bottom: mediaQuery.viewInsets.bottom),
                  ),
                  child: Column(
                    children: [
                      if (importedRecipients == null)
                        Padding(
                          padding: EdgeInsets.symmetric(vertical: 12.0),
                          child: etaInputCard,
                        ),
                      if (pageIndex == SendPageIndex.recipient)
                        recipientInputCard,
                      if (pageIndex == SendPageIndex.amount) amountInputCard,
                      if (pageIndex == SendPageIndex.signers) signersInputCard,
                      //if (pageIndex == SendPageIndex.sign) signInputCard,
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, result) {
        if (didPop) return;
        prevPageOrPop(result);
      },
      child: scrollView,
    );
  }

  Widget completedCardLabel(BuildContext context, String text) =>
      Text(text, style: Theme.of(context).textTheme.labelLarge);

  Future<ConfirmationTarget?> showFeeRateDialog(BuildContext context) async {
    final walletCtx = WalletContext.of(context)!;

    final target = await showDialog<ConfirmationTarget>(
      context: context,
      builder: (context) {
        return BackdropFilter(
          filter: blurFilter,
          child: FeeRatePickerDialog(walletContext: walletCtx, state: state),
        );
      },
    );

    if (context.mounted &&
        importedRecipients == null &&
        pageIndex.index > SendPageIndex.amount.index) {
      setState(() => pageIndex = SendPageIndex.amount);
    }
    return target;
  }

  signersDone(BuildContext context) async {
    UnsignedTx? unsignedTx = importedRecipients == null
        ? null
        : _importedUnsignedTx();
    try {
      unsignedTx ??= state.tryFinish();
    } on TryFinishTxError catch (e) {
      final why = switch (e) {
        TryFinishTxError.missingFeerate => 'No feerate',
        TryFinishTxError.incompleteRecipientValues => 'No recipient amount',
        TryFinishTxError.insufficientBalance => 'Insufficient Balance',
      };
      showErrorSnackbar(context, 'Invalid transaction: $why');
    }

    if (widget.remoteSigning && unsignedTx != null) {
      widget.onTxReady!(unsignedTx, state.selectedSigners().toList());
      Navigator.pop(context);
      return;
    }

    final fsCtx = FrostsnapContext.of(context)!;
    final walletCtx = WalletContext.of(context)!;
    final access = walletCtx.wallet.frostKey()!.accessStructures()[0];
    final chainTipHeight = walletCtx.wallet.superWallet.height();
    final now = DateTime.now();

    final tx = unsignedTx?.details(
      superWallet: walletCtx.superWallet,
      masterAppkey: walletCtx.masterAppkey,
    );
    if (tx == null) return;
    final txDetails = TxDetailsModel(
      tx: tx,
      chainTipHeight: chainTipHeight,
      now: now,
    );
    nextPageOrPop(null);
    await showBottomSheetOrDialog(
      context,
      title: Text('Transaction Details'),
      builder: (context, scrollController) => walletCtx.wrap(
        TxDetailsPage(
          txStates: walletCtx.txStream,
          txDetails: txDetails,
          psbtMan: fsCtx.psbtManager,
          signingParams: TxSigningParams.start(
            accessStructureRef: access.accessStructureRef(),
            unsignedTx: unsignedTx!,
            devices: state.selectedSigners().toList(),
          ),
        ),
      ),
    );
  }

  void amountDone(BuildContext context) {
    nextPageOrPop(null);
  }

  void recipientContact(BuildContext context, SpContactEntry contact) {
    // Hardcoded recipient index for now - since only 1 recipient is supported.
    state.setRecipientContact(recipient: 0, contact: contact);
    addrController.controller.clear();
    recipientNext(context);
  }

  /// The add flow, then pays whoever was added.
  Future<void> recipientAddContact(BuildContext context, String address) async {
    final name = await showAddSpContact(
      context,
      accessStructureRef: _contactsRef,
      address: address,
    );
    if (name == null || !context.mounted) return;
    final contact = coord
        .spContacts(keyId: _contactsRef.keyId)
        .where((contact) => contact.name() == name)
        .firstOrNull;
    if (contact != null) recipientContact(context, contact);
  }

  void recipientDone(BuildContext context) async {
    if (selectedContact != null) {
      recipientNext(context);
      return;
    }
    final text = addrController.controller.text;
    final exact = coord
        .spContacts(keyId: _contactsRef.keyId)
        .where(
          (contact) => contactIsExactly(
            text,
            name: contact.name(),
            address: contact.address(),
          ),
        )
        .firstOrNull;
    if (exact != null) {
      recipientContact(context, exact);
      return;
    }
    // Hardcoded recipient index for now - since only 1 recipient is supported.
    final submitOkay = addrController.submit(0);
    if (!submitOkay) {
      // So that we see the address input error.
      setState(() {});
      return;
    }
    recipientNext(context);
  }

  void recipientNext(BuildContext context) async {
    if (state.feerate() == null) {
      final feerate = await showFeeRateDialog(context);
      if (feerate == null) return;
    }

    nextPageOrPop(null);
  }

  recipientPaste(BuildContext context) async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (!context.mounted || data == null || data.text == null) return;
    addrController.controller.text = data.text!;
    recipientDone(context);
  }

  recipientScan(BuildContext context) async {
    final addressResult = await MaybeFullscreenDialog.show<String>(
      context: context,
      child: const QrStringScanner(title: 'Scan address'),
    );
    if (!context.mounted || addressResult == null) return;
    addrController.controller.text = addressResult;
    recipientDone(context);
  }

  Future<void> recipientImport(BuildContext context) async {
    FilePickerResult? result;
    try {
      result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['csv'],
      );
    } catch (e) {
      if (context.mounted) {
        await _showErrorDialog(context, 'Could not open file picker: $e');
      }
      return;
    }
    if (!context.mounted || result == null || result.files.isEmpty) return;

    final file = result.files.single;
    String contents;
    try {
      if (file.bytes != null) {
        contents = utf8.decode(file.bytes!);
      } else if (file.path != null) {
        contents = await File(file.path!).readAsString();
      } else {
        return;
      }
    } catch (e) {
      if (context.mounted) {
        await _showErrorDialog(context, 'Failed to read file: $e');
      }
      return;
    }

    final channel = widget.contacts;
    List<RecipientLine> lines;
    try {
      lines = parseRecipientsFile(
        contents: contents,
        network: widget.superWallet.network,
        contacts: coord.spContacts(keyId: _contactsRef.keyId),
        allowNewContacts: channel != null,
      );
    } catch (e) {
      if (context.mounted) {
        await _showErrorDialog(context, e.toString());
      }
      return;
    }

    if (!context.mounted) return;

    // Silent payment lines that are not contacts yet, each address once.
    final newContacts = <String, ContactChangeView>{};
    for (final line in lines) {
      if (!line.isSilentPayment || line.contact != null) continue;
      newContacts.putIfAbsent(
        line.address.toLowerCase(),
        () => ContactChangeView(
          remove: false,
          name: line.label!,
          address: line.address,
        ),
      );
    }
    if (channel != null && newContacts.isNotEmpty) {
      final added = await _addNewContacts(
        context,
        channel,
        newContacts.values.toList(),
      );
      if (!added || !context.mounted) return;
      // Every line resolves to a contact now, through the same checks.
      try {
        lines = parseRecipientsFile(
          contents: contents,
          network: widget.superWallet.network,
          contacts: coord.spContacts(keyId: _contactsRef.keyId),
          allowNewContacts: false,
        );
      } catch (e) {
        if (context.mounted) {
          await _showErrorDialog(context, e.toString());
        }
        return;
      }
      if (!context.mounted) return;
    }

    try {
      state.setRecipients(lines: lines);
    } catch (e) {
      if (context.mounted) {
        await _showErrorDialog(context, e.toString());
      }
      state.clearRecipients();
      return;
    }

    if (state.feerate() == null) {
      final feerate = await showFeeRateDialog(context);
      if (feerate == null || !context.mounted) {
        state.clearRecipients();
        return;
      }
    }

    setState(() {
      importedRecipients = lines;
      _clearImportedTx();
      pageIndex = SendPageIndex.signers;
    });
    scrollToTop();
  }

  /// Shows the new contacts a file names and asks the group to add them in one change set.
  /// Whether the book has them now.
  Future<bool> _addNewContacts(
    BuildContext context,
    ChannelContacts channel,
    List<ContactChangeView> adds,
  ) async {
    if (channel.state.value?.book.syncing ?? true) {
      await _showErrorDialog(
        context,
        'This file pays new contacts, and contacts are still syncing with the group. '
        'Import it again once they have synced.',
      );
      return false;
    }
    final ask = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          adds.length == 1 ? '1 new contact' : '${adds.length} new contacts',
        ),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'These silent payment addresses are not contacts yet. The group adds them, '
                'named by their labels, before the send. Every member confirms them on a '
                'device, so check each name and address against your own records.',
              ),
              for (final add in adds) ContactChangeTile(change: add),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Ask the group'),
          ),
        ],
      ),
    );
    if (ask != true || !context.mounted) return false;
    final added = await channel.askGroup(context, adds);
    if (!added && context.mounted) {
      showErrorSnackbar(
        context,
        'The send continues once the group has added the contacts. Import the file again then.',
      );
    }
    return added;
  }

  Future<void> _showErrorDialog(BuildContext context, String message) async {
    await showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Error importing recipients'),
        content: SingleChildScrollView(child: Text(message)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  scrollToTop() {
    Future.delayed(Durations.long3).then((_) async {
      if (context.mounted) {
        await scrollController.animateTo(
          0,
          duration: Durations.short3,
          curve: Curves.linear,
        );
      }
    });
  }

  prevPageOrPop(Object? result) {
    if (importedRecipients != null) {
      state.clearRecipients();
      setState(() {
        importedRecipients = null;
        _clearImportedTx();
        pageIndex = SendPageIndex.recipient;
      });
      return;
    }
    final prevIndex = pageIndex.index - 1;
    if (prevIndex < 0) {
      Navigator.pop(context, result);
    } else {
      final prev = SendPageIndex.values[prevIndex];
      setState(() => pageIndex = prev);
      if (pageIndex == SendPageIndex.signers) scrollToTop();
    }
  }

  nextPageOrPop(Object? result) {
    final nextIndex = pageIndex.index + 1;
    if (nextIndex >= SendPageIndex.values.length) {
      Navigator.pop(context, result);
    } else {
      final next = SendPageIndex.values[nextIndex];
      setState(() => pageIndex = next);
      if (pageIndex == SendPageIndex.signers) scrollToTop();
    }
  }
}
