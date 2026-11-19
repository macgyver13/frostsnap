# Demo: silent payment contacts on a nostr wallet

Dev tooling, not for merge. Signet only: the simulated devices keep their keys unencrypted on disk.

This runs a 2-of-3 wallet across three app instances, each with one simulated device, on a local nostr
relay. One member imports a recipients file with two new silent payment contacts, the group adds them in one
contact ceremony, and the member sends to them. A third member who was offline comes back and finds the
same contacts without any ceremony, then renames one of them with another member.

## What you need

- macOS with Flutter, and the RISC-V toolchain that `just build-firmware` uses. Run the recipe inside
  `nix develop`. If the nix daemon is not running, point cargo at the cross compiler from the nix store
  instead, as the earlier phases did:

  ```bash
  export CC_riscv32imc_unknown_none_elf=/nix/store/wi96xjqk096rnfh8699y63ic00bmgh31-riscv32-none-elf-gcc-wrapper-14.3.0/bin/riscv32-none-elf-cc
  ```

  ```bash
  export AR_riscv32imc_unknown_none_elf=/nix/store/wi96xjqk096rnfh8699y63ic00bmgh31-riscv32-none-elf-gcc-wrapper-14.3.0/bin/riscv32-none-elf-ar
  ```

  Unset `CC` and `CFLAGS` in that shell if your profile sets them.
- Signet coins. Any signet faucet will do; the demo spends about 25,000 sat plus fees.

## Build workarounds

- The app and the simulators must announce the same firmware digest, or the app asks for a firmware upgrade
  and setup stops. The recipe builds `frontier`, saves the image, and passes the same file to the app
  (`BUNDLE_FIRMWARE=<path>`) and to each simulator (`--firmware`). It is never flashed, so it does not need
  to be signed.
- espflash 4 refuses to save an image without an ESP-IDF app descriptor. The recipe passes
  `--ignore-app-descriptor` when `espflash --version` is not 3.x. The repo pins espflash 3.2.0, and
  `just build macos --debug` (which expects a signed `dev-frontier.bin`) does not work with espflash 4.
- The app has its relays built in. `FROSTSNAP_NOSTR_RELAYS` (comma separated) replaces them, and the recipe
  sets it to the local relay.
- The local Flutter's `pub get` changes `frostsnapp/pubspec.lock`. Do not commit that.

## Start everything

```bash
just demo-sp-contacts
```

This builds the firmware image, the simulator, the relay and the app, then starts in
`~/tmp/frostsnap-sp-demo` (pass another directory as the first argument to keep demos apart):

- a relay at `ws://127.0.0.1:7777` (`frostsnap_nostr/examples/local_relay.rs`, events kept in memory, so
  keep it running for the whole demo),
- three simulator windows with state files `dev1.state` to `dev3.state`,
- three app windows with data dirs `app1` to `app3`, each seeing only its own simulator.

Logs are in `~/tmp/frostsnap-sp-demo/logs`. Ctrl-C in the terminal stops everything. The relay keeps
events in memory only, so Ctrl-C also loses the channel's history: starting the recipe again on the same
app data has not been tried, and the book would rely on the apps republishing it. Use a new directory for
a new run. To start one app again
(for example the member who comes online late):

```bash
just demo-sp-app 3
```

To use public relays instead of the local one, write them comma separated into
`~/tmp/frostsnap-sp-demo/relay` (for example `wss://relay.damus.io,wss://nos.lol`) and start each app again
with `just demo-sp-app <n>`. Every app must use the same relays.

## 1. Set up the devices and the 2-of-3 wallet

The steps in this section were written from the app's code, not from a run, so a label or the order of
the screens may differ slightly.

In each app:

1. Settings: turn on Developer mode, so signet and remote wallets are offered.
2. The app shows its simulator as a new device. Name it (for example Dev 1, Dev 2, Dev 3) and confirm the
   name in the simulator window.

Create the wallet:

1. App 1: Create a multi-sig wallet, then "A group of us". On "Name this wallet", name it and, under the
   network options that developer mode adds there, pick Signet. Open the lobby and copy the invite link.
2. Apps 2 and 3: Join with invite link, and paste it.
3. In each app, Add your devices and pick its simulator.
4. App 1: Continue with 3 devices, choose threshold 2, then Generate keys. Each app shows "Generate this key?"
   with the wallet, threshold, network and participants; Accept in each.
5. Confirm on each simulator window. "Verify the security code": the code must be the same on all three
   devices. Continue, and record the backup on each simulator.
6. If the wallet opens without the chat, turn on Coordinate over Nostr for it (wallet menu) in each app.
   A nostr wallet shows the chat and a Contacts button in the app bar.

Open Contacts in each app. All three show the same "Contacts check code" with no contacts.

The lobby above is the apps' first use of the relay, and that has not been seen working yet: the override
was only checked by the recipe starting the apps. If the lobby never finds the other members, check that
each app is connected to the local relay:

```bash
lsof -nP -iTCP:7777 -sTCP:ESTABLISHED
```

## 2. Fund the wallet

In app 1, take a receive address and send signet coins to it from a faucet. Wait for a confirmation.

Then quit app 3 (Cmd-Q). It stays offline for the contact ceremony and the first send.

## 3. Import the file and add the contacts

`docs/sp-contacts-demo-recipients.csv` pays two new silent payment addresses (labels Alice and Bob) and one
ordinary signet address. The ordinary address belongs to a throwaway key; replace it with an address of your
own if you want those coins back. The silent payment addresses are derived from fixed test keys, so coins
sent to them are spendable by anyone who reads this repo: signet only.

1. App 1: Send, then Import recipients, and pick the file. A dialog "2 new contacts" lists Alice and Bob
   with their addresses and the reminder to check them against your own records. Choose Ask the group.
2. App 1 shows the "Contact changes" sheet: Add Alice, Add Bob, and "Confirmed on 0 of 2 devices."
   Choose Confirm on Dev 1.
3. Simulator 1 shows "Add contact / Alice" with the full address, then "Add contact / Bob" with its address,
   then the hold. Check each address against the file, and hold.
4. App 2: the chat shows a banner "Contact request from <member 1> needs your device"; choose Review.
   The card lists the changes, who asked, "Confirmed by" member 1, and Confirm on Dev 2. Confirm, check the
   two contacts on simulator 2, and hold.
5. Both apps move through "Confirmed. Waiting for the devices to sign." to "Done. Every member's contacts
   have these changes." The devices sign the records with no second hold.

Contacts in apps 1 and 2 now lists Alice and Bob, and both show the same check code, which differs from the
empty book's.

## 4. Send to the new contacts

When the contacts land, app 1's import continues to the batch review: Alice 5000 sat, Bob 4000 sat and the
ordinary address 3000 sat. Send the signing request to the group.

1. App 1 offers on its own request and signs on simulator 1. The simulator shows the batch: each recipient,
   or a summary and list above three.
2. App 2: open the request in the chat. The offer sheet first checks the books ("Checking contacts...");
   with the same book the offer button is enabled. Offer, review on simulator 2, and hold.
3. Once both have signed, broadcast from either app.

## 5. Bring the third member online

```bash
just demo-sp-app 3
```

App 3 reads the channel's history. Its Contacts screen may show Syncing for a moment, then Alice and Bob
with the same check code as apps 1 and 2. No ceremony runs and nothing asks app 3's device to confirm.

## 6. Rename a contact from another app

1. App 3: Contacts, Bob, Rename, enter Robert, and Ask to rename.
2. The card shows Remove Bob and Add Robert. Confirm on Dev 3. Simulator 3 shows "Remove contact / Bob" with
   the address, then "Add contact / Robert" with the same address, then one hold.
3. Confirm in app 1 or app 2 as well (the chat banner, or the card on the Contacts screen).
4. All three apps reach "Done" and list Alice and Robert, with a new check code that is the same in every
   app.

## 7. Import the next file from the third app

`docs/sp-contacts-demo-recipients-2.csv` pays both contacts with empty labels. In app 3, Send, Import
recipients, and pick it. Both lines resolve to the existing contacts (Alice and Robert), so no ceremony
runs, and the send goes to review. Another member offers from the same book, both sign, and every app shows
the same contacts throughout.

## What the screens say

A ceremony card's status:

| Status | Text |
|---|---|
| Waiting for confirmations | Confirmed on N of 2 devices. |
| Request ahead of this book | Waiting for contacts to sync before it can be confirmed. |
| Another request from the same head is open | Another contact change from the same book is still open. This one waits until it lands or is cancelled. |
| Subset chosen, signing | Confirmed. Waiting for the devices to sign. |
| This member's device forgot its approval | Your device forgot its approval before it signed. Confirm on it again. |
| Published | Done. Every member's contacts have these changes. |
| Dropped | Dropped. It was cancelled, or another change to the contacts landed first. |

The offer sheet on a send that pays a contact:

| Verdict | Text |
|---|---|
| Checking | Checking contacts... |
| Same book | (no message, the offer button is enabled) |
| This app is behind | Waiting for contacts to sync. You can offer once your contacts match the requester's. |
| The requester is behind | The requester's contacts are out of date. They need to sync and ask again. |
| Pays a contact not in the book | This send pays NAME, who is not in this wallet's contacts, so it can't be signed. |
| No book head | This send pays a contact but doesn't say which contacts it was built from, so it can't be signed. |

## Known limits

- An offer's reserved nonces live in the app's memory. If a member restarts the app after confirming and
  before the round signs, it cannot sign that round; the requester cancels and asks again ("Cancel and ask
  again" on the card).
- A device keeps one approval in memory. Unplugging or restarting a simulator between confirming and signing
  means confirming again.
- A member announces its head in a separate event after its offer, not inside the offer.
- A file with new contacts is refused while the book is syncing; import it again once Syncing is gone.

## Start over

Stop the demo with Ctrl-C, then remove the demo directory. This deletes the three simulated devices' keys
and the three apps' data for the demo wallet, and cannot be undone:

```bash
rm -rf ~/tmp/frostsnap-sp-demo
```
