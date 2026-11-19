//! The FFI for a wallet's contact book on its nostr channel: start a change set ceremony, follow
//! it, confirm it on the local device, read the book, and the gate's verdict on a sign request.

use super::{BookHead, ChannelHandle, EventId, PublicKey};
use crate::api::coordinator::Coordinator;
use crate::api::signing::SpContactEntry;
use crate::contacts_glue::ContactsGlue;
use crate::frb_generated::StreamSink;
use anyhow::{anyhow, Result};
use flutter_rust_bridge::frb;
use frostsnap_core::silent_payments::{
    ContactBook, ContactChange, SilentPaymentRecipient, SpContactDetails,
};
use frostsnap_core::WireSignTask;
use frostsnap_core::{DeviceId, SymmetricKey};
pub use frostsnap_nostr::signing::contacts::{CeremonyStatus, SignGate};

/// One change of a change set, as the app shows and builds it.
#[derive(Clone, Debug)]
pub struct ContactChangeView {
    pub remove: bool,
    pub name: String,
    pub address: String,
}

/// A change set ceremony this member has seen in the channel.
#[derive(Clone, Debug)]
pub struct ContactCeremonyView {
    pub request_id: EventId,
    pub author: PublicKey,
    /// This member asked for it.
    pub mine: bool,
    pub changes: Vec<ContactChangeView>,
    pub status: CeremonyStatus,
    /// The members that have confirmed it on a device so far.
    pub offered_by: Vec<PublicKey>,
    /// Why the last step on this member's device failed, if it did.
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ContactBookView {
    pub contacts: Vec<SpContactEntry>,
    pub head: BookHead,
    /// Another member is ahead of this book, or a change set waits for one it doesn't have.
    pub syncing: bool,
    /// Signed change sets that were not applied because another change landed first, each with
    /// its changes. Start them again with `start_contact_changes` to apply them to the book as
    /// it is now.
    pub dropped: Vec<Vec<ContactChangeView>>,
}

/// The book and every ceremony, sent again whenever either changes.
#[derive(Clone, Debug)]
pub struct ContactsState {
    pub book: ContactBookView,
    pub ceremonies: Vec<ContactCeremonyView>,
}

#[frb(mirror(CeremonyStatus), non_opaque)]
pub enum _CeremonyStatus {
    Syncing,
    WaitingForConfirmations { offers: usize, threshold: usize },
    Confirmed,
    PendingDeviceRestart,
    Published,
    Dropped,
    BlockedByOpenRequest { request_id: EventId },
}

#[frb(mirror(SignGate), non_opaque)]
pub enum _SignGate {
    Allowed,
    MissingHead,
    WaitingForSync,
    RequesterBehind,
    NotInBook { name: String },
}

impl ContactsState {
    pub(crate) fn read(glue: &ContactsGlue) -> Self {
        let sync = glue.sync.lock().unwrap();
        let coordinator = glue.coord.coordinator.lock().unwrap();
        let key_id = glue.key_id;
        let network = glue.network;
        let errors = glue.errors.lock().unwrap();
        let view = |change: &ContactChange| ContactChangeView {
            remove: change.is_remove(),
            name: change.details().name.clone(),
            address: change
                .details()
                .recipient
                .address(network)
                .unwrap_or_default(),
        };
        Self {
            book: ContactBookView {
                contacts: coordinator
                    .sp_contacts(key_id)
                    .filter_map(|contact| {
                        Some(SpContactEntry {
                            address: contact.contact.details.recipient.address(network)?,
                            contact: contact.clone(),
                        })
                    })
                    .collect(),
                head: coordinator.sp_contact_book_head(key_id),
                syncing: sync.is_syncing(&coordinator),
                dropped: coordinator
                    .sp_contact_book(key_id)
                    .map(|book| {
                        book.dropped()
                            .into_iter()
                            .map(|signed| signed.changes.set.changes.iter().map(view).collect())
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            ceremonies: sync
                .ceremonies()
                .map(|ceremony| ContactCeremonyView {
                    request_id: ceremony.request_id,
                    author: ceremony.author,
                    mine: ceremony.author == glue.me,
                    changes: ceremony.set.changes.iter().map(view).collect(),
                    status: sync
                        .status(&coordinator, ceremony.request_id)
                        .expect("listed by the driver"),
                    offered_by: ceremony.offered_by().into_iter().collect(),
                    error: errors.get(&ceremony.request_id).cloned(),
                })
                .collect(),
        }
    }
}

impl ChannelHandle {
    /// Runs the wallet's shared contact book on this channel. Call before `start()`; without it
    /// the channel shows no contacts, and refuses to offer on or request a send that pays one.
    #[frb(sync)]
    pub fn attach_contacts(&self, coord: &Coordinator) -> Result<()> {
        if self.inner.initialized() {
            return Err(anyhow!("attach contacts before starting the channel"));
        }
        self.contacts_coord
            .set(coord.0.clone())
            .map_err(|_| anyhow!("contacts are already attached"))
    }

    /// The book and the ceremonies, now and on every change.
    pub fn sub_contacts(&self, sink: StreamSink<ContactsState>) -> Result<()> {
        self.require_contacts()?.set_sink(sink);
        Ok(())
    }

    fn require_contacts(&self) -> Result<&std::sync::Arc<ContactsGlue>> {
        self.contacts
            .get()
            .ok_or_else(|| anyhow!("contacts are not attached to this channel"))
    }

    /// Asks the group to confirm `changes` against the book as it is now: adds, removes, or a
    /// rename as a remove and an add of the same address. Refused if they don't apply to it.
    pub async fn start_contact_changes(&self, changes: Vec<ContactChangeView>) -> Result<EventId> {
        let glue = self.require_contacts()?;
        let set = {
            let sync = glue.sync.lock().unwrap();
            let network = glue.network;
            let changes = changes
                .into_iter()
                .map(|change| {
                    // A scanned QR code often gives the address in uppercase.
                    let address = change.address.trim().to_lowercase();
                    let recipient = SilentPaymentRecipient::from_address(&address, network)
                        .ok_or_else(|| {
                            anyhow!("{address} is not a silent payment address on this network")
                        })?;
                    let details = SpContactDetails {
                        name: change.name,
                        recipient,
                    };
                    Ok(if change.remove {
                        ContactChange::Remove(details)
                    } else {
                        ContactChange::Add(details)
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let coordinator = glue.coord.coordinator.lock().unwrap();
            sync.new_change_set(&coordinator, changes)
                .map_err(|e| anyhow!("{e}"))?
        };
        let inner = self.require_inner()?;
        let keys = inner.runner_handle.signing_keys().clone();
        inner.send_contact_request(&keys, set).await
    }

    /// Withdraws a ceremony this member asked for.
    pub async fn cancel_contact_changes(&self, request_id: EventId) -> Result<EventId> {
        self.send_sign_cancel(request_id).await
    }

    /// Asks the local device to confirm the change set of `request_id`, or to confirm it again
    /// after it forgot its approval. The key stays in memory for the device's signature once the
    /// round confirms.
    pub fn confirm_contact_changes(
        &self,
        request_id: EventId,
        device_id: DeviceId,
        encryption_key: SymmetricKey,
    ) -> Result<()> {
        self.require_contacts()?
            .confirm(request_id, device_id, encryption_key)
    }

    /// Whether this member may offer on the sign request `request_id`, as far as contacts go.
    pub async fn sign_gate(&self, request_id: EventId) -> Result<SignGate> {
        self.check_sign_gate(request_id).await
    }

    /// The gate's verdict, announcing this member's head once if it waits for sync.
    pub(crate) async fn check_sign_gate(&self, request_id: EventId) -> Result<SignGate> {
        let (sign_task, book_head) = self
            .requests
            .lock()
            .unwrap()
            .get(&request_id)
            .cloned()
            .ok_or_else(|| anyhow!("no such sign request in this channel"))?;
        let Some(glue) = self.contacts.get() else {
            return Ok(gate_without_book(
                self.key_context.purpose.bitcoin_network(),
                &sign_task,
            ));
        };
        let (gate, actions) = {
            let mut sync = glue.sync.lock().unwrap();
            let coordinator = glue.coord.coordinator.lock().unwrap();
            sync.sign_gate(&coordinator, request_id, &sign_task, book_head)
        };
        let inner = self.require_inner()?;
        let keys = inner.runner_handle.signing_keys().clone();
        glue.execute(actions, inner, &keys).await;
        Ok(gate)
    }

    /// Refuses unless the gate allows an offer on `request_id`.
    pub(crate) async fn require_offer_allowed(&self, request_id: EventId) -> Result<()> {
        offer_allowed(&self.check_sign_gate(request_id).await?)
    }

    /// This member's book head, for a sign request that pays a contact.
    pub(crate) fn book_head(&self) -> Result<BookHead> {
        let glue = self.require_contacts()?;
        let coordinator = glue.coord.coordinator.lock().unwrap();
        Ok(coordinator.sp_contact_book_head(glue.key_id))
    }
}

/// The gate on a channel with no contact book attached: only a send that pays no contact passes.
fn gate_without_book(network: Option<bitcoin::Network>, sign_task: &WireSignTask) -> SignGate {
    let Some(network) = network else {
        return SignGate::Allowed;
    };
    let no_book = ContactBook::new(network);
    match frostsnap_nostr::signing::contacts::sign_gate(&no_book, sign_task, None) {
        SignGate::Allowed => SignGate::Allowed,
        _ => SignGate::MissingHead,
    }
}

/// An offer goes out only if the gate allows it; otherwise why not, as the app shows it.
fn offer_allowed(gate: &SignGate) -> Result<()> {
    let why = match gate {
        SignGate::Allowed => return Ok(()),
        SignGate::MissingHead => {
            "this request pays a contact but doesn't say which contacts it was built from".into()
        }
        SignGate::WaitingForSync => "waiting for contacts to sync".into(),
        SignGate::RequesterBehind => "the requester's contacts are out of date".into(),
        SignGate::NotInBook { name } => format!("this request pays {name}, who is not a contact"),
    };
    Err(anyhow!("can't offer to sign: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Network};
    use frostsnap_core::bitcoin_transaction::{LocalSpk, TransactionTemplate};
    use frostsnap_core::schnorr_fun::fun::{g, marker::*, Point, Scalar, G};
    use frostsnap_core::silent_payments::{
        ContactChangeSet, SignedSpContact, SignedSpContactChanges, SpContactChanges,
    };
    use frostsnap_core::tweak::BitcoinBip32Path;
    use frostsnap_core::MasterAppkey;
    use frostsnap_nostr::signing::contacts::sign_gate;

    const NETWORK: Network = Network::Signet;

    fn point(byte: u8) -> Point {
        let secret = Scalar::<Secret, Zero>::from_bytes_mod_order([byte; 32])
            .non_zero()
            .unwrap();
        g!(secret * G).normalize()
    }

    /// A set that adds `name` to `book`. The gate never checks signatures, so it has none.
    fn add(book: &ContactBook, name: &str, byte: u8) -> SignedSpContactChanges {
        let details = SpContactDetails {
            name: name.into(),
            recipient: SilentPaymentRecipient {
                scan_key: point(byte),
                spend_key: point(byte + 1),
            },
        };
        SignedSpContactChanges {
            changes: SpContactChanges {
                set: ContactChangeSet {
                    head: book.head(),
                    changes: vec![ContactChange::Add(details)],
                },
                account_ecdh: vec![point(byte + 2)],
            },
            signatures: vec![[0; 64]],
        }
    }

    fn send_paying(contact: &SignedSpContact) -> WireSignTask {
        let mut template = TransactionTemplate::new();
        template.push_imaginary_owned_input(
            LocalSpk {
                master_appkey: MasterAppkey::derive_from_rootkey(point(0x77)),
                bip32_path: BitcoinBip32Path::external(0),
            },
            Amount::from_sat(100_000),
        );
        let address = contact.contact.details.recipient.address(NETWORK).unwrap();
        template.push_silent_payment_output(Amount::from_sat(50_000), contact.clone(), address);
        WireSignTask::BitcoinTransaction(template)
    }

    /// A reviewer whose book differs from the request's head can't offer: it waits until its
    /// book reaches that head, and refuses a requester whose book is behind its own. A request
    /// that pays a contact the book doesn't have, or that names no head, is refused, as is any
    /// send to a contact on a channel with no book.
    #[test]
    fn an_offer_waits_for_the_requesters_book() {
        let mut requester = ContactBook::new(NETWORK);
        let add_ann = add(&requester, "Ann", 0x11);
        requester.insert(add_ann.clone());
        let ann = requester.by_name("Ann").unwrap().clone();
        let to_ann = send_paying(&ann);
        let head = requester.head();

        let mut reviewer = ContactBook::new(NETWORK);
        let gate = sign_gate(&reviewer, &to_ann, Some(head));
        assert_eq!(gate, SignGate::WaitingForSync);
        assert_eq!(
            offer_allowed(&gate).unwrap_err().to_string(),
            "can't offer to sign: waiting for contacts to sync"
        );

        reviewer.insert(add_ann);
        assert!(offer_allowed(&sign_gate(&reviewer, &to_ann, Some(head))).is_ok());

        reviewer.insert(add(&reviewer, "Bea", 0x21));
        let gate = sign_gate(&reviewer, &to_ann, Some(head));
        assert_eq!(gate, SignGate::RequesterBehind);
        assert_eq!(
            offer_allowed(&gate).unwrap_err().to_string(),
            "can't offer to sign: the requester's contacts are out of date"
        );

        // A contact with the same name and address that isn't the book's own record.
        let mut forged = ann.clone();
        forged.signature = [1; 64];
        let gate = sign_gate(&requester, &send_paying(&forged), Some(head));
        assert_eq!(
            offer_allowed(&gate).unwrap_err().to_string(),
            "can't offer to sign: this request pays Ann, who is not a contact"
        );
        assert!(offer_allowed(&sign_gate(&requester, &to_ann, None)).is_err());

        assert_eq!(
            gate_without_book(Some(NETWORK), &to_ann),
            SignGate::MissingHead
        );
        assert!(offer_allowed(&gate_without_book(Some(NETWORK), &to_ann)).is_err());
        let test = WireSignTask::Test {
            message: "no contacts".into(),
        };
        assert!(offer_allowed(&gate_without_book(Some(NETWORK), &test)).is_ok());
    }
}
