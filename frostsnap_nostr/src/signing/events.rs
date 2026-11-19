//! Events and wire format for the signing channel.
//!
//! - [`ChannelEvent`] is the top-level stream emitted by
//!   [`crate::signing::ChannelClient`] through its `Sink<ChannelEvent>`.
//!   It carries chat messages, connection state, group metadata, and
//!   signing-protocol events.
//! - [`SigningMessage`] is the bincode wire payload of kind-9001 inner
//!   events on the nostr channel.
//! - [`SigningEvent`] is the decoded signing-protocol event, carried inside
//!   `ChannelEvent::Signing { event, pending }`.

use crate::channel::ParticipantShares;
use crate::{EventId, PublicKey};
use frostsnap_core::{
    coordinator::{
        remote_sp_contact::SpContactOffer, ParticipantBinonces, ParticipantSignatureShares,
    },
    silent_payments::{BookHead, ContactChangeSet, EcdhShare, SignedSpContactChanges},
    SignSessionId, WireSignTask,
};
use nostr_sdk::{Event, TagKind};

// ============================================================================
// Channel events (top-level sink stream)
// ============================================================================

/// Re-exported: member state is owned by the channel runner (block
/// pattern — see `ChannelInfraEvent::Members`); this alias keeps the
/// established `frostsnap_nostr::GroupMember` path stable.
pub use crate::channel_runner::GroupMember;

/// Events emitted by ChannelClient through the Sink.
/// Dart receives these and builds the chat + signing state.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ChannelEvent {
    ChatMessage {
        message_id: EventId,
        author: PublicKey,
        content: String,
        timestamp: u64,
        reply_to: Option<EventId>,
        pending: bool,
    },
    MessageSent {
        message_id: EventId,
    },
    MessageSendFailed {
        message_id: EventId,
        reason: String,
    },
    ReceiveAddress {
        message_id: EventId,
        author: PublicKey,
        timestamp: u64,
        pending: bool,
        derivation_index: u32,
        memo: String,
    },
    ReceiveAddressSendFailed {
        message_id: EventId,
        reason: String,
    },
    /// A tx that touches this group's wallet was observed (in
    /// mempool or just confirmed). Carries identifiers + chat-side
    /// correlations only; Dart fetches the tx data via
    /// `SuperWallet::get_tx(txid)` at render time.
    TxObservation {
        txid: String,
        kind: ObservationKind,
        /// `last_seen` for `Mempool`, `confirmation_time.time` for
        /// `Confirmed`. Used by Dart for chat-timeline ordering.
        timestamp: u64,
        /// Set when this tx pays to an address that was previously
        /// announced via a `ReceiveAddress` chat message.
        /// Chronology-only — resolved once on first observation,
        /// no back-patching.
        address_reveal_event: Option<EventId>,
        /// Set when this tx is the signed result of a chat
        /// `SigningEvent::Request`. Same chronology rule.
        signing_start_event: Option<EventId>,
    },
    ConnectionState(ConnectionState),
    /// The channel's full member block (runner-owned; block pattern).
    /// Emitted unperturbed on every membership/profile change —
    /// consumers display it, they never reconstruct member state
    /// from deltas.
    GroupMetadata {
        members: Vec<GroupMember>,
    },
    Signing {
        event: SigningEvent,
        pending: bool,
    },
    Error {
        event_id: EventId,
        author: PublicKey,
        timestamp: u64,
        reason: String,
    },
    /// The channel's fold state — currently just the initial participant
    /// mapping from the creation event. Emitted when the creation event
    /// is received (either fetched from relay or just published).
    ChannelState {
        participants: Vec<ChannelParticipant>,
    },
}

/// Dart-friendly representation of a participant's share ownership.
/// Converted from `ParticipantShares` (which uses opaque `ShareIndex`).
#[derive(Debug, Clone)]
pub struct ChannelParticipant {
    pub pubkey: PublicKey,
    pub share_indices: Vec<u32>,
}

impl From<&ParticipantShares> for ChannelParticipant {
    fn from(p: &ParticipantShares) -> Self {
        Self {
            pubkey: p.pubkey,
            share_indices: p
                .share_indices
                .iter()
                .map(|si| u32::try_from(*si).expect("share index fits u32"))
                .collect(),
        }
    }
}

impl ChannelEvent {
    pub fn from_inner_chat_message(inner_event: &Event, pending: bool) -> Self {
        Self::ChatMessage {
            message_id: inner_event.id.into(),
            author: inner_event.pubkey.into(),
            content: inner_event.content.clone(),
            timestamp: inner_event.created_at.as_secs(),
            reply_to: inner_event.tags.iter().find_map(|tag| {
                if tag.kind() == TagKind::e() {
                    tag.content()
                        .and_then(|s| nostr_sdk::EventId::from_hex(s).ok())
                        .map(EventId::from)
                } else {
                    None
                }
            }),
            pending,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected { reason: Option<String> },
}

/// Which moment-in-time a `TxObservation` event represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationKind {
    /// Wallet has seen the tx (typically in mempool) but it
    /// hasn't been confirmed in a block yet.
    Mempool,
    /// Wallet has seen a block containing the tx.
    Confirmed,
}

// ============================================================================
// Signing-protocol events
// ============================================================================

/// One entry in a [`SigningEvent::RoundConfirmed`]'s selected subset.
#[derive(Debug, Clone)]
pub struct ConfirmedSubsetEntry {
    pub event_id: EventId,
    pub author: PublicKey,
    pub timestamp: u64,
    pub binonces: Vec<ParticipantBinonces>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SigningEvent {
    Request {
        event_id: EventId,
        author: PublicKey,
        sign_task: WireSignTask,
        message: String,
        /// The requester's contact book head. A request that pays a contact carries it, and a
        /// reviewer offers only from the same head (see `contacts::sign_gate`).
        book_head: Option<BookHead>,
        timestamp: u64,
    },
    Offer {
        event_id: EventId,
        author: PublicKey,
        request_id: EventId,
        binonces: Vec<ParticipantBinonces>,
        timestamp: u64,
    },
    /// Emitted when the settling timer expires with at least `threshold`
    /// offers observed. The subset is locked in; included participants
    /// should sign.
    RoundConfirmed {
        request_id: EventId,
        subset: Vec<ConfirmedSubsetEntry>,
        session_id: SignSessionId,
        sign_task: WireSignTask,
        timestamp: u64,
    },
    /// Emitted when the settling timer expires with fewer than `threshold`
    /// offers. The round is still collecting; this is a provisional
    /// snapshot. Offers already in `observed` will almost certainly remain
    /// in the final confirmed subset (selector is oldest-first), so the
    /// UI can surface "your offer is likely accepted" to their authors.
    /// Re-emitted on every subsequent quiet period as new offers arrive.
    RoundPending {
        request_id: EventId,
        observed: Vec<EventId>,
        threshold: usize,
        timestamp: u64,
    },
    Partial {
        event_id: EventId,
        author: PublicKey,
        request_id: EventId,
        offer_subset: Vec<EventId>,
        session_id: SignSessionId,
        signature_shares: ParticipantSignatureShares,
        timestamp: u64,
    },
    Cancel {
        event_id: EventId,
        author: PublicKey,
        request_id: EventId,
        timestamp: u64,
    },
    Rejected {
        event_id: EventId,
        author: PublicKey,
        timestamp: u64,
        reason: String,
    },
}

// ============================================================================
// Contact events
// ============================================================================

/// One offer of a [`ContactEvent::RoundConfirmed`] subset.
#[derive(Debug, Clone)]
pub struct ContactOfferEntry {
    pub event_id: EventId,
    pub author: PublicKey,
    pub timestamp: u64,
    pub offer: SpContactOffer,
}

/// The contact change set ceremony, folded from the channel like signing rounds. A request names a
/// change set, each member's device confirms it and the member offers its ECDH shares, and once the
/// settling timer picks a subset of a threshold of offers, the members in it sign. These go to the
/// sink given to [`crate::signing::ChannelClient::with_contact_sink`], not to the chat's sink.
#[derive(Debug, Clone)]
pub enum ContactEvent {
    Request {
        event_id: EventId,
        author: PublicKey,
        set: ContactChangeSet,
        timestamp: u64,
    },
    /// An offer whose shares checked against the wallet's key. One that does not check is
    /// `Rejected` instead and never takes a place in the subset.
    Offer {
        event_id: EventId,
        author: PublicKey,
        request_id: EventId,
        offer: SpContactOffer,
        timestamp: u64,
    },
    /// The subset is locked in. `sign_task` is the change set with each add's `x * B_scan`
    /// combined from the subset's shares, and `session_id` the session its signatures belong to.
    RoundConfirmed {
        request_id: EventId,
        subset: Vec<ContactOfferEntry>,
        session_id: SignSessionId,
        sign_task: WireSignTask,
        timestamp: u64,
    },
    RoundPending {
        request_id: EventId,
        observed: Vec<EventId>,
        threshold: usize,
        timestamp: u64,
    },
    /// A signature share over the task the partial's `offer_subset` completes.
    Partial {
        event_id: EventId,
        author: PublicKey,
        request_id: EventId,
        offer_subset: Vec<EventId>,
        session_id: SignSessionId,
        sign_task: WireSignTask,
        signature_shares: ParticipantSignatureShares,
        timestamp: u64,
    },
    Cancel {
        event_id: EventId,
        author: PublicKey,
        request_id: EventId,
        timestamp: u64,
    },
    Rejected {
        event_id: EventId,
        author: PublicKey,
        timestamp: u64,
        reason: String,
    },
    /// A signed change set any member published. Not checked yet: the receiver checks it against
    /// the wallet's key before it touches the book.
    Changes {
        event_id: EventId,
        author: PublicKey,
        signed: SignedSpContactChanges,
        timestamp: u64,
    },
    /// The head of a member's book, announced when it connects and with each offer it makes.
    BookHead {
        event_id: EventId,
        author: PublicKey,
        head: BookHead,
        timestamp: u64,
    },
    /// The channel's history has been read from the relays. Events before this one are history.
    HistorySynced,
}

// ============================================================================
// Wire format
// ============================================================================

/// Bincode-friendly wrapper around `EventId`. Nostr-sdk's serde `Serialize`
/// unconditionally emits hex strings, so `#[bincode(with_serde)]` on a raw
/// `EventId` would encode 72 bytes instead of 32. This newtype uses the
/// frostsnap_core macros to encode/decode as raw bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WireEventId(pub [u8; 32]);

frostsnap_core::impl_display_debug_serialize!(
    fn to_bytes(weid: &WireEventId) -> [u8; 32] {
        weid.0
    }
);

frostsnap_core::impl_fromstr_deserialize!(
    name => "wire event id",
    fn from_bytes(bytes: [u8; 32]) -> WireEventId { WireEventId(bytes) }
);

impl From<EventId> for WireEventId {
    fn from(id: EventId) -> Self {
        WireEventId(id.0)
    }
}

impl From<WireEventId> for EventId {
    fn from(w: WireEventId) -> Self {
        EventId(w.0)
    }
}

/// Wire format for all frostsnap signing messages in the channel.
#[derive(bincode::Encode, bincode::Decode)]
pub(crate) enum SigningMessage {
    Request {
        sign_task: WireSignTask,
        message: String,
    },
    Offer {
        binonces: Vec<ParticipantBinonces>,
    },
    Partial {
        offer_subset: Vec<WireEventId>,
        signature_shares: ParticipantSignatureShares,
    },
    Cancel,
    /// Index 4 was the silent payment offer of the per-send ECDH round (PR 640), which this
    /// branch dropped. It stays reserved so a channel that carries one never decodes it as
    /// something else.
    RetiredSpOffer,
    /// Asks the group to confirm a contact change set. Partials and Cancel are shared with signing.
    ContactRequest {
        set: ContactChangeSet,
    },
    /// A member's device confirmed the change set: binonces for one signature per change, and the
    /// device's ECDH share of each add with its proof.
    ContactOffer {
        binonces: ParticipantBinonces,
        shares: Vec<EcdhShare>,
    },
    /// A change set a threshold of devices signed. Published once by any member that has every
    /// partial of the subset, and again by a member answering a head behind its own.
    ContactChanges {
        signed: SignedSpContactChanges,
    },
    /// The head of the author's contact book.
    BookHead {
        head: BookHead,
    },
    /// A sign request that pays a contact, with the head of the requester's book. `Request` keeps
    /// its bytes, so a request that pays no contact is still a `Request`.
    RequestAtHead {
        sign_task: WireSignTask,
        message: String,
        head: BookHead,
    },
}

/// Wire format for receive-address share messages (kind 7800).
/// Carries only the structural information needed to derive the
/// address — receivers compute the actual address themselves from
/// their wallet descriptor. Keychain is always external and
/// account is the wallet's default; neither needs to be on the
/// wire today.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct ReceiveAddressPayload {
    pub derivation_index: u32,
    pub memo: String,
}

#[cfg(test)]
mod encoding {
    use super::SigningMessage;
    use frostsnap_core::coordinator::ParticipantBinonces;
    use frostsnap_core::schnorr_fun::fun::{marker::*, Scalar};
    use frostsnap_core::silent_payments::{
        BookHead, ContactChangeSet, SignedSpContactChanges, SpContactChanges,
    };

    fn encoded(message: &SigningMessage) -> String {
        let bytes = bincode::encode_to_vec(message, bincode::config::standard()).unwrap();
        frostsnap_core::hex::encode(&bytes)
    }

    /// New variants are appended, so the bytes of the existing ones do not change, and index 4
    /// stays reserved for the retired silent payment offer. `standard()` encodes the variant
    /// index and lengths as varints.
    #[test]
    fn contact_messages_are_appended_variants() {
        assert_eq!(encoded(&SigningMessage::Offer { binonces: vec![] }), "0100");
        assert_eq!(encoded(&SigningMessage::Cancel), "03");
        assert_eq!(encoded(&SigningMessage::RetiredSpOffer), "04");
        // Bytes written before the new variants still decode as what they were.
        let decode = |hex: &str| {
            let bytes = frostsnap_core::hex::decode(hex).unwrap();
            bincode::decode_from_slice::<SigningMessage, _>(&bytes, bincode::config::standard())
                .unwrap()
                .0
        };
        assert!(
            matches!(decode("0100"), SigningMessage::Offer { binonces } if binonces.is_empty())
        );
        assert!(matches!(decode("03"), SigningMessage::Cancel));
        let request = encoded(&SigningMessage::ContactRequest {
            set: ContactChangeSet {
                head: BookHead::empty(),
                changes: vec![],
            },
        });
        assert!(request.starts_with("0500"), "{request}");
        let share_index =
            Scalar::<Secret, NonZero>::from(core::num::NonZeroU32::new(1).unwrap()).public();
        assert_eq!(
            encoded(&SigningMessage::ContactOffer {
                binonces: ParticipantBinonces {
                    share_index,
                    binonces: vec![],
                },
                shares: vec![],
            })[..2],
            *"06"
        );
        let head = BookHead::empty();
        let changes = encoded(&SigningMessage::ContactChanges {
            signed: SignedSpContactChanges {
                changes: SpContactChanges {
                    set: ContactChangeSet {
                        head,
                        changes: vec![],
                    },
                    account_ecdh: vec![],
                },
                signatures: vec![],
            },
        });
        assert!(changes.starts_with("0700"), "{changes}");
        assert_eq!(
            encoded(&SigningMessage::BookHead { head }),
            format!("0800{}", frostsnap_core::hex::encode(&head.hash))
        );
        let at_head = encoded(&SigningMessage::RequestAtHead {
            sign_task: frostsnap_core::WireSignTask::Test {
                message: String::new(),
            },
            message: String::new(),
            head,
        });
        assert!(at_head.starts_with("09"), "{at_head}");
    }
}
