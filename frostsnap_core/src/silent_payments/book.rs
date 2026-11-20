//! The contact book a wallet's coordinators share.
//!
//! The book is a fold over change sets a threshold of devices signed. Each change set names the
//! [`BookHead`] it applies to, and applying it gives the next head, so every coordinator that knows
//! the same change sets reaches the same book whatever order they arrived in. Each change signs a
//! message that commits to the head the set produces. That head is a hash over the head the set
//! applies to and the whole set, so a signed change can't be moved onto another book or split
//! from the rest of its set.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use bitcoin::Network;
use schnorr_fun::{fun::Point, Schnorr, Signature};
use sha2::Digest;

use super::{tagged, SignedSpContact, SilentPaymentRecipient, SpContact, SpContactDetails};
use crate::{sign_task::SignItem, tweak::AppTweak, MasterAppkey};

/// A contact book's version and the hash chain of the change sets it applied to get there.
#[derive(
    bincode::Encode, bincode::Decode, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct BookHead {
    pub version: u32,
    pub hash: [u8; 32],
}

impl BookHead {
    /// The head of a book no change set has been applied to.
    pub fn empty() -> Self {
        Self {
            version: 0,
            hash: tagged("frostsnap/sp-contact-book/empty").finalize().into(),
        }
    }

    /// The head after applying the change set with digest `set_digest` to this one.
    pub fn next(&self, set_digest: &[u8; 32]) -> Self {
        Self {
            version: self.version + 1,
            hash: tagged("frostsnap/sp-contact-book/head")
                .chain_update(self.version.to_be_bytes())
                .chain_update(self.hash)
                .chain_update(set_digest)
                .finalize()
                .into(),
        }
    }

    /// A short code two signers can compare to see they have the same book: the first 4 bytes of
    /// the head's hash as two groups of four hex characters, e.g. `3f9a 1c07`.
    pub fn check_code(&self) -> String {
        let h = &self.hash;
        alloc::format!("{:02x}{:02x} {:02x}{:02x}", h[0], h[1], h[2], h[3])
    }
}

/// One change to the book.
#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ContactChange {
    /// Adds a contact under a name not in use once the set's removes have applied.
    Add(SpContactDetails),
    /// Removes the contact with this name and address.
    Remove(SpContactDetails),
}

impl ContactChange {
    pub fn details(&self) -> &SpContactDetails {
        match self {
            ContactChange::Add(details) | ContactChange::Remove(details) => details,
        }
    }

    pub fn is_remove(&self) -> bool {
        matches!(self, ContactChange::Remove(_))
    }

    fn tag(&self) -> u8 {
        match self {
            ContactChange::Add(_) => 0,
            ContactChange::Remove(_) => 1,
        }
    }

    /// What the wallet signs for this change, in the change set that moves the book to `head`.
    /// An add also commits to its `x * B_scan`.
    pub(super) fn sign_item(
        &self,
        head: BookHead,
        network: Network,
        account_ecdh: Option<Point>,
    ) -> SignItem {
        let mut message = Vec::with_capacity(4 + 32 + 1 + 32 + 33);
        message.extend_from_slice(&head.version.to_be_bytes());
        message.extend_from_slice(&head.hash);
        message.push(self.tag());
        message.extend_from_slice(&self.details().digest(network));
        if let Some(account_ecdh) = account_ecdh {
            message.extend_from_slice(&account_ecdh.to_bytes());
        }
        SignItem {
            message,
            app_tweak: AppTweak::SpContact,
        }
    }
}

/// Changes to the book whose head is `head`. Within a set removes apply before adds, so a rename is
/// a remove and an add of the same address under the new name.
#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ContactChangeSet {
    pub head: BookHead,
    pub changes: Vec<ContactChange>,
}

impl ContactChangeSet {
    /// Whether the set could apply to some book: it changes something, every name is valid, and no
    /// name is added twice or removed twice.
    pub fn is_well_formed(&self) -> bool {
        let mut seen = BTreeSet::new();
        !self.changes.is_empty()
            && self.changes.iter().all(|change| {
                change.details().has_valid_name()
                    && seen.insert((
                        change.is_remove(),
                        change.details().name.to_ascii_lowercase(),
                    ))
            })
    }

    pub fn adds(&self) -> impl Iterator<Item = &SpContactDetails> {
        self.changes.iter().filter_map(|change| match change {
            ContactChange::Add(details) => Some(details),
            ContactChange::Remove(_) => None,
        })
    }

    /// Commits to the head, the network and every change in order. It is what a device approves
    /// with one hold, and what the next head hashes.
    pub fn digest(&self, network: Network) -> [u8; 32] {
        let mut hash = tagged("frostsnap/sp-contact-change-set")
            .chain_update(network.magic().to_bytes())
            .chain_update(self.head.version.to_be_bytes())
            .chain_update(self.head.hash)
            .chain_update((self.changes.len() as u32).to_be_bytes());
        for change in &self.changes {
            hash.update([change.tag()]);
            hash.update(change.details().digest(network));
        }
        hash.finalize().into()
    }

    pub fn next_head(&self, network: Network) -> BookHead {
        self.head.next(&self.digest(network))
    }
}

/// A change set with `x * B_scan` for each add, in the order of the adds. It is what the wallet
/// signs, one signature per change.
#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SpContactChanges {
    pub set: ContactChangeSet,
    pub account_ecdh: Vec<Point>,
}

impl SpContactChanges {
    /// Whether the set is well formed and has one `x * B_scan` per add.
    pub fn is_well_formed(&self) -> bool {
        self.set.is_well_formed() && self.set.adds().count() == self.account_ecdh.len()
    }

    /// One sign item per change, in order. Call only on a well formed set.
    pub fn sign_items(&self, network: Network) -> Vec<SignItem> {
        let head = self.set.next_head(network);
        let mut account_ecdh = self.account_ecdh.iter();
        self.set
            .changes
            .iter()
            .map(|change| {
                let ecdh = match change {
                    ContactChange::Add(_) => account_ecdh.next().copied(),
                    ContactChange::Remove(_) => None,
                };
                change.sign_item(head, network, ecdh)
            })
            .collect()
    }
}

/// A change set with the wallet's signature on each change under [`AppTweak::SpContact`]. Any
/// coordinator checks it against the master appkey before it touches the book.
#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedSpContactChanges {
    pub changes: SpContactChanges,
    pub signatures: Vec<[u8; 64]>,
}

impl SignedSpContactChanges {
    pub fn verify(&self, master_appkey: MasterAppkey, network: Network) -> bool {
        if !self.changes.is_well_formed() || self.signatures.len() != self.changes.set.changes.len()
        {
            return false;
        }
        let schnorr = Schnorr::<sha2::Sha256, _>::verify_only();
        self.changes
            .sign_items(network)
            .iter()
            .zip(&self.signatures)
            .all(|(item, signature)| {
                Signature::from_bytes(*signature).is_some_and(|signature| {
                    item.verify_final_signature(&schnorr, master_appkey, &signature)
                })
            })
    }

    /// The records this set adds, each with its own signature.
    pub fn added_contacts(&self, network: Network) -> Vec<SignedSpContact> {
        let added_at = self.changes.set.next_head(network);
        let mut account_ecdh = self.changes.account_ecdh.iter();
        self.changes
            .set
            .changes
            .iter()
            .zip(&self.signatures)
            .filter_map(|(change, signature)| match change {
                ContactChange::Add(details) => Some(SignedSpContact {
                    contact: SpContact {
                        details: details.clone(),
                        account_ecdh: *account_ecdh.next()?,
                    },
                    added_at,
                    signature: *signature,
                }),
                ContactChange::Remove(_) => None,
            })
            .collect()
    }
}

/// Why a change set can't apply to a book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeSetError {
    /// The set applies to another head.
    WrongHead,
    /// An empty set, an invalid name, or a name added or removed twice.
    Malformed,
    /// A remove of a contact the book doesn't have under that name and address.
    NoSuchContact,
    /// An add under a name still in use once the set's removes have applied.
    NameTaken,
}

impl core::fmt::Display for ChangeSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChangeSetError::WrongHead => write!(f, "The contacts changed since this was started"),
            ChangeSetError::Malformed => write!(f, "These contact changes are not valid"),
            ChangeSetError::NoSuchContact => {
                write!(f, "A contact to remove is not in this wallet's contacts")
            }
            ChangeSetError::NameTaken => {
                write!(f, "This wallet already has a contact with that name")
            }
        }
    }
}

/// A wallet's contacts: the fold of every signed change set it knows.
///
/// Starting from the empty head, the fold follows the longest branch of valid change sets. Each
/// set names the head the one before it produced. Of branches of equal length from one head, the
/// one whose first set has the smallest digest wins. A set that arrives late from an old head
/// can't displace a set that already has a descendant. A set that is invalid against the book at
/// its head is skipped the same way on every coordinator. A set whose head the fold hasn't reached
/// waits and applies once the sets before it arrive. A set for a head the fold has passed changes
/// nothing. A replayed old set can't bring back a removed contact.
#[derive(Clone, Debug, PartialEq)]
pub struct ContactBook {
    network: Network,
    /// Every signed change set this book knows, by digest. The caller checks each one's signatures
    /// before inserting it.
    sets: BTreeMap<[u8; 32], SignedSpContactChanges>,
    head: BookHead,
    /// The digests of the sets the fold applied, in order, and the heads it passed through from
    /// the empty one to `head`. `heads` is one longer than `applied`.
    applied: Vec<[u8; 32]>,
    heads: Vec<BookHead>,
    contacts: Vec<SignedSpContact>,
    /// Contacts removed on this coordinator only, by the head they were added at and their name.
    hidden: BTreeSet<(BookHead, String)>,
}

impl ContactBook {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            sets: Default::default(),
            head: BookHead::empty(),
            applied: Default::default(),
            heads: [BookHead::empty()].into(),
            contacts: Default::default(),
            hidden: Default::default(),
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn head(&self) -> BookHead {
        self.head
    }

    /// Adds a change set whose signatures the caller has checked, and folds the book again.
    /// Returns false if the book already had it.
    pub fn insert(&mut self, signed: SignedSpContactChanges) -> bool {
        let digest = signed.changes.set.digest(self.network);
        if self.sets.insert(digest, signed).is_some() {
            return false;
        }
        self.fold();
        true
    }

    pub fn contains(&self, set_digest: &[u8; 32]) -> bool {
        self.sets.contains_key(set_digest)
    }

    /// Whether `set` applies to the book as it is now.
    pub fn check(&self, set: &ContactChangeSet) -> Result<(), ChangeSetError> {
        if set.head != self.head {
            return Err(ChangeSetError::WrongHead);
        }
        apply(&self.contacts, set, &[]).map(|_| ())
    }

    /// Whether `head` is this book's head or one the fold passed on the way to it.
    pub fn has_passed(&self, head: &BookHead) -> bool {
        self.heads.get(head.version as usize) == Some(head)
    }

    /// Whether the fold applied the change set with digest `set_digest`.
    pub fn applied(&self, set_digest: &[u8; 32]) -> bool {
        self.applied.contains(set_digest)
    }

    /// The change sets the fold applied after `head`, in order. Empty unless it passed `head`.
    pub fn sets_after(&self, head: &BookHead) -> Vec<&SignedSpContactChanges> {
        if !self.has_passed(head) {
            return Vec::new();
        }
        self.applied[head.version as usize..]
            .iter()
            .map(|digest| &self.sets[digest])
            .collect()
    }

    /// Whether some change set waits for one this book doesn't have: its head is neither the empty
    /// head nor the head any known set produces. A set built on a set that lost to another from
    /// the same head never applies. It doesn't count as waiting: its head is known.
    pub fn is_waiting_for_missing_set(&self) -> bool {
        let produced = self
            .sets
            .iter()
            .map(|(digest, signed)| signed.changes.set.head.next(digest))
            .collect::<BTreeSet<_>>();
        self.sets.values().any(|signed| {
            let head = signed.changes.set.head;
            head != BookHead::empty() && !produced.contains(&head)
        })
    }

    fn fold(&mut self) {
        let (applied, contacts) = self.longest_branch(BookHead::empty(), &[]);
        let mut head = BookHead::empty();
        let mut heads = Vec::from([head]);
        for digest in &applied {
            head = head.next(digest);
            heads.push(head);
        }
        self.head = head;
        self.applied = applied;
        self.heads = heads;
        self.contacts = contacts;
    }

    /// The longest branch of valid sets from `head`, where the book holds `contacts`: the digests
    /// it applies in order and the contacts it ends with. Of branches of equal length, the one
    /// whose first set has the smallest digest wins. Each head is reached by one path through the
    /// hash chain. Every set is visited once.
    fn longest_branch(
        &self,
        head: BookHead,
        contacts: &[SignedSpContact],
    ) -> (Vec<[u8; 32]>, Vec<SignedSpContact>) {
        let mut best: Option<(Vec<[u8; 32]>, Vec<SignedSpContact>)> = None;
        // In digest order, so on a tie the first, smallest, stays.
        for (digest, signed) in self
            .sets
            .iter()
            .filter(|(_, signed)| signed.changes.set.head == head)
        {
            let added = signed.added_contacts(self.network);
            let Ok(next) = apply(contacts, &signed.changes.set, &added) else {
                continue;
            };
            let (rest, end) = self.longest_branch(head.next(digest), &next);
            if best
                .as_ref()
                .is_none_or(|(applied, _)| rest.len() + 1 > applied.len())
            {
                let mut applied = Vec::from([*digest]);
                applied.extend(rest);
                best = Some((applied, end));
            }
        }
        best.unwrap_or_else(|| (Vec::new(), contacts.to_vec()))
    }

    /// The signed sets that will never apply: a set on a branch that lost to a longer one (or to
    /// one of equal length whose first set has a smaller digest), anything built on it, and a set
    /// that is invalid where it applies. A set waiting for one this book doesn't have is not
    /// dropped. The app shows these and can ask for their changes again from the current head.
    pub fn dropped(&self) -> Vec<&SignedSpContactChanges> {
        let produced = self
            .sets
            .iter()
            .map(|(digest, signed)| signed.changes.set.head.next(digest))
            .collect::<BTreeSet<_>>();
        self.sets
            .iter()
            .filter(|(digest, signed)| {
                let head = signed.changes.set.head;
                !self.applied.contains(digest)
                    && (head == BookHead::empty() || produced.contains(&head))
            })
            .map(|(_, signed)| signed)
            .collect()
    }

    /// The contacts this coordinator shows and pays.
    pub fn contacts(&self) -> impl Iterator<Item = &SignedSpContact> {
        self.contacts
            .iter()
            .filter(|contact| !self.is_hidden(contact))
    }

    /// The contact named `name`, ignoring case.
    pub fn by_name(&self, name: &str) -> Option<&SignedSpContact> {
        self.contacts()
            .find(|contact| contact.contact.details.name.eq_ignore_ascii_case(name))
    }

    /// The contact with the address of `recipient`.
    pub fn by_address(&self, recipient: &SilentPaymentRecipient) -> Option<&SignedSpContact> {
        self.contacts()
            .find(|contact| contact.contact.details.recipient == *recipient)
    }

    /// Stops showing the contact named `name` on this coordinator only. The book and its head are
    /// unchanged, and the name stays in use for the fold. This is how a wallet with no nostr
    /// channel removes a contact. A nostr wallet removes one with a change set every coordinator in
    /// the group applies.
    pub fn hide(&mut self, name: &str) -> bool {
        let Some(contact) = self.by_name(name) else {
            return false;
        };
        let key = (contact.added_at, contact.contact.details.name.clone());
        self.hidden.insert(key)
    }

    fn is_hidden(&self, contact: &SignedSpContact) -> bool {
        self.hidden
            .contains(&(contact.added_at, contact.contact.details.name.clone()))
    }
}

/// `contacts` with `set` applied, where `added` are the signed records of its adds. Removes apply
/// before adds. An empty `added` checks the set without building its records.
fn apply(
    contacts: &[SignedSpContact],
    set: &ContactChangeSet,
    added: &[SignedSpContact],
) -> Result<Vec<SignedSpContact>, ChangeSetError> {
    if !set.is_well_formed() {
        return Err(ChangeSetError::Malformed);
    }
    let mut contacts = contacts.to_vec();
    for change in set.changes.iter().filter(|change| change.is_remove()) {
        let details = change.details();
        let position = contacts
            .iter()
            .position(|contact| {
                contact.contact.details.same_name(details)
                    && contact.contact.details.recipient == details.recipient
            })
            .ok_or(ChangeSetError::NoSuchContact)?;
        contacts.remove(position);
    }
    for details in set.adds() {
        if contacts
            .iter()
            .any(|contact| contact.contact.details.same_name(details))
        {
            return Err(ChangeSetError::NameTaken);
        }
    }
    contacts.extend_from_slice(added);
    Ok(contacts)
}
