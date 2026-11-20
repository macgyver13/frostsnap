//! The contact book a wallet's group shares over its signing channel, and the ceremonies that
//! change it.
//!
//! [`ContactSync`] takes the channel's [`ContactEvent`]s and this member's coordinator, and returns
//! what to publish and what to send to the local device. It does no IO, so the app runs it next to
//! its coordinator and tests run three of them against one another.
//!
//! - A ceremony starts with a `ContactRequest`. The user asks their device to confirm it
//!   ([`ContactSync::confirm`]), and once the device answers ([`ContactSync::device_confirmed`])
//!   the member publishes its offer and its book head.
//! - When the round confirms, a member whose offer is in the subset asks its device to sign, and
//!   publishes the signature share ([`ContactSync::got_share`]). Members outside the subset never
//!   sign.
//! - Any member that has every partial of a subset combines them and publishes the signed set,
//!   unless it was already published. Every member checks a published set against the wallet's
//!   key before it folds it into the book.
//! - A member announces its head when it has read the channel's history. A member that sees a
//!   head behind its own republishes the sets after it, after a short random delay the caller
//!   picks, skipping sets another member republished meanwhile. A head this book never passed, or
//!   a set waiting for a missing one, shows the book as syncing.

use super::events::ContactEvent;
use crate::{EventId, PublicKey};
use frostsnap_core::{
    coordinator::{
        remote_signing::{self, RemoteSignSessionId},
        remote_sp_contact::SpContactOffer,
        CoordinatorSend, FrostCoordinator, KeyContext, ParticipantBinonces,
        ParticipantSignatureShares, StartSignError,
    },
    message::signing::SpContactSessionId,
    schnorr_fun::frost::ShareIndex,
    silent_payments::{
        BookHead, ChangeSetError, ContactBook, ContactChange, ContactChangeSet,
        SignedSpContactChanges,
    },
    AccessStructureRef, DeviceId, SignSessionId, SymmetricKey, WireSignTask,
};
use std::collections::{BTreeMap, BTreeSet};

/// A head announced this long before the member started is history, and is not answered.
const HEAD_ANNOUNCEMENT_SLACK_SECS: u64 = 60;

/// Something for the caller to publish to the channel.
#[derive(Debug, Clone)]
pub enum ContactPublish {
    Offer {
        request_id: EventId,
        offer: SpContactOffer,
    },
    Partial {
        request_id: EventId,
        offer_subset: Vec<EventId>,
        signature_shares: ParticipantSignatureShares,
    },
    Changes(SignedSpContactChanges),
    Head(BookHead),
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ContactAction {
    Publish(ContactPublish),
    /// Ask the local device to confirm a change set.
    ToDevice(CoordinatorSend),
    /// Ask the local device to sign the confirmed set. Its share comes back as `GotShare` for
    /// `session_id`, which goes to [`ContactSync::got_share`].
    SignOnDevice {
        session_id: SignSessionId,
        send: CoordinatorSend,
    },
    /// Call [`ContactSync::republish_due`] with this head after a short random delay.
    ScheduleRepublish(BookHead),
}

/// Where a ceremony stands, from this member's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyStatus {
    /// The request applies to a head this book has not reached yet.
    Syncing,
    /// Collecting offers; `offers` of the `threshold` needed so far.
    WaitingForConfirmations { offers: usize, threshold: usize },
    /// The subset is locked in and its members are signing.
    Confirmed,
    /// This member's offer is in the subset, but its device forgot its approval before it signed:
    /// it restarted or was unplugged, or confirmed another change set since. The user confirms on
    /// the device again.
    PendingDeviceRestart,
    /// The signed set is in the book.
    Published,
    /// The requester cancelled, or the book moved on from the set's head without it.
    Dropped,
    /// An earlier request from the same head, `request_id`, is still open. Members don't confirm
    /// this one until that one is published, cancelled or dropped, so two sets from one head
    /// don't both get signed.
    BlockedByOpenRequest { request_id: EventId },
}

pub struct Ceremony {
    pub request_id: EventId,
    pub author: PublicKey,
    pub set: ContactChangeSet,
    pub timestamp: u64,
    offers: BTreeMap<EventId, SpContactOffer>,
    /// The member that made each offer.
    offered_by: BTreeMap<EventId, PublicKey>,
    /// The subset the round confirmed, with the task and session it signs.
    confirmed: Option<(Vec<EventId>, WireSignTask, SignSessionId)>,
    /// Signature shares by the offer subset they name.
    partials: BTreeMap<
        Vec<EventId>,
        (
            WireSignTask,
            BTreeMap<ShareIndex, ParticipantSignatureShares>,
        ),
    >,
    cancelled: bool,
    /// The local device asked to confirm, and the key to ask it with. In memory only, like the
    /// device's approval.
    device: Option<(DeviceId, SymmetricKey)>,
    device_confirmed: bool,
    our_offer: Option<EventId>,
    partial_sent: bool,
}

impl Ceremony {
    fn session_id(&self) -> SpContactSessionId {
        SpContactSessionId(self.request_id.0)
    }

    /// The members that offered, each once.
    pub fn offered_by(&self) -> BTreeSet<PublicKey> {
        self.offered_by.values().copied().collect()
    }

    fn our_offer_in_subset(&self) -> bool {
        match (&self.confirmed, self.our_offer) {
            (Some((subset, _, _)), Some(ours)) => subset.contains(&ours),
            _ => false,
        }
    }
}

pub struct ContactSync {
    key: KeyContext,
    access_structure_ref: AccessStructureRef,
    me: PublicKey,
    started_at: u64,
    history_synced: bool,
    ceremonies: BTreeMap<EventId, Ceremony>,
    /// The latest head each other member announced, with when.
    heads: BTreeMap<PublicKey, (u64, BookHead)>,
    /// Republishes waiting for their delay, by the head they answer, with the digests of the sets
    /// published since they were scheduled.
    republish: BTreeMap<BookHead, BTreeSet<[u8; 32]>>,
    /// The digests of every change set seen in the channel.
    published: BTreeSet<[u8; 32]>,
}

impl ContactSync {
    /// `me` is this member's nostr key, `started_at` when it connected, in unix seconds.
    pub fn new(key: KeyContext, me: PublicKey, started_at: u64) -> Self {
        Self {
            access_structure_ref: key.access_structure_ref(),
            key,
            me,
            started_at,
            history_synced: false,
            ceremonies: Default::default(),
            heads: Default::default(),
            republish: Default::default(),
            published: Default::default(),
        }
    }

    fn network(&self) -> bdk_chain::bitcoin::Network {
        self.key
            .purpose
            .bitcoin_network()
            .expect("contacts are only synced for a bitcoin key")
    }

    fn book(&self, coord: &FrostCoordinator) -> ContactBook {
        coord
            .sp_contact_book(self.access_structure_ref.key_id)
            .cloned()
            .unwrap_or_else(|| ContactBook::new(self.network()))
    }

    /// A change set of `changes` against the book as it is now, checked so a request the group
    /// can't apply is never published.
    pub fn new_change_set(
        &self,
        coord: &FrostCoordinator,
        changes: Vec<ContactChange>,
    ) -> Result<ContactChangeSet, ChangeSetError> {
        let book = self.book(coord);
        let set = ContactChangeSet {
            head: book.head(),
            changes,
        };
        book.check(&set)?;
        Ok(set)
    }

    pub fn ceremonies(&self) -> impl Iterator<Item = &Ceremony> {
        self.ceremonies.values()
    }

    /// Whether the book is behind what the group has: another member announced a head this book
    /// never passed, or a set waits for one this book doesn't have.
    pub fn is_syncing(&self, coord: &FrostCoordinator) -> bool {
        let book = self.book(coord);
        book.is_waiting_for_missing_set()
            || self.heads.values().any(|(_, head)| !book.has_passed(head))
    }

    pub fn status(&self, coord: &FrostCoordinator, request_id: EventId) -> Option<CeremonyStatus> {
        let book = self.book(coord);
        let status = self.status_in(&book, request_id)?;
        if !matches!(status, CeremonyStatus::WaitingForConfirmations { .. }) {
            return Some(status);
        }
        let ceremony = &self.ceremonies[&request_id];
        let earlier_open = self
            .ceremonies
            .values()
            .filter(|other| {
                other.set.head == ceremony.set.head
                    && (other.timestamp, other.request_id) < (ceremony.timestamp, request_id)
            })
            .find(|other| {
                !matches!(
                    self.status_in(&book, other.request_id),
                    Some(CeremonyStatus::Published | CeremonyStatus::Dropped)
                )
            });
        Some(match earlier_open {
            Some(other) => CeremonyStatus::BlockedByOpenRequest {
                request_id: other.request_id,
            },
            None => status,
        })
    }

    /// The status of `request_id` on its own, without looking at other requests.
    fn status_in(&self, book: &ContactBook, request_id: EventId) -> Option<CeremonyStatus> {
        let ceremony = self.ceremonies.get(&request_id)?;
        let digest = ceremony.set.digest(self.network());
        Some(if book.applied(&digest) {
            CeremonyStatus::Published
        } else if ceremony.cancelled
            || (book.has_passed(&ceremony.set.head) && ceremony.set.head != book.head())
        {
            CeremonyStatus::Dropped
        } else if !book.has_passed(&ceremony.set.head) {
            CeremonyStatus::Syncing
        } else if ceremony.confirmed.is_none() {
            CeremonyStatus::WaitingForConfirmations {
                offers: ceremony.offers.len(),
                threshold: self.key.threshold(),
            }
        } else if ceremony.our_offer_in_subset()
            && !ceremony.device_confirmed
            && !ceremony.partial_sent
        {
            CeremonyStatus::PendingDeviceRestart
        } else {
            CeremonyStatus::Confirmed
        })
    }

    pub fn on_event(
        &mut self,
        coord: &mut FrostCoordinator,
        event: ContactEvent,
    ) -> Vec<ContactAction> {
        let mut actions = Vec::new();
        match event {
            ContactEvent::Request {
                event_id,
                author,
                set,
                timestamp,
            } => {
                // A requester whose book is behind is answered like a head behind.
                if author != self.me && self.is_live(timestamp) {
                    actions.extend(self.answer_head(coord, set.head));
                }
                self.ceremonies.entry(event_id).or_insert(Ceremony {
                    request_id: event_id,
                    author,
                    set,
                    timestamp,
                    offers: Default::default(),
                    offered_by: Default::default(),
                    confirmed: None,
                    partials: Default::default(),
                    cancelled: false,
                    device: None,
                    device_confirmed: false,
                    our_offer: None,
                    partial_sent: false,
                });
            }
            ContactEvent::Offer {
                event_id,
                author,
                request_id,
                offer,
                ..
            } => {
                if let Some(ceremony) = self.ceremonies.get_mut(&request_id) {
                    ceremony.offers.insert(event_id, offer);
                    ceremony.offered_by.insert(event_id, author);
                    if author == self.me {
                        ceremony.our_offer = Some(event_id);
                    }
                }
            }
            ContactEvent::RoundConfirmed {
                request_id,
                subset,
                session_id,
                sign_task,
                ..
            } => {
                if let Some(ceremony) = self.ceremonies.get_mut(&request_id) {
                    let subset = subset.iter().map(|entry| entry.event_id).collect();
                    ceremony.confirmed = Some((subset, sign_task, session_id));
                }
                match self.try_sign(coord, request_id) {
                    Ok(sign) => actions.extend(sign),
                    Err(e) => {
                        tracing::warn!(%request_id, error = ?e, "could not ask the device to sign contact changes");
                    }
                }
            }
            ContactEvent::RoundPending { .. } | ContactEvent::Rejected { .. } => {}
            ContactEvent::Partial {
                author,
                request_id,
                offer_subset,
                sign_task,
                signature_shares,
                ..
            } => {
                if let Some(ceremony) = self.ceremonies.get_mut(&request_id) {
                    if author == self.me {
                        ceremony.partial_sent = true;
                    }
                    ceremony
                        .partials
                        .entry(offer_subset.clone())
                        .or_insert_with(|| (sign_task, Default::default()))
                        .1
                        .insert(signature_shares.share_index, signature_shares);
                }
                actions.extend(self.try_combine(coord, request_id, &offer_subset));
            }
            ContactEvent::Cancel { request_id, .. } => {
                if let Some(ceremony) = self.ceremonies.get_mut(&request_id) {
                    ceremony.cancelled = true;
                }
            }
            ContactEvent::Changes { signed, .. } => {
                let digest = signed.changes.set.digest(self.network());
                match coord.add_sp_contact_changes(self.access_structure_ref.key_id, signed) {
                    Ok(()) => {
                        self.published.insert(digest);
                        for skip in self.republish.values_mut() {
                            skip.insert(digest);
                        }
                    }
                    Err(reason) => {
                        tracing::warn!(%reason, "contact changes refused");
                    }
                }
            }
            ContactEvent::BookHead {
                author,
                head,
                timestamp,
                ..
            } => {
                if author != self.me {
                    let newer = self
                        .heads
                        .get(&author)
                        .is_none_or(|(seen_at, _)| *seen_at <= timestamp);
                    if newer {
                        self.heads.insert(author, (timestamp, head));
                    }
                    if newer && self.is_live(timestamp) {
                        actions.extend(self.answer_head(coord, head));
                    }
                }
            }
            ContactEvent::HistorySynced => {
                if !self.history_synced {
                    self.history_synced = true;
                    // Partials read from the history are combined only now, once every set the
                    // history holds is known, so a set already published isn't published again.
                    let complete = self
                        .ceremonies
                        .values()
                        .flat_map(|ceremony| {
                            ceremony
                                .partials
                                .keys()
                                .map(|subset| (ceremony.request_id, subset.clone()))
                        })
                        .collect::<Vec<_>>();
                    for (request_id, subset) in complete {
                        actions.extend(self.try_combine(coord, request_id, &subset));
                    }
                    actions.push(ContactAction::Publish(ContactPublish::Head(
                        self.book(coord).head(),
                    )));
                }
            }
        }
        self.settle(coord);
        actions
    }

    /// Whether an event published at `timestamp` is live: read after the history, and not much
    /// older than this member's start. A head from the history is not answered, since the member
    /// that announced it may have moved on.
    fn is_live(&self, timestamp: u64) -> bool {
        self.history_synced && timestamp + HEAD_ANNOUNCEMENT_SLACK_SECS >= self.started_at
    }

    /// Schedules a republish of the sets after `head`, once, if this book has passed it.
    fn answer_head(&mut self, coord: &FrostCoordinator, head: BookHead) -> Option<ContactAction> {
        let book = self.book(coord);
        if head == book.head() || !book.has_passed(&head) || self.republish.contains_key(&head) {
            return None;
        }
        self.republish.insert(head, Default::default());
        Some(ContactAction::ScheduleRepublish(head))
    }

    /// Asks `device_id` to confirm the change set of `request_id`, or to confirm it again after it
    /// forgot its approval. Refused with `WrongHead` while the request is ahead of this book.
    pub fn confirm(
        &mut self,
        coord: &mut FrostCoordinator,
        request_id: EventId,
        device_id: DeviceId,
        encryption_key: SymmetricKey,
    ) -> Result<Vec<ContactAction>, StartSignError> {
        match self.status(coord, request_id) {
            None => return Err(StartSignError::NoSuchSpContactSession),
            Some(CeremonyStatus::Syncing) => {
                return Err(StartSignError::SpContactChanges(ChangeSetError::WrongHead))
            }
            Some(
                CeremonyStatus::WaitingForConfirmations { .. }
                | CeremonyStatus::PendingDeviceRestart,
            ) => {}
            Some(
                CeremonyStatus::Confirmed | CeremonyStatus::Published | CeremonyStatus::Dropped,
            ) => {
                return Err(StartSignError::InvalidSpContactOffer(
                    "these contact changes no longer need this device",
                ))
            }
            Some(CeremonyStatus::BlockedByOpenRequest { .. }) => {
                return Err(StartSignError::InvalidSpContactOffer(
                    "an earlier request for changes to this book is still open",
                ))
            }
        }
        let ceremony = self
            .ceremonies
            .get_mut(&request_id)
            .expect("status found it");
        // The device keeps one approval, so the shares it gave for any other set are void.
        coord.forget_sp_contact_shares_from(device_id);
        let send = match ceremony.device {
            Some((asked, _)) if asked == device_id => {
                coord.request_sp_contact_ecdh(ceremony.session_id(), device_id, encryption_key)?
            }
            _ => coord.start_remote_sp_contact(
                ceremony.session_id(),
                self.access_structure_ref,
                ceremony.set.clone(),
                device_id,
                encryption_key,
            )?,
        };
        ceremony.device = Some((device_id, encryption_key));
        // A device keeps one approval, so asking it about this set forgets any other.
        for ceremony in self.ceremonies.values_mut() {
            if ceremony.device.is_some_and(|(asked, _)| asked == device_id) {
                ceremony.device_confirmed = false;
            }
        }
        Ok(vec![ContactAction::ToDevice(send)])
    }

    /// The local device answered with its ECDH shares. The first time, the member publishes its
    /// offer and its head. After the device confirmed again, it signs if the round is waiting
    /// for it.
    pub fn device_confirmed(
        &mut self,
        coord: &mut FrostCoordinator,
        request_id: EventId,
    ) -> Result<Vec<ContactAction>, StartSignError> {
        let ceremony = self
            .ceremonies
            .get_mut(&request_id)
            .ok_or(StartSignError::NoSuchSpContactSession)?;
        ceremony.device_confirmed = true;
        if ceremony.our_offer.is_some() {
            let sign = self.try_sign(coord, request_id);
            if sign.is_err() {
                // It can't sign, so the ceremony still waits on this member.
                if let Some(ceremony) = self.ceremonies.get_mut(&request_id) {
                    ceremony.device_confirmed = false;
                }
            }
            return sign;
        }
        let offer = coord.offer_remote_sp_contact(ceremony.session_id())?;
        Ok(vec![
            ContactAction::Publish(ContactPublish::Offer { request_id, offer }),
            ContactAction::Publish(ContactPublish::Head(self.book(coord).head())),
        ])
    }

    /// The local device disconnected, and with it went its approvals.
    pub fn device_disconnected(&mut self, device_id: DeviceId) {
        for ceremony in self.ceremonies.values_mut() {
            if ceremony.device.is_some_and(|(asked, _)| asked == device_id) {
                ceremony.device_confirmed = false;
            }
        }
    }

    /// The local device signed. Publishes its signature share for the ceremony whose session it
    /// belongs to.
    pub fn got_share(
        &mut self,
        session_id: SignSessionId,
        signature_shares: ParticipantSignatureShares,
    ) -> Vec<ContactAction> {
        let Some(ceremony) = self
            .ceremonies
            .values()
            .find(|ceremony| matches!(&ceremony.confirmed, Some((_, _, id)) if *id == session_id))
        else {
            return vec![];
        };
        let (subset, _, _) = ceremony.confirmed.clone().expect("found by it");
        vec![ContactAction::Publish(ContactPublish::Partial {
            request_id: ceremony.request_id,
            offer_subset: subset,
            signature_shares,
        })]
    }

    /// Publishes the sets after `head`, the head another member announced, unless another member
    /// republished them since.
    pub fn republish_due(
        &mut self,
        coord: &FrostCoordinator,
        head: BookHead,
    ) -> Vec<ContactAction> {
        let Some(skip) = self.republish.remove(&head) else {
            return vec![];
        };
        let network = self.network();
        self.book(coord)
            .sets_after(&head)
            .into_iter()
            .filter(|signed| !skip.contains(&signed.changes.set.digest(network)))
            .map(|signed| ContactAction::Publish(ContactPublish::Changes(signed.clone())))
            .collect()
    }

    /// Asks the local device to sign if the round waits for it. Fails if this coordinator can't
    /// build the request, for example after an app restart lost the nonces its offer reserved.
    fn try_sign(
        &mut self,
        coord: &mut FrostCoordinator,
        request_id: EventId,
    ) -> Result<Vec<ContactAction>, StartSignError> {
        let Some(ceremony) = self.ceremonies.get(&request_id) else {
            return Ok(vec![]);
        };
        let Some((subset, _, _)) = &ceremony.confirmed else {
            return Ok(vec![]);
        };
        let Some((_, encryption_key)) = ceremony.device else {
            return Ok(vec![]);
        };
        if !ceremony.our_offer_in_subset() || !ceremony.device_confirmed || ceremony.partial_sent {
            return Ok(vec![]);
        }
        let offers = subset
            .iter()
            .map(|event_id| ceremony.offers[event_id].clone())
            .collect::<Vec<_>>();
        let request =
            coord.sign_remote_sp_contact(ceremony.session_id(), &offers, encryption_key)?;
        Ok(vec![ContactAction::SignOnDevice {
            session_id: request.request_sign.group_sign_req.session_id(),
            send: request.into(),
        }])
    }

    /// Combines the partials of `offer_subset` once there is one from every offer in it, and
    /// publishes the signed set unless it was published already.
    fn try_combine(
        &mut self,
        coord: &FrostCoordinator,
        request_id: EventId,
        offer_subset: &[EventId],
    ) -> Vec<ContactAction> {
        let Some(ceremony) = self.ceremonies.get(&request_id) else {
            return vec![];
        };
        if !self.history_synced {
            return vec![];
        }
        let Some((sign_task, shares)) = ceremony.partials.get(offer_subset) else {
            return vec![];
        };
        let binonces = offer_subset
            .iter()
            .map(|event_id| ceremony.offers[event_id].participant_binonces.clone())
            .collect::<Vec<ParticipantBinonces>>();
        if binonces
            .iter()
            .any(|binonces| !shares.contains_key(&binonces.share_index))
        {
            return vec![];
        }
        let digest = ceremony.set.digest(self.network());
        if self.published.contains(&digest) || self.book(coord).contains(&digest) {
            return vec![];
        }
        let WireSignTask::SpContactChanges(changes) = sign_task else {
            return vec![];
        };
        let shares = shares.values().collect::<Vec<_>>();
        match remote_signing::combine_signatures(sign_task.clone(), &self.key, &binonces, &shares) {
            Ok(signatures) => vec![ContactAction::Publish(ContactPublish::Changes(
                SignedSpContactChanges {
                    changes: (**changes).clone(),
                    signatures: signatures.iter().map(|signature| signature.0).collect(),
                },
            ))],
            Err(e) => {
                tracing::warn!(%request_id, error = ?e, "contact partials do not combine");
                vec![]
            }
        }
    }

    /// Frees the nonces of this member's sessions for ceremonies that are over.
    fn settle(&mut self, coord: &mut FrostCoordinator) {
        let over = self
            .ceremonies
            .keys()
            .copied()
            .filter(|request_id| {
                matches!(
                    self.status(coord, *request_id),
                    Some(CeremonyStatus::Published | CeremonyStatus::Dropped)
                )
            })
            .collect::<Vec<_>>();
        for request_id in over {
            let ceremony = self.ceremonies.get_mut(&request_id).expect("listed above");
            if ceremony.device.take().is_some() {
                coord.cancel_sp_contact(ceremony.session_id());
                coord.cancel_remote_sign_session(RemoteSignSessionId(request_id.0));
                ceremony.device_confirmed = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_runner::EventMeta;
    use crate::signing::events::{SigningMessage, WireEventId};
    use crate::signing::ingest_signing_message;
    use crate::signing::test_group::{details, Group};
    use crate::signing::tree::{SigningEventTree, TreeEvent};
    use frostsnap_core::test::TEST_ENCRYPTION_KEY;
    use nostr_sdk::Keys;

    const SETTLING: std::time::Duration = std::time::Duration::from_secs(4);
    const T0: u64 = 1_000_000;

    /// A channel message as it was published, kept so a member that comes online later reads it
    /// as history.
    #[derive(Clone)]
    struct Published {
        meta: EventMeta,
        bytes: Vec<u8>,
        reply_to: Option<EventId>,
    }

    struct Member {
        sync: ContactSync,
        tree: SigningEventTree,
        online: bool,
        /// How many events of the log this member has read.
        read: usize,
        /// Republishes the member scheduled and has not run yet.
        scheduled: Vec<BookHead>,
    }

    /// Three members of a 2-of-3 wallet on one channel. Each publish is encoded, decoded and fed
    /// through every online member's tree and driver, as the channel runner does.
    struct Net {
        group: Group,
        keys: Vec<PublicKey>,
        members: Vec<Member>,
        log: Vec<Published>,
        /// Log entries the relays lost: never delivered to a member that reads them later.
        lost: BTreeSet<usize>,
        /// Members whose publishes the relays lose.
        muted: BTreeSet<usize>,
        clock: u64,
        next_id: u8,
    }

    impl Net {
        fn new(nonce_streams: usize) -> Self {
            let group = Group::new(nonce_streams);
            let key = group.key_context();
            let keys = (0..3)
                .map(|_| PublicKey::from(Keys::generate().public_key()))
                .collect::<Vec<_>>();
            let members = keys
                .iter()
                .map(|pk| Member {
                    sync: ContactSync::new(key.clone(), *pk, T0),
                    tree: SigningEventTree::new(key.clone(), SETTLING),
                    online: false,
                    read: 0,
                    scheduled: vec![],
                })
                .collect();
            let mut net = Self {
                group,
                keys,
                members,
                log: vec![],
                lost: Default::default(),
                muted: Default::default(),
                clock: T0,
                next_id: 0,
            };
            for ci in 0..3 {
                net.connect(ci);
            }
            net
        }

        /// The member starts a fresh channel client, as the app does: it reads the whole history,
        /// then announces its head. Only its coordinator carries over.
        fn connect(&mut self, ci: usize) {
            let key = self.group.key_context();
            self.members[ci] = Member {
                sync: ContactSync::new(key.clone(), self.keys[ci], self.clock),
                tree: SigningEventTree::new(key, SETTLING),
                online: true,
                read: 0,
                scheduled: vec![],
            };
            while self.members[ci].read < self.log.len() {
                let index = self.members[ci].read;
                self.members[ci].read += 1;
                if !self.lost.contains(&index) {
                    let event = self.log[index].clone();
                    self.deliver(ci, event);
                }
            }
            self.react(ci, ContactEvent::HistorySynced);
        }

        fn disconnect(&mut self, ci: usize) {
            self.members[ci].online = false;
        }

        fn publish(
            &mut self,
            ci: usize,
            message: SigningMessage,
            reply_to: Option<EventId>,
        ) -> EventId {
            self.clock += 1;
            self.next_id += 1;
            let mut id = [0u8; 32];
            id[0] = self.next_id;
            let event_id = EventId(id);
            let bytes = bincode::encode_to_vec(&message, bincode::config::standard()).unwrap();
            self.log.push(Published {
                meta: EventMeta {
                    event_id,
                    author: self.keys[ci],
                    timestamp: self.clock,
                },
                bytes,
                reply_to,
            });
            if self.muted.contains(&ci) {
                self.lost.insert(self.log.len() - 1);
            }
            self.pump();
            event_id
        }

        /// Delivers the log to every online member that has not read it.
        fn pump(&mut self) {
            for ci in 0..3 {
                while self.members[ci].online && self.members[ci].read < self.log.len() {
                    let index = self.members[ci].read;
                    self.members[ci].read += 1;
                    if !self.lost.contains(&index) {
                        let event = self.log[index].clone();
                        self.deliver(ci, event);
                    }
                }
            }
        }

        fn deliver(&mut self, ci: usize, event: Published) {
            let (message, _) =
                bincode::decode_from_slice(&event.bytes, bincode::config::standard()).unwrap();
            let (events, _) = ingest_signing_message(
                &mut self.members[ci].tree,
                event.meta,
                message,
                event.reply_to,
            )
            .unwrap();
            for event in events {
                if let TreeEvent::Contact(event) = event {
                    self.react(ci, event);
                }
            }
        }

        fn react(&mut self, ci: usize, event: ContactEvent) {
            let member = &mut self.members[ci];
            let actions = member
                .sync
                .on_event(&mut self.group.run.participants[ci].coordinator, event);
            self.act(ci, actions);
        }

        /// Does what the app does with the driver's actions.
        fn act(&mut self, ci: usize, actions: Vec<ContactAction>) {
            for action in actions {
                match action {
                    ContactAction::Publish(publish) => {
                        let (message, reply_to) = match publish {
                            ContactPublish::Offer { request_id, offer } => (
                                SigningMessage::ContactOffer {
                                    binonces: offer.participant_binonces,
                                    shares: offer.shares,
                                },
                                Some(request_id),
                            ),
                            ContactPublish::Partial {
                                request_id,
                                offer_subset,
                                signature_shares,
                            } => (
                                SigningMessage::Partial {
                                    offer_subset: offer_subset
                                        .into_iter()
                                        .map(WireEventId::from)
                                        .collect(),
                                    signature_shares,
                                },
                                Some(request_id),
                            ),
                            ContactPublish::Changes(signed) => {
                                (SigningMessage::ContactChanges { signed }, None)
                            }
                            ContactPublish::Head(head) => (SigningMessage::BookHead { head }, None),
                        };
                        self.publish(ci, message, reply_to);
                    }
                    ContactAction::ToDevice(send) => {
                        self.group.run.extend_from_coordinator(ci, [send]);
                        self.group.settle();
                    }
                    ContactAction::SignOnDevice { session_id, send } => {
                        self.group.run.extend_from_coordinator(ci, [send]);
                        self.group.settle();
                        if let Some(shares) = self.group.env.shares.remove(&(ci, session_id)) {
                            let actions = self.members[ci].sync.got_share(session_id, shares);
                            self.act(ci, actions);
                        }
                    }
                    ContactAction::ScheduleRepublish(head) => {
                        self.members[ci].scheduled.push(head);
                    }
                }
            }
        }

        fn coord(&mut self, ci: usize) -> &mut FrostCoordinator {
            &mut self.group.run.participants[ci].coordinator
        }

        fn request(&mut self, ci: usize, changes: Vec<ContactChange>) -> EventId {
            let set = self.members[ci]
                .sync
                .new_change_set(&self.group.run.participants[ci].coordinator, changes)
                .unwrap();
            self.publish(ci, SigningMessage::ContactRequest { set }, None)
        }

        /// Member `ci`'s device confirms the request, and the member offers.
        fn confirm(&mut self, ci: usize, request_id: EventId) -> Result<(), StartSignError> {
            let device = self.group.device(ci);
            let actions = self.members[ci].sync.confirm(
                &mut self.group.run.participants[ci].coordinator,
                request_id,
                device,
                TEST_ENCRYPTION_KEY,
            )?;
            self.act(ci, actions);
            let actions = self.members[ci]
                .sync
                .device_confirmed(&mut self.group.run.participants[ci].coordinator, request_id)?;
            self.act(ci, actions);
            Ok(())
        }

        /// The settling timer fires on every online member.
        fn settle_round(&mut self, request_id: EventId) {
            for ci in 0..3 {
                if !self.members[ci].online {
                    continue;
                }
                if let Some(TreeEvent::Contact(event)) =
                    self.members[ci].tree.timer_expired(request_id)
                {
                    self.react(ci, event);
                }
            }
        }

        fn status(&self, ci: usize, request_id: EventId) -> CeremonyStatus {
            self.members[ci]
                .sync
                .status(&self.group.run.participants[ci].coordinator, request_id)
                .unwrap()
        }

        fn syncing(&self, ci: usize) -> bool {
            self.members[ci]
                .sync
                .is_syncing(&self.group.run.participants[ci].coordinator)
        }

        fn head(&self, ci: usize) -> BookHead {
            self.group.run.participants[ci]
                .coordinator
                .sp_contact_book_head(self.group.key_id())
        }

        fn names(&self, ci: usize) -> Vec<String> {
            self.group.run.participants[ci]
                .coordinator
                .sp_contacts(self.group.key_id())
                .map(|contact| contact.contact.details.name.clone())
                .collect()
        }

        fn changes_published(&self) -> usize {
            self.count(|message| matches!(message, SigningMessage::ContactChanges { .. }))
        }

        fn count(&self, f: impl Fn(&SigningMessage) -> bool) -> usize {
            self.log
                .iter()
                .filter(|event| {
                    bincode::decode_from_slice::<SigningMessage, _>(
                        &event.bytes,
                        bincode::config::standard(),
                    )
                    .is_ok_and(|(message, _)| f(&message))
                })
                .count()
        }
    }

    fn add(name: &str, byte: u8) -> ContactChange {
        ContactChange::Add(details(name, byte, byte + 1))
    }

    /// Member 0 asks for two contacts and goes offline. Members 1 and 2 confirm and sign, and one
    /// of them publishes the signed set. Member 1's device restarts between its offer and the
    /// round confirming, so the ceremony waits until it confirms again. Member 0 finds the
    /// contacts in the channel when it comes back.
    #[test]
    fn a_ceremony_is_published_while_the_requester_is_offline() {
        let mut net = Net::new(2);
        let request_id = net.request(0, vec![add("Ann", 0x11), add("Ben", 0x21)]);
        net.disconnect(0);
        net.confirm(1, request_id).unwrap();
        net.confirm(2, request_id).unwrap();
        assert_eq!(
            net.status(1, request_id),
            CeremonyStatus::WaitingForConfirmations {
                offers: 2,
                threshold: 2
            }
        );
        let ceremony = net.members[1]
            .sync
            .ceremonies()
            .find(|ceremony| ceremony.request_id == request_id)
            .unwrap();
        assert_eq!(
            ceremony.offered_by(),
            BTreeSet::from([net.keys[1], net.keys[2]])
        );

        let device = net.group.device(1);
        net.group.run.participants[1]
            .devices
            .get_mut(&device)
            .unwrap()
            .clear_tmp_data();
        net.coord(1).forget_sp_contact_shares_from(device);
        net.members[1].sync.device_disconnected(device);

        net.settle_round(request_id);
        assert_eq!(
            net.status(1, request_id),
            CeremonyStatus::PendingDeviceRestart
        );
        assert_eq!(net.status(2, request_id), CeremonyStatus::Confirmed);
        assert_eq!(net.changes_published(), 0);

        net.confirm(1, request_id).unwrap();
        // Both signers see every partial, and each publishes unless it saw the other's first.
        let published = net.changes_published();
        assert!(published >= 1);
        for ci in [1, 2] {
            assert_eq!(net.status(ci, request_id), CeremonyStatus::Published);
            assert_eq!(net.names(ci), ["Ann", "Ben"]);
        }

        net.connect(0);
        assert_eq!(net.status(0, request_id), CeremonyStatus::Published);
        assert_eq!(net.head(0), net.head(1));
        assert_eq!(net.names(0), ["Ann", "Ben"]);
        assert!(!net.syncing(0));
        // A member that comes back reads the ceremony as history and does not publish it again.
        assert_eq!(net.changes_published(), published);
    }

    /// The relays lost the signed set and its partials before member 0 read them. Member 0
    /// announces the empty head
    /// when it connects, both other members schedule a republish, and the second one to run
    /// skips the set the first one republished.
    #[test]
    fn a_head_behind_is_answered_with_the_sets_after_it() {
        let mut net = Net::new(2);
        net.disconnect(0);
        let request_id = net.request(1, vec![add("Cat", 0x31)]);
        net.confirm(1, request_id).unwrap();
        net.confirm(2, request_id).unwrap();
        net.settle_round(request_id);
        let published = net.changes_published();
        assert!(published >= 1);
        for (index, event) in net.log.iter().enumerate() {
            if matches!(
                bincode::decode_from_slice(&event.bytes, bincode::config::standard()),
                Ok((
                    SigningMessage::ContactChanges { .. } | SigningMessage::Partial { .. },
                    _
                ))
            ) {
                net.lost.insert(index);
            }
        }

        net.connect(0);
        assert_eq!(net.head(0), BookHead::empty());
        assert_eq!(net.members[1].scheduled, [BookHead::empty()]);
        assert_eq!(net.members[2].scheduled, [BookHead::empty()]);
        // Member 1 announces its head, as it does with each offer: member 0 sees it is behind.
        let head = net.head(1);
        net.publish(1, SigningMessage::BookHead { head }, None);
        assert!(net.syncing(0));
        assert!(!net.syncing(2));

        for ci in [2, 1] {
            let head = net.members[ci].scheduled.pop().unwrap();
            let actions = net.members[ci]
                .sync
                .republish_due(&net.group.run.participants[ci].coordinator, head);
            net.act(ci, actions);
        }
        assert_eq!(net.changes_published(), published + 1);
        assert_eq!(net.head(0), net.head(1));
        assert_eq!(net.names(0), ["Cat"]);
        assert!(!net.syncing(0));
        // Nobody answers the republished set with another head or set.
        assert!(net.members.iter().all(|member| member.scheduled.is_empty()));
    }

    /// When all three confirm, only the two members whose offers the round picked sign.
    #[test]
    fn members_outside_the_subset_never_sign() {
        let mut net = Net::new(2);
        let request_id = net.request(0, vec![add("Nan", 0x91)]);
        for ci in 0..3 {
            net.confirm(ci, request_id).unwrap();
        }
        net.settle_round(request_id);
        assert_eq!(
            net.count(|message| matches!(message, SigningMessage::Partial { .. })),
            2
        );
        for ci in 0..3 {
            assert_eq!(net.status(ci, request_id), CeremonyStatus::Published);
        }
    }

    /// The app restarts after its offer: its reserved nonces were in memory, so it can no longer
    /// sign for the subset its offer is in, and confirming again says why.
    // FIXME: the round is locked with this member in it, so the ceremony can't finish; the
    // requester has to cancel and ask again. Persisting the offer's nonces is a design question.
    #[test]
    fn an_app_restart_after_offering_cannot_sign() {
        let mut net = Net::new(2);
        let request_id = net.request(0, vec![add("Oli", 0xa1)]);
        net.confirm(0, request_id).unwrap();
        net.confirm(1, request_id).unwrap();
        net.disconnect(1);
        net.coord(1).clear_tmp_data();
        net.settle_round(request_id);
        net.connect(1);
        net.settle_round(request_id);
        assert_eq!(
            net.status(1, request_id),
            CeremonyStatus::PendingDeviceRestart
        );
        assert!(matches!(
            net.confirm(1, request_id),
            Err(StartSignError::InvalidSpContactOffer(_))
        ));
        assert_eq!(
            net.status(1, request_id),
            CeremonyStatus::PendingDeviceRestart
        );
    }

    /// A request from a member whose book is behind is answered with the sets it is missing, as
    /// a head behind is, and that member's own request is then dropped.
    #[test]
    fn a_stale_requester_is_answered_with_the_sets_it_missed() {
        let mut net = Net::new(2);
        net.disconnect(0);
        let landed = net.request(1, vec![add("Pia", 0xb1)]);
        net.confirm(1, landed).unwrap();
        net.confirm(2, landed).unwrap();
        net.settle_round(landed);
        for (index, event) in net.log.iter().enumerate() {
            if matches!(
                bincode::decode_from_slice(&event.bytes, bincode::config::standard()),
                Ok((
                    SigningMessage::ContactChanges { .. } | SigningMessage::Partial { .. },
                    _
                ))
            ) {
                net.lost.insert(index);
            }
        }
        // Member 0's head announcement is lost too, so only its request shows it is behind.
        net.muted.insert(0);
        net.connect(0);
        net.muted.clear();
        assert!(net.members[1].scheduled.is_empty());

        let stale = net.request(0, vec![add("Quin", 0xb3)]);
        assert_eq!(net.members[1].scheduled, [BookHead::empty()]);
        let head = net.members[1].scheduled.pop().unwrap();
        let actions = net.members[1]
            .sync
            .republish_due(&net.group.run.participants[1].coordinator, head);
        net.act(1, actions);
        assert_eq!(net.head(0), net.head(1));
        assert_eq!(net.names(0), ["Pia"]);
        assert_eq!(net.status(0, stale), CeremonyStatus::Dropped);
    }

    /// Republishing an old set after a later one removed its contact changes nothing.
    #[test]
    fn a_replayed_change_set_is_harmless() {
        let mut net = Net::new(2);
        let add_dee = net.request(0, vec![add("Dee", 0x41)]);
        net.confirm(0, add_dee).unwrap();
        net.confirm(1, add_dee).unwrap();
        net.settle_round(add_dee);
        let signed_add = net.group.run.participants[0]
            .coordinator
            .sp_contact_book(net.group.key_id())
            .unwrap()
            .sets_after(&BookHead::empty())[0]
            .clone();

        let remove_dee = net.request(2, vec![ContactChange::Remove(details("Dee", 0x41, 0x42))]);
        net.confirm(1, remove_dee).unwrap();
        net.confirm(2, remove_dee).unwrap();
        net.settle_round(remove_dee);
        let head = net.head(0);
        assert_eq!(head.version, 2);
        assert!(net.names(0).is_empty());

        net.publish(
            0,
            SigningMessage::ContactChanges { signed: signed_add },
            None,
        );
        for ci in 0..3 {
            assert_eq!(net.head(ci), head);
            assert!(net.names(ci).is_empty());
            assert!(!net.syncing(ci));
        }
    }

    /// A set of five adds costs each confirming device five nonces, from one stream it holds until
    /// the ceremony is over. With its only stream held by a remote send it offered on, a device
    /// can't offer until the coordinator tops its nonces up.
    #[test]
    fn five_adds_cost_five_nonces_and_a_top_up_frees_a_stream() {
        let mut net = Net::new(1);
        let device = net.group.device(1);
        let before = net.coord(1).nonces_available(device);
        assert_eq!(before.len(), 1);
        let asref = net.group.access_structure_ref;
        net.coord(1)
            .offer_to_sign(
                RemoteSignSessionId([0x55; 32]),
                asref,
                WireSignTask::Test {
                    message: "a send".into(),
                },
                device,
            )
            .unwrap();

        let five = net.request(
            0,
            vec![
                add("Eve", 0x51),
                add("Fay", 0x53),
                add("Gus", 0x55),
                add("Hal", 0x57),
                add("Ivy", 0x59),
            ],
        );
        assert!(matches!(
            net.confirm(1, five),
            Err(StartSignError::NotEnoughNoncesForDevice(_))
        ));
        let top_up = net.group.run.participants[1]
            .coordinator
            .maybe_request_nonce_replenishment(&[device].into(), 2, &mut net.group.rng);
        net.group.run.extend_from_coordinator(1, top_up);
        net.group.settle();
        let actions = net.members[1]
            .sync
            .device_confirmed(&mut net.group.run.participants[1].coordinator, five)
            .unwrap();
        net.act(1, actions);
        let ours = net.members[1]
            .sync
            .ceremonies()
            .find(|ceremony| ceremony.request_id == five)
            .unwrap()
            .offers
            .values()
            .next()
            .unwrap()
            .participant_binonces
            .binonces
            .len();
        assert_eq!(ours, 5);
        // The new stream is held by the ceremony. (nonces_available does not count the send's
        // reservation, so it still lists the first stream.)
        let streams = net.coord(1).nonces_available(device);
        assert_eq!(
            streams.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>()
        );

        net.confirm(2, five).unwrap();
        net.settle_round(five);
        assert_eq!(net.names(0), ["Eve", "Fay", "Gus", "Hal", "Ivy"]);
        assert_eq!(net.status(1, five), CeremonyStatus::Published);
        // The finished ceremony gave its stream back.
        assert_eq!(net.coord(1).nonces_available(device).len(), 2);
    }

    /// While a request from one head is open, members don't confirm a later one from the same
    /// head, so two sets from one head are never both signed. Once the first lands, the second is
    /// dropped, since the book left its head.
    #[test]
    fn a_second_request_from_one_head_waits_for_the_first() {
        let mut net = Net::new(2);
        let first = net.request(0, vec![add("Rex", 0xc1)]);
        let second = net.request(2, vec![add("Sal", 0xc3)]);
        assert_eq!(
            net.status(1, second),
            CeremonyStatus::BlockedByOpenRequest { request_id: first }
        );
        let offers_before =
            net.count(|message| matches!(message, SigningMessage::ContactOffer { .. }));
        assert!(matches!(
            net.confirm(1, second),
            Err(StartSignError::InvalidSpContactOffer(_))
        ));
        // Refused before the device was asked, and no offer was published.
        assert!(net.group.run.message_queue.is_empty());
        assert_eq!(
            net.count(|message| matches!(message, SigningMessage::ContactOffer { .. })),
            offers_before
        );

        net.confirm(0, first).unwrap();
        net.confirm(1, first).unwrap();
        net.settle_round(first);
        assert_eq!(net.status(1, first), CeremonyStatus::Published);
        assert_eq!(net.status(1, second), CeremonyStatus::Dropped);

        // A cancelled first request unblocks the next one from the same head.
        let third = net.request(0, vec![add("Tia", 0xc5)]);
        let fourth = net.request(2, vec![add("Uma", 0xc7)]);
        assert_eq!(
            net.status(1, fourth),
            CeremonyStatus::BlockedByOpenRequest { request_id: third }
        );
        net.publish(0, SigningMessage::Cancel, Some(third));
        assert!(matches!(
            net.status(1, fourth),
            CeremonyStatus::WaitingForConfirmations { .. }
        ));
        net.confirm(1, fourth).unwrap();
    }

    /// A forged set from a member of the channel never reaches the book.
    #[test]
    fn a_forged_change_set_is_refused() {
        let mut net = Net::new(2);
        let request_id = net.request(0, vec![add("Kim", 0x71)]);
        net.confirm(0, request_id).unwrap();
        net.confirm(1, request_id).unwrap();
        net.settle_round(request_id);
        let mut forged = net.group.run.participants[0]
            .coordinator
            .sp_contact_book(net.group.key_id())
            .unwrap()
            .sets_after(&BookHead::empty())[0]
            .clone();
        let ContactChange::Add(details) = &mut forged.changes.set.changes[0] else {
            unreachable!()
        };
        details.name = "Mallory".into();
        let head = net.head(2);
        net.publish(1, SigningMessage::ContactChanges { signed: forged }, None);
        assert_eq!(net.head(2), head);
        assert_eq!(net.names(2), ["Kim"]);
    }
}
