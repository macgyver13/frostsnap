//! Live smoke test of the shared contact book: three coordinators of a 2-of-3 signet wallet run
//! the contact ceremony, a send to the new contacts and a rename over a nostr relay, each with its
//! own `ChannelClient` and `ContactSync`, as the app does. Devices are the core test devices.
//!
//! Members 0 and 1 add two contacts and send to them. Member 2 comes online afterwards, must
//! reach the same book from the channel with no ceremony of its own, and then renames a contact with member 1.

use bitcoin::{Amount, Network};
use frostsnap_coordinator::Sink;
use frostsnap_core::bitcoin_transaction::{LocalSpk, TransactionTemplate};
use frostsnap_core::coordinator::signing::RemoteSignSessionId;
use frostsnap_core::coordinator::{
    remote_signing, CoordinatorToUserKeyGenMessage, CoordinatorToUserMessage,
    CoordinatorToUserSigningMessage, FrostCoordinator, KeyContext, ParticipantSignatureShares,
};
use frostsnap_core::device::KeyPurpose;
use frostsnap_core::schnorr_fun::fun::{g, marker::*, Point, Scalar, G};
use frostsnap_core::schnorr_fun::Schnorr;
use frostsnap_core::silent_payments::{
    BookHead, ContactChange, SignedSpContact, SilentPaymentRecipient, SpContactDetails,
};
use frostsnap_core::test::{Env, Run, TEST_ENCRYPTION_KEY};
use frostsnap_core::tweak::BitcoinBip32Path;
use frostsnap_core::{AccessStructureRef, KeyId, SignSessionId, WireSignTask};
use frostsnap_nostr::channel::{ChannelInitData, ParticipantShares};
use frostsnap_nostr::signing::contacts::{
    CeremonyStatus, ContactAction, ContactPublish, ContactSync, SignGate,
};
use frostsnap_nostr::signing::{ChannelClient, ChannelEvent, ContactEvent, SigningEvent};
use frostsnap_nostr::{ChannelHandle, EventId, NostrIdentity, Nsec, PublicKey, ToBech32};
use nostr_relay_builder::prelude::*;
use nostr_sdk::{Client, Keys};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const NETWORK: Network = Network::Signet;
const SETTLING: Duration = Duration::from_millis(400);
const REPUBLISH_DELAY: Duration = Duration::from_millis(300);
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct GroupEnv {
    shares: BTreeMap<(usize, SignSessionId), ParticipantSignatureShares>,
}

impl Env for GroupEnv {
    fn user_react_to_coordinator(
        &mut self,
        run: &mut Run,
        ci: usize,
        message: CoordinatorToUserMessage,
        rng: &mut impl RngCore,
    ) {
        match message {
            CoordinatorToUserMessage::KeyGen {
                keygen_id,
                inner:
                    CoordinatorToUserKeyGenMessage::KeyGenAck {
                        all_acks_received: true,
                        ..
                    },
            } => {
                let sends = run.participants[ci]
                    .coordinator
                    .finalize_keygen(keygen_id, TEST_ENCRYPTION_KEY, rng)
                    .unwrap();
                run.extend_from_coordinator(ci, sends);
            }
            CoordinatorToUserMessage::Signing(CoordinatorToUserSigningMessage::GotShare {
                session_id,
                shares,
                ..
            }) => {
                self.shares.insert((ci, session_id), shares);
            }
            _ => {}
        }
    }
}

struct ForwardSink<T>(mpsc::UnboundedSender<T>);

impl<T> Clone for ForwardSink<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Send + 'static> Sink<T> for ForwardSink<T> {
    fn send(&self, event: T) {
        let _ = self.0.send(event);
    }
}

/// One coordinator's channel client and contact driver.
struct Member {
    keys: Keys,
    handle: ChannelHandle,
    sync: ContactSync,
    contacts: mpsc::UnboundedReceiver<ContactEvent>,
    channel: mpsc::UnboundedReceiver<ChannelEvent>,
    history_synced: bool,
    /// Signing events seen, in order.
    signing: Vec<SigningEvent>,
    /// Republishes waiting for their delay, as the app schedules them.
    republish: Vec<(Instant, BookHead)>,
}

struct Group {
    run: Run,
    env: GroupEnv,
    rng: ChaCha20Rng,
    access_structure_ref: AccessStructureRef,
    key: KeyContext,
    init_data: ChannelInitData,
    relay_url: String,
    members: Vec<Option<Member>>,
}

impl Group {
    async fn new(relay_url: String) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(640);
        let mut env = GroupEnv::default();
        let mut run = Run::start_after_remote_keygen(
            &[1, 1, 1],
            2,
            "sp contacts demo",
            KeyPurpose::Bitcoin(NETWORK),
            &mut env,
            &mut rng,
        );
        run.replenish_all_nonces(4, &mut env, &mut rng);
        let key_data = run.participants[0]
            .coordinator
            .iter_keys()
            .next()
            .unwrap()
            .clone();
        let access_structure_ref = key_data
            .access_structures()
            .next()
            .unwrap()
            .access_structure_ref();
        let root_shared_key = key_data
            .complete_key
            .root_shared_key(
                access_structure_ref.access_structure_id,
                TEST_ENCRYPTION_KEY,
            )
            .unwrap();
        let participant_devices = run
            .participants
            .iter()
            .map(|p| {
                let pubkey: PublicKey = nostr_keys(p).public_key().into();
                (pubkey, p.devices.keys().copied().collect::<Vec<_>>())
            })
            .collect::<Vec<_>>();
        let devices_in_order = run
            .participants
            .iter()
            .flat_map(|p| p.devices.keys().copied())
            .collect::<Vec<_>>();
        let init_data = ChannelInitData {
            key_name: key_data.key_name.clone(),
            purpose: KeyPurpose::Bitcoin(NETWORK),
            root_shared_key,
            participants: ParticipantShares::from_device_lists(
                &participant_devices,
                &devices_in_order,
            )
            .unwrap(),
        };
        let key = init_data.key_context();
        Self {
            run,
            env,
            rng,
            access_structure_ref,
            key,
            init_data,
            relay_url,
            members: vec![None, None, None],
        }
    }

    fn key_id(&self) -> KeyId {
        self.access_structure_ref.key_id
    }

    fn coord(&self, ci: usize) -> &FrostCoordinator {
        &self.run.participants[ci].coordinator
    }

    fn member(&mut self, ci: usize) -> &mut Member {
        self.members[ci].as_mut().expect("member is online")
    }

    /// Starts member `ci`'s channel client fresh, as the app does when it opens the wallet.
    async fn connect(&mut self, ci: usize) {
        let keys = nostr_keys(&self.run.participants[ci]);
        let client = Client::builder().build();
        client.add_relay(&self.relay_url).await.unwrap();
        client.connect().await;
        let (contact_tx, contacts) = mpsc::unbounded_channel();
        let (channel_tx, channel) = mpsc::unbounded_channel();
        let init = (ci == 0).then(|| self.init_data.clone());
        let identity = NostrIdentity::Generated {
            nsec: Nsec(keys.secret_key().to_bech32().unwrap()),
            name: format!("member-{ci}"),
            created_at: 1_700_000_000,
        };
        let handle = ChannelClient::new(self.key.clone(), init)
            .with_settling_window(SETTLING)
            .with_contact_sink(ForwardSink(contact_tx))
            .run(client, ForwardSink(channel_tx), identity)
            .await
            .unwrap();
        let sync = ContactSync::new(self.key.clone(), keys.public_key().into(), unix_now());
        self.members[ci] = Some(Member {
            keys,
            handle,
            sync,
            contacts,
            channel,
            history_synced: false,
            signing: vec![],
            republish: vec![],
        });
        self.until(&format!("member {ci} reads the history"), |g| {
            g.members[ci].as_ref().unwrap().history_synced
        })
        .await;
    }

    /// Feeds every online member's queued events to its driver and does what it asks.
    async fn pump(&mut self) {
        for ci in 0..3 {
            let Some(member) = self.members[ci].as_mut() else {
                continue;
            };
            while let Ok(event) = member.channel.try_recv() {
                if let ChannelEvent::Signing { event, .. } = event {
                    member.signing.push(event);
                }
            }
            let mut events = vec![];
            while let Ok(event) = member.contacts.try_recv() {
                events.push(event);
            }
            let now = Instant::now();
            let due = member
                .republish
                .iter()
                .filter(|(at, _)| *at <= now)
                .map(|(_, head)| *head)
                .collect::<Vec<_>>();
            member.republish.retain(|(at, _)| *at > now);
            for event in events {
                if matches!(event, ContactEvent::HistorySynced) {
                    self.member(ci).history_synced = true;
                }
                let coord = &mut self.run.participants[ci].coordinator;
                let actions = self.members[ci]
                    .as_mut()
                    .unwrap()
                    .sync
                    .on_event(coord, event);
                self.act(ci, actions).await;
            }
            for head in due {
                let coord = &self.run.participants[ci].coordinator;
                let actions = self.members[ci]
                    .as_mut()
                    .unwrap()
                    .sync
                    .republish_due(coord, head);
                self.act(ci, actions).await;
            }
        }
    }

    /// Does what the app's contact glue does with the driver's actions.
    async fn act(&mut self, ci: usize, actions: Vec<ContactAction>) {
        let mut queue = actions;
        while !queue.is_empty() {
            let mut next = vec![];
            for action in queue {
                match action {
                    ContactAction::Publish(publish) => {
                        let member = self.members[ci].as_ref().unwrap();
                        let (handle, keys) = (&member.handle, &member.keys);
                        match publish {
                            ContactPublish::Offer { request_id, offer } => {
                                handle.send_contact_offer(keys, request_id, offer).await
                            }
                            ContactPublish::Partial {
                                request_id,
                                offer_subset,
                                signature_shares,
                            } => {
                                handle
                                    .send_sign_partial(
                                        keys,
                                        request_id,
                                        offer_subset,
                                        signature_shares,
                                    )
                                    .await
                            }
                            ContactPublish::Changes(signed) => {
                                handle.send_contact_changes(keys, signed).await
                            }
                            ContactPublish::Head(head) => handle.send_book_head(keys, head).await,
                        }
                        .unwrap();
                    }
                    ContactAction::ToDevice(send) => {
                        self.run.extend_from_coordinator(ci, [send]);
                        self.run
                            .run_until_finished(&mut self.env, &mut self.rng)
                            .unwrap();
                    }
                    ContactAction::SignOnDevice { session_id, send } => {
                        self.run.extend_from_coordinator(ci, [send]);
                        self.run
                            .run_until_finished(&mut self.env, &mut self.rng)
                            .unwrap();
                        let shares = self.env.shares.remove(&(ci, session_id)).unwrap();
                        next.extend(self.member(ci).sync.got_share(session_id, shares));
                    }
                    ContactAction::ScheduleRepublish(head) => {
                        self.member(ci)
                            .republish
                            .push((Instant::now() + REPUBLISH_DELAY, head));
                    }
                }
            }
            queue = next;
        }
    }

    /// Pumps until `done` holds, or panics after the timeout.
    async fn until(&mut self, what: &str, done: impl Fn(&Self) -> bool) {
        let start = Instant::now();
        loop {
            self.pump().await;
            if done(self) {
                return;
            }
            assert!(start.elapsed() < TIMEOUT, "timed out waiting until {what}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn status(&self, ci: usize, request_id: EventId) -> Option<CeremonyStatus> {
        self.members[ci]
            .as_ref()
            .unwrap()
            .sync
            .status(self.coord(ci), request_id)
    }

    fn head(&self, ci: usize) -> BookHead {
        self.coord(ci).sp_contact_book_head(self.key_id())
    }

    fn names(&self, ci: usize) -> Vec<String> {
        let mut names = self
            .coord(ci)
            .sp_contacts(self.key_id())
            .map(|contact| contact.contact.details.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn contact(&self, ci: usize, name: &str) -> SignedSpContact {
        self.coord(ci)
            .sp_contacts(self.key_id())
            .find(|contact| contact.contact.details.name == name)
            .unwrap()
            .clone()
    }

    /// Member `ci` asks the group for `changes` and returns the request's id.
    async fn request(&mut self, ci: usize, changes: Vec<ContactChange>) -> EventId {
        let set = self.members[ci]
            .as_ref()
            .unwrap()
            .sync
            .new_change_set(self.coord(ci), changes)
            .unwrap();
        let member = self.members[ci].as_ref().unwrap();
        member
            .handle
            .send_contact_request(&member.keys, set)
            .await
            .unwrap()
    }

    /// Member `ci`'s device confirms the request, and the member offers.
    async fn confirm(&mut self, ci: usize, request_id: EventId) {
        self.until(&format!("member {ci} sees the request"), |g| {
            matches!(
                g.status(ci, request_id),
                Some(CeremonyStatus::WaitingForConfirmations { .. })
            )
        })
        .await;
        let device = *self.run.participants[ci].devices.keys().next().unwrap();
        let coord = &mut self.run.participants[ci].coordinator;
        let actions = self.members[ci]
            .as_mut()
            .unwrap()
            .sync
            .confirm(coord, request_id, device, TEST_ENCRYPTION_KEY)
            .unwrap();
        self.act(ci, actions).await;
        let coord = &mut self.run.participants[ci].coordinator;
        let actions = self.members[ci]
            .as_mut()
            .unwrap()
            .sync
            .device_confirmed(coord, request_id)
            .unwrap();
        self.act(ci, actions).await;
    }

    /// Waits until every online member has the request's set in its book.
    async fn until_published(&mut self, request_id: EventId) {
        self.until("the change set is in every online book", |g| {
            (0..3)
                .filter(|ci| g.members[*ci].is_some())
                .all(|ci| g.status(ci, request_id) == Some(CeremonyStatus::Published))
        })
        .await;
    }

    /// Member `signer` checks the send against its book and offers to sign it.
    async fn offer_send(
        &mut self,
        signer: usize,
        request_id: EventId,
        reservation: RemoteSignSessionId,
    ) {
        self.until(&format!("member {signer} sees the send"), |g| {
            find_request(g.members[signer].as_ref().unwrap(), request_id).is_some()
        })
        .await;
        let (task, head) =
            find_request(self.members[signer].as_ref().unwrap(), request_id).unwrap();
        let coord = &self.run.participants[signer].coordinator;
        let (gate, actions) = self.members[signer]
            .as_mut()
            .unwrap()
            .sync
            .sign_gate(coord, request_id, &task, head);
        assert_eq!(gate, SignGate::Allowed, "member {signer} may offer");
        self.act(signer, actions).await;
        let device = *self.run.participants[signer].devices.keys().next().unwrap();
        let offer = self.run.participants[signer]
            .coordinator
            .offer_to_sign(reservation, self.access_structure_ref, task, device)
            .unwrap();
        let member = self.members[signer].as_ref().unwrap();
        member
            .handle
            .send_sign_offer(&member.keys, request_id, vec![offer.participant_binonces])
            .await
            .unwrap();
    }
}

fn find_request(member: &Member, request_id: EventId) -> Option<(WireSignTask, Option<BookHead>)> {
    member.signing.iter().find_map(|event| match event {
        SigningEvent::Request {
            event_id,
            sign_task,
            book_head,
            ..
        } if *event_id == request_id => Some((sign_task.clone(), *book_head)),
        _ => None,
    })
}

fn nostr_keys(participant: &frostsnap_core::test::Participant) -> Keys {
    let secret_bytes = participant.keypair.secret_key().to_bytes();
    Keys::new(nostr_sdk::SecretKey::from_slice(&secret_bytes).unwrap())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn details(name: &str, scan: u8, spend: u8) -> SpContactDetails {
    let point = |byte: u8| -> Point {
        let secret = Scalar::<Secret, Zero>::from_bytes_mod_order([byte; 32])
            .non_zero()
            .unwrap();
        g!(secret * G).normalize()
    };
    SpContactDetails {
        name: name.into(),
        recipient: SilentPaymentRecipient {
            scan_key: point(scan),
            spend_key: point(spend),
        },
    }
}

#[tokio::test]
async fn contacts_ceremony_send_late_joiner_and_rename() {
    let _ = tracing_subscriber::fmt::try_init();
    let relay = MockRelay::run().await.unwrap();
    let mut group = Group::new(relay.url().await.to_string()).await;

    // Members 0 and 1 are online. Member 0 imports a file with two new contacts.
    group.connect(0).await;
    group.connect(1).await;
    let ann = details("Ann", 0x11, 0x12);
    let ben = details("Ben", 0x21, 0x22);
    let add_two = group
        .request(
            0,
            vec![
                ContactChange::Add(ann.clone()),
                ContactChange::Add(ben.clone()),
            ],
        )
        .await;
    group.confirm(0, add_two).await;
    group.confirm(1, add_two).await;
    group.until_published(add_two).await;
    assert_eq!(group.head(0), group.head(1));
    assert_eq!(group.head(0).version, 1);
    assert_eq!(group.names(0), ["Ann", "Ben"]);
    assert_eq!(group.names(1), ["Ann", "Ben"]);

    // Member 0 sends to both contacts, with change. Member 1 reviews it from the same
    // book, both sign, and the signatures verify.
    let master_appkey = group
        .coord(0)
        .iter_keys()
        .next()
        .unwrap()
        .complete_key
        .master_appkey;
    let mut template = TransactionTemplate::new();
    template.push_imaginary_owned_input(
        LocalSpk {
            master_appkey,
            bip32_path: BitcoinBip32Path::external(0),
        },
        Amount::from_sat(200_000),
    );
    for (name, sats) in [("Ann", 40_000), ("Ben", 30_000)] {
        let contact = group.contact(0, name);
        let address = contact.contact.details.recipient.address(NETWORK).unwrap();
        template.push_silent_payment_output(Amount::from_sat(sats), contact, address);
    }
    template.push_owned_output(
        Amount::from_sat(120_000),
        LocalSpk {
            master_appkey,
            bip32_path: BitcoinBip32Path::internal(0),
        },
    );
    let template = template.with_contact_sp_scripts(master_appkey).unwrap();
    let task = WireSignTask::BitcoinTransaction(template);
    let head = group.head(0);
    let send = {
        let member = group.members[0].as_ref().unwrap();
        member
            .handle
            .send_sign_request_at_head(&member.keys, task.clone(), "pay the file".into(), head)
            .await
            .unwrap()
    };
    let reservation = RemoteSignSessionId::new([5u8; 32]);
    group.offer_send(0, send, reservation).await;
    group.offer_send(1, send, reservation).await;
    group
        .until("both see the send's round confirmed", |g| {
            [0, 1].iter().all(|ci| {
                g.members[*ci].as_ref().unwrap().signing.iter().any(|event| {
                    matches!(event, SigningEvent::RoundConfirmed { request_id, .. } if *request_id == send)
                })
            })
        })
        .await;
    let (session_id, subset) = group.members[0]
        .as_ref()
        .unwrap()
        .signing
        .iter()
        .find_map(|event| match event {
            SigningEvent::RoundConfirmed {
                request_id,
                session_id,
                subset,
                ..
            } if *request_id == send => Some((*session_id, subset.clone())),
            _ => None,
        })
        .unwrap();
    let binonces = subset
        .iter()
        .flat_map(|entry| entry.binonces.iter().cloned())
        .collect::<Vec<_>>();
    let offer_subset = subset
        .iter()
        .map(|entry| entry.event_id)
        .collect::<Vec<_>>();
    for ci in [0, 1] {
        let device = *group.run.participants[ci].devices.keys().next().unwrap();
        let request = group.run.participants[ci]
            .coordinator
            .sign_with_nonce_reservation(reservation, device, &binonces, TEST_ENCRYPTION_KEY)
            .unwrap();
        group.run.extend_from_coordinator(ci, request);
        group
            .run
            .run_until_finished(&mut group.env, &mut group.rng)
            .unwrap();
        let shares = group.env.shares.remove(&(ci, session_id)).unwrap();
        let member = group.members[ci].as_ref().unwrap();
        member
            .handle
            .send_sign_partial(&member.keys, send, offer_subset.clone(), shares)
            .await
            .unwrap();
    }
    group
        .until("member 0 has both partials of the send", |g| {
            g.members[0]
                .as_ref()
                .unwrap()
                .signing
                .iter()
                .filter(|event| matches!(event, SigningEvent::Partial { request_id, .. } if *request_id == send))
                .count()
                == 2
        })
        .await;
    let partials = group.members[0]
        .as_ref()
        .unwrap()
        .signing
        .iter()
        .filter_map(|event| match event {
            SigningEvent::Partial {
                request_id,
                signature_shares,
                ..
            } if *request_id == send => Some(signature_shares.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let signatures = remote_signing::combine_signatures(
        task.clone(),
        &group.key,
        &binonces,
        &partials.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let checked = task
        .check(master_appkey, KeyPurpose::Bitcoin(NETWORK))
        .unwrap();
    let decoded = signatures
        .iter()
        .map(|signature| signature.into_decoded().unwrap())
        .collect::<Vec<_>>();
    assert!(checked.verify_final_signatures(&Schnorr::<sha2::Sha256>::verify_only(), &decoded));

    // Member 2 comes online for the first time and reaches the same book from the channel, with
    // no ceremony of its own.
    group.connect(2).await;
    group
        .until("member 2 has the group's book", |g| g.head(2) == g.head(0))
        .await;
    assert_eq!(group.names(2), ["Ann", "Ben"]);
    assert_eq!(group.status(2, add_two), Some(CeremonyStatus::Published));
    assert!(!group.members[2]
        .as_ref()
        .unwrap()
        .sync
        .is_syncing(group.coord(2)));

    // Member 2 renames Ann to Anna with member 1. Every member reaches the new head.
    let anna = SpContactDetails {
        name: "Anna".into(),
        recipient: ann.recipient,
    };
    let rename = group
        .request(
            2,
            vec![ContactChange::Remove(ann), ContactChange::Add(anna)],
        )
        .await;
    group.confirm(2, rename).await;
    group.confirm(1, rename).await;
    group.until_published(rename).await;
    group
        .until("every member has the renamed book", |g| {
            g.head(0) == g.head(2) && g.head(1) == g.head(2)
        })
        .await;
    assert_eq!(group.head(0).version, 2);
    for ci in 0..3 {
        assert_eq!(group.names(ci), ["Anna", "Ben"], "member {ci}");
    }
    tracing::info!(check_code = %group.head(0).check_code(), "every member has the same book");
}
