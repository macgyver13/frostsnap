//! Contact change sets confirmed by devices on different coordinators.

use bitcoin::Network;
use frostsnap_core::coordinator::remote_sp_contact::{sp_contact_sign_task, SpContactOffer};
use frostsnap_core::coordinator::signing::ParticipantSignatureShares;
use frostsnap_core::coordinator::{
    remote_signing, CoordinatorToUserMessage, CoordinatorToUserSigningMessage, KeyContext,
    StartSignError,
};
use frostsnap_core::device::KeyPurpose;
use frostsnap_core::message::signing::SpContactSessionId;
use frostsnap_core::silent_payments::{
    ContactChange, ContactChangeSet, SignedSpContactChanges, SilentPaymentRecipient,
    SpContactDetails,
};
use frostsnap_core::test::{Env, Run, TEST_ENCRYPTION_KEY};
use frostsnap_core::{AccessStructureRef, DeviceId, KeyId, SignSessionId, WireSignTask};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use schnorr_fun::fun::{g, marker::*, Point, Scalar, G};
use std::collections::BTreeMap;

const NETWORK: Network = Network::Bitcoin;

#[derive(Default)]
struct ContactEnv {
    shares: BTreeMap<(usize, SignSessionId), ParticipantSignatureShares>,
}

impl Env for ContactEnv {
    fn user_react_to_coordinator(
        &mut self,
        run: &mut Run,
        ci: usize,
        message: CoordinatorToUserMessage,
        rng: &mut impl rand_chacha::rand_core::RngCore,
    ) {
        match message {
            CoordinatorToUserMessage::KeyGen {
                keygen_id,
                inner:
                    frostsnap_core::coordinator::CoordinatorToUserKeyGenMessage::KeyGenAck {
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

/// Three coordinators with one device each, sharing a 2-of-3 bitcoin key.
struct Group {
    run: Run,
    env: ContactEnv,
    rng: ChaCha20Rng,
    access_structure_ref: AccessStructureRef,
}

impl Group {
    fn new() -> Self {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut env = ContactEnv::default();
        let mut run = Run::start_after_remote_keygen(
            &[1, 1, 1],
            2,
            "contact key",
            KeyPurpose::Bitcoin(NETWORK),
            &mut env,
            &mut rng,
        );
        run.replenish_all_nonces(2, &mut env, &mut rng);
        let access_structure_ref = run.participants[0]
            .coordinator
            .iter_access_structures()
            .next()
            .unwrap()
            .access_structure_ref();
        Self {
            run,
            env,
            rng,
            access_structure_ref,
        }
    }

    fn key_context(&self) -> KeyContext {
        let access_structure = self.run.participants[0]
            .coordinator
            .get_access_structure(self.access_structure_ref)
            .unwrap();
        KeyContext {
            app_shared_key: access_structure.app_shared_key(),
            purpose: KeyPurpose::Bitcoin(NETWORK),
        }
    }

    fn key_id(&self) -> KeyId {
        self.access_structure_ref.key_id
    }

    fn device(&self, ci: usize) -> DeviceId {
        *self.run.participants[ci].devices.keys().next().unwrap()
    }

    /// Coordinator `ci`'s device confirms `changes`, and the coordinator makes its offer.
    fn confirm(
        &mut self,
        ci: usize,
        session_id: SpContactSessionId,
        changes: &ContactChangeSet,
    ) -> SpContactOffer {
        let device = self.device(ci);
        let send = self.run.participants[ci]
            .coordinator
            .start_remote_sp_contact(
                session_id,
                self.access_structure_ref,
                changes.clone(),
                device,
                TEST_ENCRYPTION_KEY,
            )
            .unwrap();
        self.run.extend_from_coordinator(ci, [send]);
        self.run
            .run_until_finished(&mut self.env, &mut self.rng)
            .unwrap();
        self.run.participants[ci]
            .coordinator
            .offer_remote_sp_contact(session_id)
            .unwrap()
    }

    /// Each coordinator in `subset` signs from the subset's offers, and the signatures combine.
    fn sign(
        &mut self,
        session_id: SpContactSessionId,
        subset: &[usize],
        offers: &[SpContactOffer],
    ) -> SignedSpContactChanges {
        let mut sign_task = None;
        for &ci in subset {
            let request = self.run.participants[ci]
                .coordinator
                .sign_remote_sp_contact(session_id, offers, TEST_ENCRYPTION_KEY)
                .unwrap();
            assert!(request.sp_contact_proofs.is_some());
            sign_task = Some(request.request_sign.group_sign_req.sign_task.clone());
            self.run.extend_from_coordinator(ci, [request]);
        }
        self.run
            .run_until_finished(&mut self.env, &mut self.rng)
            .unwrap();
        let sign_task = sign_task.unwrap();
        let all_binonces = offers
            .iter()
            .map(|offer| offer.participant_binonces.clone())
            .collect::<Vec<_>>();
        let session_id = frostsnap_core::message::GroupSignReq::from_binonces(
            sign_task.clone(),
            self.access_structure_ref.access_structure_id,
            &all_binonces,
        )
        .session_id();
        let shares = subset
            .iter()
            .map(|ci| self.env.shares[&(*ci, session_id)].clone())
            .collect::<Vec<_>>();
        let key = self.key_context();
        let signatures = remote_signing::combine_signatures(
            sign_task.clone(),
            &key,
            &all_binonces,
            &shares.iter().collect::<Vec<_>>(),
        )
        .unwrap();
        let WireSignTask::SpContactChanges(changes) = sign_task else {
            panic!("a contact ceremony signs contact changes");
        };
        SignedSpContactChanges {
            changes: *changes,
            signatures: signatures.iter().map(|signature| signature.0).collect(),
        }
    }
}

/// Coordinator 0 asks for the changes, but its device is not in the confirming subset. Coordinators
/// 1 and 2 confirm and sign, and every coordinator applies the signed set to the same book.
#[test]
fn a_change_set_confirmed_by_other_coordinators_devices() {
    let mut group = Group::new();
    let session_id = SpContactSessionId([1; 32]);
    let changes = ContactChangeSet {
        head: group.run.participants[0]
            .coordinator
            .sp_contact_book_head(group.key_id()),
        changes: vec![
            ContactChange::Add(details("Ann", 0x11, 0x12)),
            ContactChange::Add(details("Ben", 0x13, 0x14)),
        ],
    };

    let offers = [1, 2].map(|ci| group.confirm(ci, session_id, &changes));
    let key = group.key_context();
    for offer in &offers {
        offer.check(&key, &changes).unwrap();
    }
    let sign_task = sp_contact_sign_task(&key, changes.clone(), &offers).unwrap();
    let signed = group.sign(session_id, &[1, 2], &offers);
    assert_eq!(
        sign_task,
        WireSignTask::SpContactChanges(Box::new(signed.changes.clone()))
    );
    assert_eq!(signed.signatures.len(), 2);

    let key_id = group.key_id();
    for ci in 0..3 {
        group.run.participants[ci]
            .coordinator
            .add_sp_contact_changes(key_id, signed.clone())
            .unwrap();
    }
    let heads = (0..3)
        .map(|ci| {
            group.run.participants[ci]
                .coordinator
                .sp_contact_book_head(group.key_id())
        })
        .collect::<Vec<_>>();
    assert_eq!(heads, [changes.next_head(NETWORK); 3]);
    let master = group.run.participants[0]
        .coordinator
        .iter_keys()
        .next()
        .unwrap()
        .complete_key
        .master_appkey;
    let book = group.run.participants[0]
        .coordinator
        .sp_contact_book(group.key_id())
        .unwrap();
    for name in ["Ann", "Ben"] {
        assert!(book.by_name(name).unwrap().verify(master, NETWORK));
    }
    // The ceremony ends in each signer's remote sign session.
    for ci in [1, 2] {
        group.run.participants[ci]
            .coordinator
            .cancel_remote_sign_session(remote_signing::RemoteSignSessionId(session_id.0));
    }
}

/// An offer whose proof does not check is refused before anything is signed.
#[test]
fn a_tampered_offer_is_refused() {
    let mut group = Group::new();
    let session_id = SpContactSessionId([2; 32]);
    let changes = ContactChangeSet {
        head: group.run.participants[0]
            .coordinator
            .sp_contact_book_head(group.key_id()),
        changes: vec![ContactChange::Add(details("Cat", 0x21, 0x22))],
    };
    let offers = [0, 2].map(|ci| group.confirm(ci, session_id, &changes));

    let mut tampered = offers.clone();
    tampered[1].shares[0].proof[5] ^= 1;
    let mut other_point = offers.clone();
    other_point[1].shares[0].ecdh_share = details("x", 0x23, 0x24).recipient.scan_key;
    let mut missing_share = offers.clone();
    missing_share[1].shares.clear();
    let key = group.key_context();
    for offers in [&tampered, &other_point, &missing_share] {
        assert!(offers[1].check(&key, &changes).is_err());
    }
    offers[1].check(&key, &changes).unwrap();
    for offers in [tampered, other_point, missing_share] {
        assert!(matches!(
            group.run.participants[0]
                .coordinator
                .sign_remote_sp_contact(session_id, &offers, TEST_ENCRYPTION_KEY),
            Err(StartSignError::InvalidSpContactOffer(_))
        ));
    }
    assert!(matches!(
        group.run.participants[0]
            .coordinator
            .sign_remote_sp_contact(session_id, &offers[..1], TEST_ENCRYPTION_KEY),
        Err(StartSignError::NotEnoughDevicesSelected { .. })
    ));
}

/// A device that restarted between its offer and the round confirming has forgotten the approval,
/// so it ignores the sign request. The ceremony stays pending until it confirms again.
#[test]
fn an_approval_lost_on_restart_leaves_the_ceremony_pending() {
    let mut group = Group::new();
    let session_id = SpContactSessionId([3; 32]);
    let changes = ContactChangeSet {
        head: group.run.participants[0]
            .coordinator
            .sp_contact_book_head(group.key_id()),
        changes: vec![ContactChange::Add(details("Dee", 0x31, 0x32))],
    };
    let offers = [0, 1].map(|ci| group.confirm(ci, session_id, &changes));

    let device = group.device(1);
    group.run.participants[1]
        .devices
        .get_mut(&device)
        .unwrap()
        .clear_tmp_data();
    let request = group.run.participants[1]
        .coordinator
        .sign_remote_sp_contact(session_id, &offers, TEST_ENCRYPTION_KEY)
        .unwrap();
    group.run.extend_from_coordinator(1, [request]);
    group
        .run
        .run_until_finished(&mut group.env, &mut group.rng)
        .unwrap();
    assert!(group.env.shares.keys().all(|(ci, _)| *ci != 1));
}
