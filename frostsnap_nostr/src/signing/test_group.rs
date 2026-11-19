//! Three coordinators with one device each, sharing a 2-of-3 bitcoin key, for tests that run the
//! contact ceremony through the channel types.

use bitcoin::Network;
use frostsnap_core::coordinator::{
    remote_sp_contact::SpContactOffer, CoordinatorToUserKeyGenMessage, CoordinatorToUserMessage,
    CoordinatorToUserSigningMessage, KeyContext, ParticipantSignatureShares,
};
use frostsnap_core::device::KeyPurpose;
use frostsnap_core::message::signing::SpContactSessionId;
use frostsnap_core::schnorr_fun::fun::{g, marker::*, Point, Scalar, G};
use frostsnap_core::silent_payments::{ContactChangeSet, SilentPaymentRecipient, SpContactDetails};
use frostsnap_core::test::{Env, Run, TEST_ENCRYPTION_KEY};
use frostsnap_core::{AccessStructureRef, DeviceId, KeyId, SignSessionId};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

pub(crate) const NETWORK: Network = Network::Bitcoin;

#[derive(Default)]
pub(crate) struct GroupEnv {
    /// Signature shares each coordinator's device gave, by coordinator and session.
    pub shares: BTreeMap<(usize, SignSessionId), ParticipantSignatureShares>,
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

pub(crate) fn details(name: &str, scan: u8, spend: u8) -> SpContactDetails {
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

pub(crate) struct Group {
    pub run: Run,
    pub env: GroupEnv,
    pub rng: ChaCha20Rng,
    pub access_structure_ref: AccessStructureRef,
}

impl Group {
    /// Each device starts with `nonce_streams` streams of nonces.
    pub fn new(nonce_streams: usize) -> Self {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut env = GroupEnv::default();
        let mut run = Run::start_after_remote_keygen(
            &[1, 1, 1],
            2,
            "contact key",
            KeyPurpose::Bitcoin(NETWORK),
            &mut env,
            &mut rng,
        );
        run.replenish_all_nonces(nonce_streams, &mut env, &mut rng);
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

    pub fn key_context(&self) -> KeyContext {
        let access_structure = self.run.participants[0]
            .coordinator
            .get_access_structure(self.access_structure_ref)
            .unwrap();
        KeyContext {
            app_shared_key: access_structure.app_shared_key(),
            purpose: KeyPurpose::Bitcoin(NETWORK),
        }
    }

    pub fn key_id(&self) -> KeyId {
        self.access_structure_ref.key_id
    }

    pub fn device(&self, ci: usize) -> DeviceId {
        *self.run.participants[ci].devices.keys().next().unwrap()
    }

    /// Delivers every queued message between coordinators and their devices.
    pub fn settle(&mut self) {
        self.run
            .run_until_finished(&mut self.env, &mut self.rng)
            .unwrap();
    }

    /// Coordinator `ci`'s device confirms `set`, and the coordinator makes its offer.
    pub fn confirm(
        &mut self,
        ci: usize,
        session_id: SpContactSessionId,
        set: &ContactChangeSet,
    ) -> SpContactOffer {
        let device = self.device(ci);
        let send = self.run.participants[ci]
            .coordinator
            .start_remote_sp_contact(
                session_id,
                self.access_structure_ref,
                set.clone(),
                device,
                TEST_ENCRYPTION_KEY,
            )
            .unwrap();
        self.run.extend_from_coordinator(ci, [send]);
        self.settle();
        self.run.participants[ci]
            .coordinator
            .offer_remote_sp_contact(session_id)
            .unwrap()
    }
}
