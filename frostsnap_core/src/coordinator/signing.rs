use crate::{
    message::signing::{SpEcdhSessionId, SpProofBundle},
    nonce_stream::NonceStreamSegment,
    silent_payments::EcdhShare,
    AccessStructureRef, DeviceId, KeyId, Kind, SignSessionId, WireSignTask,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use frostsnap_macros::Kind as KindDerive;
use schnorr_fun::frost::SignatureShare;

use super::FrostCoordinator;

/// A threshold ECDH for a silent payment send, from the moment its device is asked until the
/// signing session is opened from its shares.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, PartialEq)]
pub struct SpEcdhSession {
    pub session_id: SpEcdhSessionId,
    pub access_structure_ref: AccessStructureRef,
    /// The template with its silent payment scripts still to be derived.
    pub sign_task: WireSignTask,
    pub requested: BTreeSet<DeviceId>,
    pub shares: BTreeMap<DeviceId, Vec<EcdhShare>>,
}

#[derive(Clone, Debug, bincode::Encode, bincode::Decode, PartialEq, KindDerive)]
pub enum SigningMutation {
    NewNonces {
        device_id: DeviceId,
        nonce_segment: NonceStreamSegment,
    },
    NewSigningSession(super::ActiveSignSession),
    SentSignReq {
        session_id: SignSessionId,
        device_id: DeviceId,
    },
    GotSignatureSharesFromDevice {
        session_id: SignSessionId,
        device_id: DeviceId,
        signature_shares: Vec<SignatureShare>,
    },
    CloseSignSession {
        session_id: SignSessionId,
        finished: Option<Vec<super::EncodedSignature>>,
    },
    ForgetFinishedSignSession {
        session_id: SignSessionId,
    },
    NewSpEcdhSession(SpEcdhSession),
    GotSpEcdhShares {
        session_id: SpEcdhSessionId,
        device_id: DeviceId,
        shares: Vec<EcdhShare>,
    },
    CloseSpEcdhSession {
        session_id: SpEcdhSessionId,
    },
    /// The proofs the devices of a silent payment sign session check its outputs against.
    SpProofsForSession {
        session_id: SignSessionId,
        sp_proofs: SpProofBundle,
    },
}

impl SigningMutation {
    pub fn tied_to_key(&self, coord: &FrostCoordinator) -> Option<KeyId> {
        match self {
            SigningMutation::NewNonces { .. } => None,
            SigningMutation::NewSpEcdhSession(session) => Some(session.access_structure_ref.key_id),
            SigningMutation::GotSpEcdhShares { session_id, .. }
            | SigningMutation::CloseSpEcdhSession { session_id } => Some(
                coord
                    .sp_ecdh_sessions
                    .get(session_id)?
                    .access_structure_ref
                    .key_id,
            ),
            SigningMutation::NewSigningSession(active_sign_session) => {
                Some(active_sign_session.key_id)
            }
            SigningMutation::SentSignReq { session_id, .. }
            | SigningMutation::GotSignatureSharesFromDevice { session_id, .. }
            | SigningMutation::CloseSignSession { session_id, .. }
            | SigningMutation::ForgetFinishedSignSession { session_id }
            | SigningMutation::SpProofsForSession { session_id, .. } => {
                Some(coord.get_sign_session(*session_id)?.key_id())
            }
        }
    }
}
