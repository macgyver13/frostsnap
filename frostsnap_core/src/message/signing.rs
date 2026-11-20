use crate::{
    nonce_stream::{CoordNonceStreamState, NonceStreamSegment},
    silent_payments::{ContactChangeSet, EcdhShare},
    AccessStructureId, CoordShareDecryptionContrib, Kind, ShareIndex, SignSessionId,
};
use alloc::{boxed::Box, vec::Vec};
use frostsnap_macros::Kind as KindDerive;
use schnorr_fun::{
    frost::SignatureShare,
    fun::{marker::*, Point},
};

/// A request to open one or more nonce streams
#[derive(Clone, Debug, bincode::Encode, bincode::Decode)]
pub struct OpenNonceStreams {
    pub streams: Vec<CoordNonceStreamState>,
}

impl OpenNonceStreams {
    /// Split into individual OpenNonceStreams messages, each with one stream
    pub fn split(self) -> Vec<OpenNonceStreams> {
        self.streams
            .into_iter()
            .map(|stream| OpenNonceStreams {
                streams: vec![stream],
            })
            .collect()
    }
}

/// Coordinator to device signing messages
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, KindDerive)]
pub enum CoordinatorSigning {
    RequestSign(Box<super::RequestSign>),
    OpenNonceStreams(OpenNonceStreams),
    RequestSpContactEcdh(Box<RequestSpContactEcdh>),
    RequestSpContactSign(Box<RequestSpContactSign>),
}

/// Device to coordinator signing messages  
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, KindDerive)]
pub enum DeviceSigning {
    NonceResponse {
        segments: Vec<NonceStreamSegment>,
    },
    SignatureShare {
        session_id: SignSessionId,
        signature_shares: Vec<SignatureShare>,
        replenish_nonces: Option<NonceStreamSegment>,
    },
    /// One ECDH share per add of the change set, in the order of the adds.
    SpContactEcdhShare {
        session_id: SpContactSessionId,
        shares: Vec<EcdhShare>,
    },
}

/// Identifies one run of changing the contact book, before the wallet signs the changes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, bincode::Encode, bincode::Decode,
)]
pub struct SpContactSessionId(pub [u8; 32]);

/// Asks a device to confirm a contact change set with the user and answer with its share of the
/// ECDH for each add.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, PartialEq)]
pub struct RequestSpContactEcdh {
    pub session_id: SpContactSessionId,
    pub rootkey: Point,
    pub access_structure_id: AccessStructureId,
    /// The share the device answers with, in case it holds more than one.
    pub share_index: ShareIndex,
    pub coord_share_decryption_contrib: CoordShareDecryptionContrib,
    pub changes: ContactChangeSet,
}

/// What a device checks each added contact's `x * B_scan` against before signing a change set: the
/// public polynomial the access structure is identified by, and for each add, in order, the ECDH
/// shares of a threshold of parties.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, PartialEq)]
pub struct SpContactProofs {
    pub app_poly: Vec<Point<Normal, Public, Zero>>,
    pub shares: Vec<Vec<EcdhShare>>,
}

/// A sign request for a contact change set, carrying the proofs the signing session itself does not
/// keep.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
pub struct RequestSpContactSign {
    pub request_sign: super::RequestSign,
    pub proofs: SpContactProofs,
}

impl From<DeviceSigning> for super::DeviceToCoordinatorMessage {
    fn from(value: DeviceSigning) -> Self {
        Self::Signing(value)
    }
}
