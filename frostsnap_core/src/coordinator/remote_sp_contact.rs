//! Confirming a contact change set across coordinators, each with its own devices.
//!
//! Every coordinator asks its local device to confirm the set, as the local flow does. Its offer
//! is the device's ECDH share of each add with binonces reserved for one signature per change. Once
//! the caller has a threshold of offers, the confirmed subset, every coordinator in it builds the
//! sign request for its device from all of the subset's shares and proofs. The device signs only
//! the set its user approved, and only if every add's proofs recombine to its `x * B_scan`. How
//! offers travel between coordinators is the caller's business.

use super::remote_signing::{
    RemoteSignSession, RemoteSignSessionId, RemoteSignStatus, RemoteSigningMutation,
};
use super::signing::ParticipantBinonces;
use super::*;

/// What a coordinator shares for its device once the device has confirmed a change set: the
/// device's ECDH share of each add, in order, and binonces for one signature per change.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct SpContactOffer {
    pub participant_binonces: ParticipantBinonces,
    pub shares: Vec<EcdhShare>,
}

impl SpContactOffer {
    /// Checks this offer for `changes` against the wallet's key: binonces for one signature per
    /// change, and one ECDH share per add from the offer's share index, each with a valid proof.
    /// Any member of the group can run it and refuse a failing offer when it arrives.
    pub fn check(&self, key: &KeyContext, changes: &ContactChangeSet) -> Result<(), String> {
        let network = key
            .purpose
            .bitcoin_network()
            .ok_or("a contact needs a bitcoin key")?;
        if self.participant_binonces.binonces.len() != changes.changes.len() {
            return Err("an offer does not have binonces for every change".into());
        }
        check_sp_contact_shares_of(
            &key.app_shared_key,
            changes,
            network,
            Some(self.participant_binonces.share_index),
            &self.shares,
        )
    }
}

/// The task the confirmed subset `offers` signs for `changes`: each add's `x * B_scan` combined
/// from the subset's shares. Every member derives the same task, and from it the session id of the
/// subset's signature shares. The offers must each have passed [`SpContactOffer::check`].
pub fn sp_contact_sign_task(
    key: &KeyContext,
    changes: ContactChangeSet,
    offers: &[SpContactOffer],
) -> Result<WireSignTask, StartSignError> {
    let network = key
        .purpose
        .bitcoin_network()
        .ok_or(StartSignError::SignTask(crate::SignTaskError::WrongPurpose))?;
    let (changes, _) = combine_sp_contact_changes(
        &key.app_shared_key,
        changes,
        network,
        offers.iter().map(|offer| offer.shares.as_slice()),
    )?;
    Ok(WireSignTask::SpContactChanges(Box::new(changes)))
}

impl FrostCoordinator {
    /// Asks the local `device_id` to confirm `changes`, a change set another coordinator may have
    /// started. `session_id` names the ceremony and the remote sign session it ends in.
    pub fn start_remote_sp_contact(
        &mut self,
        session_id: SpContactSessionId,
        access_structure_ref: AccessStructureRef,
        changes: ContactChangeSet,
        device_id: DeviceId,
        encryption_key: SymmetricKey,
    ) -> Result<CoordinatorSend, StartSignError> {
        self.check_sp_contact_changes(access_structure_ref.key_id, &changes)?;
        self.sp_contact_sessions.insert(
            session_id,
            SpContactSession {
                access_structure_ref,
                changes,
                requested: [device_id].into(),
                shares: Default::default(),
                reserved_nonces: None,
            },
        );
        let send = self.request_sp_contact_ecdh(session_id, device_id, encryption_key);
        if send.is_err() {
            self.sp_contact_sessions.remove(&session_id);
        }
        send
    }

    /// The offer of the local device once it has confirmed. The first call reserves its binonces,
    /// in memory: they are never handed to the device before [`Self::sign_remote_sp_contact`].
    pub fn offer_remote_sp_contact(
        &mut self,
        session_id: SpContactSessionId,
    ) -> Result<SpContactOffer, StartSignError> {
        let used_streams = self
            .all_used_nonce_streams()
            .union(&self.remote_signing.all_used_nonce_streams())
            .copied()
            .collect::<BTreeSet<_>>();
        let session = self
            .sp_contact_sessions
            .get(&session_id)
            .ok_or(StartSignError::NoSuchSpContactSession)?;
        let device_id = remote_device(session)?;
        let shares = session
            .shares
            .get(&device_id)
            .ok_or(StartSignError::InvalidSpContactOffer(
                "the device has not confirmed the contact changes",
            ))?
            .clone();
        let share_index = *self
            .get_access_structure(session.access_structure_ref)
            .ok_or(StartSignError::NoSuchAccessStructure)?
            .device_to_share_index
            .get(&device_id)
            .ok_or(StartSignError::DeviceNotPartOfKey { device_id })?;
        let reserved = match &session.reserved_nonces {
            Some(reserved) => reserved.clone(),
            None => self
                .nonce_cache
                .new_signing_session(
                    &[device_id].into(),
                    session.changes.changes.len(),
                    &used_streams,
                )
                .map_err(StartSignError::NotEnoughNoncesForDevice)?
                .into_values()
                .next()
                .expect("we asked for one device"),
        };
        self.sp_contact_sessions
            .get_mut(&session_id)
            .expect("checked above")
            .reserved_nonces = Some(reserved.clone());
        Ok(SpContactOffer {
            participant_binonces: ParticipantBinonces {
                share_index,
                binonces: reserved.segment.nonces.into_iter().collect(),
            },
            shares,
        })
    }

    /// Builds the sign request for the local device from `offers`, the confirmed subset, which
    /// must hold this coordinator's own offer and at least a threshold of them. Every share in
    /// every offer is checked against its party's share image first. The request goes through the
    /// remote sign session `RemoteSignSessionId(session_id.0)`: its signature share arrives as
    /// [`CoordinatorToUserSigningMessage::GotShare`], and the caller cancels it with
    /// [`Self::cancel_remote_sign_session`] if the ceremony is dropped.
    pub fn sign_remote_sp_contact(
        &mut self,
        session_id: SpContactSessionId,
        offers: &[SpContactOffer],
        encryption_key: SymmetricKey,
    ) -> Result<RequestDeviceSign, StartSignError> {
        let session = self
            .sp_contact_sessions
            .get(&session_id)
            .ok_or(StartSignError::NoSuchSpContactSession)?
            .clone();
        let device_id = remote_device(&session)?;
        let reserved = session
            .reserved_nonces
            .ok_or(StartSignError::InvalidSpContactOffer(
                "this coordinator has not offered yet",
            ))?;
        let our_binonces = reserved.segment.nonces.iter().copied().collect::<Vec<_>>();
        let access_structure = self
            .get_access_structure(session.access_structure_ref)
            .ok_or(StartSignError::NoSuchAccessStructure)?;
        if offers.len() < access_structure.threshold() as usize {
            return Err(StartSignError::NotEnoughDevicesSelected {
                selected: offers.len(),
                threshold: access_structure.threshold(),
            });
        }
        if !offers
            .iter()
            .any(|offer| offer.participant_binonces.binonces == our_binonces)
        {
            return Err(StartSignError::InvalidSpContactOffer(
                "this coordinator's offer is not in the confirmed subset",
            ));
        }
        let network = self
            .sp_contact_network(session.access_structure_ref.key_id)
            .map_err(|_| StartSignError::SignTask(crate::SignTaskError::WrongPurpose))?;
        let app_shared_key = access_structure.app_shared_key();
        let mut share_indices = BTreeSet::new();
        for offer in offers {
            let share_index = offer.participant_binonces.share_index;
            if !share_indices.insert(share_index) {
                return Err(StartSignError::InvalidSpContactOffer(
                    "two offers from one share",
                ));
            }
            if offer.participant_binonces.binonces.len() != session.changes.changes.len() {
                return Err(StartSignError::InvalidSpContactOffer(
                    "an offer does not have binonces for every change",
                ));
            }
            check_sp_contact_shares_of(
                &app_shared_key,
                &session.changes,
                network,
                Some(share_index),
                &offer.shares,
            )
            .map_err(|_| StartSignError::InvalidSpContactOffer("an offer has a bad ECDH share"))?;
        }
        let (changes, proofs) = combine_sp_contact_changes(
            &app_shared_key,
            session.changes,
            network,
            offers.iter().map(|offer| offer.shares.as_slice()),
        )?;

        let id = RemoteSignSessionId(session_id.0);
        if !self
            .remote_signing
            .remote_sign_sessions
            .contains_key(&(id, device_id))
        {
            self.mutate(Mutation::RemoteSigning(
                RemoteSigningMutation::NewRemoteSignSession {
                    id,
                    device_id,
                    session: RemoteSignSession {
                        access_structure_ref: session.access_structure_ref,
                        sign_task: WireSignTask::SpContactChanges(Box::new(changes)),
                        binonces: our_binonces,
                        nonce_state: reserved.coord_nonce_state(),
                        status: RemoteSignStatus::Open,
                    },
                },
            ));
        }
        let all_binonces = offers
            .iter()
            .map(|offer| offer.participant_binonces.clone())
            .collect::<Vec<_>>();
        let mut request =
            self.sign_with_nonce_reservation(id, device_id, &all_binonces, encryption_key)?;
        request.sp_contact_proofs = Some(proofs);
        Ok(request)
    }
}

/// The one local device a remote contact session asked.
fn remote_device(session: &SpContactSession) -> Result<DeviceId, StartSignError> {
    match session.requested.iter().collect::<Vec<_>>()[..] {
        [device_id] => Ok(*device_id),
        _ => Err(StartSignError::InvalidSpContactOffer(
            "a remote contact session asks one local device",
        )),
    }
}
