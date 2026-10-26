//! Checks on the silent payment ECDH shares of a send, made by the coordinator before it signs with
//! them. Devices run their own checks in `device.rs`.

use crate::{
    coordinator::CoordAccessStructure,
    silent_payments::{verify_ecdh_share, EcdhShare},
    tweak::BitcoinAccount,
};
use schnorr_fun::frost::ShareIndex;

/// Checks the silent payment ECDH shares of `share_indices`: one share for each scan key of
/// `sign_task` from each index, each with a proof under that index's account key share image. The
/// images come from `access_structure`'s polynomial, never from the shares.
pub fn verify_sp_ecdh_shares(
    sign_task: &crate::WireSignTask,
    access_structure: &CoordAccessStructure,
    share_indices: &[ShareIndex],
    shares: &[EcdhShare],
) -> Result<(), &'static str> {
    let crate::WireSignTask::BitcoinTransaction(template) = sign_task else {
        return Err("not a bitcoin transaction");
    };
    if !template.has_silent_payment_outputs() {
        return Err("the transaction has no silent payment outputs");
    }
    let (input_hash, _) = template
        .as_seen_by(access_structure.master_appkey())
        .sp_ecdh_inputs()
        .ok_or("silent payment inputs are not this key's coins")?;
    let account = BitcoinAccount::default().derive_account_key(&access_structure.app_shared_key());
    let scan_keys = template.silent_payment_scan_keys();

    if shares.len() != share_indices.len() * scan_keys.len() {
        return Err("wrong number of silent payment shares");
    }
    for share_index in share_indices {
        let image = account.key().share_image(*share_index).image;
        for scan_key in &scan_keys {
            let mut matching = shares
                .iter()
                .filter(|share| share.share_index == *share_index && share.scan_key == *scan_key);
            let share = matching.next().ok_or("missing a silent payment share")?;
            if matching.next().is_some() {
                return Err("duplicate silent payment share");
            }
            if !verify_ecdh_share(image, input_hash, share) {
                return Err("silent payment ECDH share has a bad proof");
            }
        }
    }
    Ok(())
}

/// The silent payment send `sign_task` with every output script derived from the ECDH `shares` of
/// the signing subset `share_indices`. The shares are verified first, see
/// [`verify_sp_ecdh_shares`], and there must be a threshold of them.
pub fn complete_sp_task(
    sign_task: &crate::WireSignTask,
    access_structure: &CoordAccessStructure,
    share_indices: &[ShareIndex],
    shares: &[EcdhShare],
) -> Result<crate::WireSignTask, &'static str> {
    if share_indices.len() < access_structure.threshold() as usize {
        return Err("fewer silent payment participants than the threshold");
    }
    verify_sp_ecdh_shares(sign_task, access_structure, share_indices, shares)?;
    let crate::WireSignTask::BitcoinTransaction(template) = sign_task else {
        return Err("not a bitcoin transaction");
    };
    let shared_secrets = template
        .as_seen_by(access_structure.master_appkey())
        .sp_shared_secrets(shares)
        .ok_or("silent payment ECDH shares do not combine")?;
    let completed = template
        .with_sp_scripts(&shared_secrets)
        .ok_or("silent payment outputs cannot be derived")?;
    Ok(crate::WireSignTask::BitcoinTransaction(completed))
}
