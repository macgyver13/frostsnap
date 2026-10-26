//! Silent payment outputs of a [`TransactionTemplate`]: adding them, and deriving their scripts
//! from the threshold ECDH.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use bitcoin::{
    key::{TweakedPublicKey, XOnlyPublicKey},
    ScriptBuf,
};
use schnorr_fun::{
    frost::ShareIndex,
    fun::{hash::Tag, marker::*, Point, Scalar},
};
use sha2::{Digest, Sha256};

use super::{
    a_sum_public, combine_ecdh_shares, input_hash, output_keys, smallest_outpoint, EcdhShare,
    SilentPaymentRecipient,
};
use crate::{
    bitcoin_transaction::{
        Output, ScopedTo, SilentPaymentOutput, SpkOwner, TransactionTemplate, Unscoped,
    },
    tweak::{BitcoinAccount, TweakContext},
};

impl TransactionTemplate<Unscoped> {
    /// A silent payment to `recipient`, whose script is filled in by [`Self::with_sp_scripts`]
    /// once the ECDH shares are combined. `address` is the recipient's address as the user gave
    /// it, shown to the signer.
    pub fn push_silent_payment_output(
        &mut self,
        value: bitcoin::Amount,
        recipient: SilentPaymentRecipient,
        address: String,
    ) {
        self.outputs.push(Output {
            owner: SpkOwner::SilentPayment(Box::new(SilentPaymentOutput {
                recipient,
                address,
                script: None,
            })),
            value: value.to_sat(),
        });
    }
}

impl<S: Clone> TransactionTemplate<S> {
    /// The silent payment outputs in transaction order.
    pub fn silent_payment_outputs(&self) -> impl Iterator<Item = &SilentPaymentOutput> {
        self.outputs()
            .iter()
            .filter_map(|output| match &output.owner {
                SpkOwner::SilentPayment(sp) => Some(sp.as_ref()),
                _ => None,
            })
    }

    pub fn has_silent_payment_outputs(&self) -> bool {
        self.silent_payment_outputs().next().is_some()
    }

    /// The distinct scan keys of the silent payment outputs, in order of first appearance.
    pub fn silent_payment_scan_keys(&self) -> Vec<Point> {
        let mut seen = BTreeSet::new();
        self.silent_payment_outputs()
            .map(|sp| sp.recipient.scan_key)
            .filter(|scan_key| seen.insert(*scan_key))
            .collect()
    }

    /// What a device approves when it contributes its ECDH shares: everything about the send but
    /// the silent payment scripts, which the ECDH is about to derive. The transaction with those
    /// scripts cleared covers the inputs, the other outputs, the version and the lock time; the
    /// input values cover the fee; the outputs fingerprint covers every address, the silent
    /// payment ones included. A sign request whose template has the same digest is the send the
    /// device already reviewed.
    pub fn sp_approval_digest(&self, network: bitcoin::Network) -> [u8; 32] {
        use bitcoin::consensus::Encodable;
        let mut without_scripts = self.clone();
        for output in &mut without_scripts.outputs {
            if let SpkOwner::SilentPayment(sp) = &mut output.owner {
                sp.script = None;
            }
        }
        let mut tx_bytes = Vec::new();
        without_scripts
            .to_rust_bitcoin_tx()
            .consensus_encode(&mut tx_bytes)
            .expect("writing to a vec cannot fail");

        let mut hash = Sha256::default().tag(b"frostsnap/sp-approval/v1");
        hash.update((tx_bytes.len() as u64).to_le_bytes());
        hash.update(&tx_bytes);
        for input in self.inputs() {
            hash.update(input.txout().value.to_sat().to_le_bytes());
        }
        hash.update(self.outputs_fingerprint(network));
        hash.finalize().into()
    }

    /// This template with every silent payment output's script derived from `shared_secrets`.
    pub fn with_sp_scripts(&self, shared_secrets: &BTreeMap<Point, Point>) -> Option<Self> {
        let recipients = self
            .silent_payment_outputs()
            .map(|sp| sp.recipient)
            .collect::<Vec<_>>();
        let mut keys = output_keys(&recipients, shared_secrets)?.into_iter();

        let mut template = self.clone();
        for output in &mut template.outputs {
            if let SpkOwner::SilentPayment(sp) = &mut output.owner {
                let key = XOnlyPublicKey::from_slice(&keys.next()?).ok()?;
                sp.script = Some(ScriptBuf::new_p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(key),
                ));
            }
        }
        Some(template)
    }
}

/// Which inputs are ours is only known once the template names a key.
impl TransactionTemplate<ScopedTo> {
    /// The BIP352 `input_hash` and the tweak context of every input, for silent payment ECDH.
    /// `None` unless every input is a coin of this key in the default account, since the combined
    /// ECDH is only defined over one account's input secrets.
    pub fn sp_ecdh_inputs(&self) -> Option<(Scalar<Public>, Vec<TweakContext>)> {
        let account = BitcoinAccount::default();
        let account_key = account.derive_account_key(&self.master_appkey().to_xpub());
        let mut outpoints = Vec::new();
        let mut tweaks = Vec::new();
        for input in self.inputs() {
            let owner = input.owner().local_owner()?;
            if owner.bip32_path.account_keychain.account != account {
                return None;
            }
            outpoints.push(input.outpoint());
            tweaks.push(owner.bip32_path.tweak_context(&account_key));
        }
        let smallest = smallest_outpoint(&outpoints)?;
        let a_sum = a_sum_public(*account_key.key(), &tweaks)?;
        Some((input_hash(&smallest, a_sum)?, tweaks))
    }

    /// The shared secret of each scan key, from threshold shares of the ECDH.
    pub fn sp_shared_secrets(&self, shares: &[EcdhShare]) -> Option<BTreeMap<Point, Point>> {
        let (input_hash, tweaks) = self.sp_ecdh_inputs()?;
        let mut by_scan_key = BTreeMap::<Point, Vec<(ShareIndex, Point)>>::new();
        for share in shares {
            by_scan_key
                .entry(share.scan_key)
                .or_default()
                .push((share.share_index, share.ecdh_share));
        }
        by_scan_key
            .into_iter()
            .map(|(scan_key, shares)| {
                let secret = combine_ecdh_shares(input_hash, scan_key, &tweaks, &shares)?;
                Some((scan_key, secret))
            })
            .collect()
    }
}
