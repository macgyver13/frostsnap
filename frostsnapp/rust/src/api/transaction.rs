use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use bitcoin::Address;
use flutter_rust_bridge::frb;
use frostsnap_coordinator::bitcoin::wallet::SendRecipient;
use frostsnap_core::silent_payments::SilentPaymentRecipient;
use frostsnap_core::{AccessStructureId, DeviceId, MasterAppkey};

use crate::api::bitcoin::{BitcoinNetwork, BitcoinNetworkExt};
use crate::api::broadcast::Broadcast;
use crate::api::signing::UnsignedTx;
use crate::frb_generated::RustAutoOpaque;
use frostsnap_macros::broadcast_handle;
use std::str::FromStr;

use super::{
    coordinator::{AccessStructure, Coordinator, FrostKey},
    super_wallet::SuperWallet,
};

#[derive(Default, Clone, Copy, PartialEq)]
pub enum ConfirmationTarget {
    Low,
    #[default]
    Medium,
    High,
    /// Custom feerate.
    Custom(f32),
}

impl ConfirmationTarget {
    #[frb(sync)]
    pub fn feerate(self, estimates: Option<ConfirmationEstimates>) -> Option<f32> {
        Some(match self {
            ConfirmationTarget::Low => estimates?.low,
            ConfirmationTarget::Medium => estimates?.medium,
            ConfirmationTarget::High => estimates?.high,
            ConfirmationTarget::Custom(feerate) => feerate,
        })
    }

    #[frb(sync)]
    pub fn is_low(&self) -> bool {
        matches!(self, Self::Low)
    }

    #[frb(sync)]
    pub fn is_medium(&self) -> bool {
        matches!(self, Self::Medium)
    }

    #[frb(sync)]
    pub fn is_high(&self) -> bool {
        matches!(self, Self::High)
    }

    #[frb(sync)]
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

#[derive(Clone, Copy, PartialEq)]
#[frb(type_64bit_int)]
pub struct ConfirmationEstimates {
    /// Unix timestamp of last refresh.
    pub last_refresh: u64,
    /// 1 confirmation.
    pub low: f32,
    /// 2 confirmations.
    pub medium: f32,
    /// 3 confirmations.
    pub high: f32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[frb(type_64bit_int)]
pub enum AmountType {
    /// Send all.
    SendMax,
    /// Value in satoshis.
    Value(u64),
}

impl AmountType {
    #[frb(sync, type_64bit_int)]
    pub fn from_value(value: u64) -> Self {
        Self::Value(value)
    }

    #[frb(sync, type_64bit_int)]
    pub fn value(&self) -> Option<u64> {
        match self {
            Self::SendMax => None,
            Self::Value(v) => Some(*v),
        }
    }

    #[frb(sync)]
    pub fn is_send_max(&self) -> bool {
        matches!(self, Self::SendMax)
    }
}

#[derive(Clone, Default)]
pub struct Recipient {
    pub address: Option<Address>,
    /// Set for silent payment recipients (the tsp1/sp1 string the user supplied).
    pub silent_payment_address: Option<String>,
    pub amount: Option<AmountType>,
}

impl Recipient {
    #[frb(sync)]
    pub fn new(address: Option<Address>, amount: Option<AmountType>) -> Self {
        Self {
            address,
            silent_payment_address: None,
            amount,
        }
    }

    #[frb(sync)]
    pub fn is_silent_payment(&self) -> bool {
        self.silent_payment_address.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[frb(type_64bit_int)]
pub struct RecipientLine {
    pub label: Option<String>,
    pub address: String,
    pub amount_sat: u64,
    pub is_silent_payment: bool,
}

pub(crate) struct BuildTxInner {
    /// Confirmation estimates.
    pub(crate) confirmation_estimates: Option<ConfirmationEstimates>,
    /// Feerate in sats/vb.
    pub(crate) confirmation_target: ConfirmationTarget,
    /// Recipients to send to and amounts.
    pub(crate) recipients: Vec<Recipient>,
    /// The selected access structure.
    pub(crate) access_id: Option<AccessStructureId>,
    /// Selected devices to sign the transaction.
    pub(crate) signers: HashSet<DeviceId>,
    /// Silent payment recipients, parsed when they were set, by the address the user gave.
    pub(crate) silent_payment_recipients: HashMap<String, SilentPaymentRecipient>,
}

/// The dust limit of a silent payment output. Its script is not known until the signers' ECDH
/// shares are in, but it is always P2TR, so a P2TR script with a zero key has the same limit.
fn silent_payment_min_non_dust() -> u64 {
    let mut script = vec![0x51, 0x20];
    script.extend_from_slice(&[0u8; 32]);
    bitcoin::ScriptBuf::from_bytes(script)
        .minimal_non_dust()
        .to_sat()
}

impl BuildTxInner {
    /// The recipient to send `r` to, or `None` if it has no address yet.
    fn send_recipient(&self, r: &Recipient) -> Option<SendRecipient> {
        match &r.silent_payment_address {
            Some(address) => Some(SendRecipient::SilentPayment {
                recipient: *self.silent_payment_recipients.get(address)?,
                address: address.clone(),
            }),
            None => Some(SendRecipient::Address(r.address.clone()?)),
        }
    }

    fn get_or_create_recipient(&mut self, recipient: u32) -> &mut Recipient {
        let i: usize = recipient.try_into().expect("recipient index too large");
        while self.recipients.len() <= i {
            self.recipients.push(Recipient::default());
        }
        self.recipients.get_mut(i).expect("must exist")
    }

    /// Returns `None` if confirmation target is set to low/medium/high but we don't have confirmation estimates.
    fn feerate(&self) -> Option<f32> {
        self.confirmation_target
            .feerate(self.confirmation_estimates)
    }

    /// Returns `None` if no feerate is specified.
    fn available_amount(
        &self,
        super_wallet: &SuperWallet,
        master_appkey: MasterAppkey,
        recipient: u32,
    ) -> Option<u64> {
        Some(
            super_wallet.calculate_available(
                master_appkey,
                self.recipients
                    .iter()
                    .skip(recipient.saturating_sub(1) as usize)
                    .filter_map(|r| {
                        if r.silent_payment_address.is_some() {
                            None
                        } else {
                            r.address.clone()
                        }
                    })
                    .map(RustAutoOpaque::new)
                    .collect(),
                self.feerate()?,
            ),
        )
    }
}

broadcast_handle! { pub struct UnitBcast(pub Broadcast<()>); }

pub struct BuildTxState {
    pub(crate) coord: RustAutoOpaque<Coordinator>,
    pub(crate) super_wallet: SuperWallet,
    pub(crate) frost_key: FrostKey,
    pub(crate) broadcast: Broadcast<()>,
    pub(crate) is_refreshing: Arc<AtomicBool>,
    pub(crate) inner: Arc<RwLock<BuildTxInner>>,
}

impl BuildTxState {
    #[frb(sync)]
    pub fn subscribe(&self) -> UnitBcast {
        UnitBcast::new(self.broadcast.clone())
    }

    #[frb(sync)]
    pub fn master_appkey(&self) -> MasterAppkey {
        self.frost_key.master_appkey()
    }

    #[frb(sync)]
    pub fn confirmation_estimates(&self) -> Option<ConfirmationEstimates> {
        self.inner.read().unwrap().confirmation_estimates
    }

    #[frb(sync)]
    pub fn is_refreshing_confirmation_estimates(&self) -> bool {
        use std::sync::atomic::Ordering;

        self.is_refreshing.load(Ordering::Relaxed)
    }

    /// Refresh confirmation estimates.
    ///
    /// Returns `None` if a previous referesh request has not completed yet.
    pub fn refresh_confirmation_estimates(&self) -> anyhow::Result<Option<ConfirmationEstimates>> {
        use std::sync::atomic::Ordering;

        if self
            .is_refreshing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Ok(None);
        }
        self._trigger_changed();

        let estimates = self._refresh_confirmation_estimates()?;

        self.is_refreshing.store(false, Ordering::Release);
        self._trigger_changed();

        Ok(Some(estimates))
    }

    fn _refresh_confirmation_estimates(&self) -> anyhow::Result<ConfirmationEstimates> {
        let estimates = self.super_wallet.estimate_fee(vec![3, 2, 1])?;
        let confirmation_estimates = ConfirmationEstimates {
            last_refresh: std::time::UNIX_EPOCH.elapsed()?.as_secs(),
            low: estimates[0].1 as _,
            medium: estimates[1].1 as _,
            high: estimates[2].1 as _,
        };
        let mut inner = self.inner.write().unwrap();
        if inner.confirmation_estimates != Some(confirmation_estimates) {
            inner.confirmation_estimates = Some(confirmation_estimates);
        }
        Ok(confirmation_estimates)
    }

    #[frb(sync)]
    pub fn confirmation_blocks_of_feerate(&self) -> Option<u32> {
        let inner = self.inner.read().unwrap();
        match inner.confirmation_target {
            ConfirmationTarget::Low => return Some(3),
            ConfirmationTarget::Medium => return Some(2),
            ConfirmationTarget::High => return Some(1),
            ConfirmationTarget::Custom(feerate) => {
                let targets = inner.confirmation_estimates?;
                if feerate <= targets.high {
                    return Some(1);
                }
                if feerate <= targets.medium {
                    return Some(2);
                }
                if feerate <= targets.low {
                    return Some(3);
                }
                return None;
            }
        };
    }

    /// Remaining amount that is available for recipient.
    ///
    /// Returns `None` if no feerate is specified.
    #[frb(sync)]
    pub fn available_amount(&self, recipient: u32) -> Option<u64> {
        let inner = self.inner.read().unwrap();
        inner.available_amount(
            &self.super_wallet,
            self.frost_key.master_appkey(),
            recipient,
        )
    }

    #[frb(sync)]
    pub fn access_structures(&self) -> Vec<AccessStructure> {
        self.frost_key.access_structures()
    }

    #[frb(sync)]
    pub fn available_signers(&self) -> Vec<(DeviceId, Option<String>)> {
        let access_id_opt = self.inner.read().unwrap().access_id;
        let coord_lock = self.coord.blocking_read();
        access_id_opt
            .and_then(|a_id| self.frost_key.get_access_structure(a_id))
            .map_or(Vec::new(), |access| {
                access
                    .devices()
                    .map(move |d_id| {
                        let name = coord_lock.get_device_name(d_id);
                        (d_id, name)
                    })
                    .collect::<Vec<_>>()
            })
    }

    #[frb(sync)]
    pub fn selected_signers(&self) -> Vec<DeviceId> {
        self.inner.read().unwrap().signers.iter().copied().collect()
    }

    #[frb(sync)]
    pub fn access_struct(&self) -> Option<AccessStructure> {
        let inner = self.inner.read().unwrap();
        let access_id = inner.access_id?;
        self.frost_key.get_access_structure(access_id)
    }

    #[frb(sync)]
    pub fn access_id(&self) -> Option<AccessStructureId> {
        self.inner.read().unwrap().access_id
    }

    #[frb(sync)]
    pub fn set_access_id(&self, access_id: &AccessStructureId) {
        let mut inner = self.inner.write().unwrap();
        if inner.access_id.as_ref() != Some(access_id) {
            inner.access_id = Some(*access_id);
            inner.signers.clear();
            self._trigger_changed();
        }
    }

    #[frb(sync)]
    pub fn select_signer(&self, d_id: DeviceId) {
        let mut inner = self.inner.write().unwrap();
        if inner.signers.insert(d_id) {
            self._trigger_changed();
        }
    }

    #[frb(sync)]
    pub fn deselect_signer(&self, d_id: DeviceId) {
        let mut inner = self.inner.write().unwrap();
        if inner.signers.remove(&d_id) {
            self._trigger_changed();
        }
    }

    #[frb(sync)]
    pub fn is_signer_selected(&self, d_id: DeviceId) -> bool {
        let inner = self.inner.read().unwrap();
        inner.signers.contains(&d_id)
    }

    #[frb(sync)]
    pub fn recipient_count(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.recipients.len() as u64
    }

    #[frb(sync)]
    pub fn recipient(&self, recipient: u32) -> Option<Recipient> {
        let inner = self.inner.read().unwrap();
        inner.recipients.get(recipient as usize).cloned()
    }

    /// Determines the target feerate.
    ///
    /// If confirmation target is not `Custom`, this value uses the `ConfirmationEstimates` to
    /// determine the feerate.
    #[frb(sync)]
    pub fn feerate(&self) -> Option<f32> {
        let inner = self.inner.read().unwrap();
        inner
            .confirmation_target
            .feerate(inner.confirmation_estimates)
    }

    #[frb(sync)]
    pub fn confirmation_target(&self) -> ConfirmationTarget {
        let inner = self.inner.read().unwrap();
        inner.confirmation_target
    }

    #[frb(sync)]
    pub fn set_confirmation_target(&self, target: ConfirmationTarget) {
        let mut inner = self.inner.write().unwrap();
        if inner.confirmation_target != target {
            inner.confirmation_target = target;
            self._trigger_changed();
        }
    }

    #[frb(sync, type_64bit_int)]
    pub fn fee(&self) -> Option<u64> {
        let inner = self.inner.read().unwrap();
        let mut sw = self.super_wallet.inner.lock().unwrap();
        sw.send_to(
            self.frost_key.master_appkey(),
            inner.recipients.iter().filter_map(|r| {
                let recip = inner.send_recipient(r)?;
                let amount = r.amount.map_or(Some(0), |a| a.value());
                Some((recip, amount))
            }),
            inner.feerate()?,
        )
        .ok()?
        .fee()
    }

    #[frb(sync)]
    pub fn set_recipient_with_uri(&self, recipient: u32, uri: &str) -> Result<(), String> {
        let trimmed = uri.trim();
        let net = self.super_wallet.network;
        if let Some(sp) = SilentPaymentRecipient::from_address(trimmed, net) {
            let mut inner = self.inner.write().unwrap();
            inner
                .silent_payment_recipients
                .insert(trimmed.to_string(), sp);
            let r = inner.get_or_create_recipient(recipient);
            let mut changed = false;
            if r.silent_payment_address.as_ref() != Some(&trimmed.to_string()) {
                r.silent_payment_address = Some(trimmed.to_string());
                r.address = None;
                changed = true;
            }
            if changed {
                self._trigger_changed();
            }
            return Ok(());
        }
        let info = self
            .super_wallet
            .network
            .validate_destination_address(uri)?;

        let mut inner = self.inner.write().unwrap();
        let r = inner.get_or_create_recipient(recipient);

        let mut changed = false;
        if r.address.as_ref() != Some(&info.address) {
            r.address = Some(info.address);
            r.silent_payment_address = None;
            changed = true;
        }
        if r.amount != info.amount.map(AmountType::Value) {
            r.amount = info.amount.map(AmountType::Value);
            changed = true;
        }
        if changed {
            self._trigger_changed();
        }

        Ok(())
    }

    #[frb(sync)]
    pub fn remove_recipient(&self, recipient: u32) -> bool {
        let i: usize = recipient
            .try_into()
            .expect("recipient index must fit into usize");
        let mut inner = self.inner.write().unwrap();
        if inner.recipients.len() <= i {
            false
        } else {
            inner.recipients.remove(i);
            self._trigger_changed();
            true
        }
    }

    #[frb(sync)]
    pub fn set_address(&self, recipient: u32, address: &Address) {
        let mut inner = self.inner.write().unwrap();
        let r = inner.get_or_create_recipient(recipient);
        if r.address.as_ref() != Some(address) {
            r.address = Some(address.clone());
            r.silent_payment_address = None;
            self._trigger_changed();
        }
    }

    #[frb(sync)]
    pub fn clear_address(&self, recipient: u64) {
        let i: usize = recipient
            .try_into()
            .expect("recipient index must fit in usize");
        let mut inner = self.inner.write().unwrap();
        if let Some(r) = inner.recipients.get_mut(i) {
            let had = r.address.is_some() || r.silent_payment_address.is_some();
            r.address = None;
            r.silent_payment_address = None;
            if had {
                self._trigger_changed();
            }
        }
    }

    #[frb(sync)]
    pub fn set_amount(&self, recipient: u32, amount: u64) {
        let mut inner = self.inner.write().unwrap();
        let r = inner.get_or_create_recipient(recipient);
        if r.amount != Some(AmountType::Value(amount)) {
            r.amount = Some(AmountType::Value(amount));
            self._trigger_changed();
        }
    }

    #[frb(sync)]
    pub fn set_send_max(&self, recipient: u32) {
        let mut inner = self.inner.write().unwrap();
        let r = inner.get_or_create_recipient(recipient);
        if r.amount != Some(AmountType::SendMax) {
            r.amount = Some(AmountType::SendMax);
            self._trigger_changed();
        }
    }

    #[frb(sync)]
    pub fn set_recipients(&self, lines: Vec<RecipientLine>) -> Result<(), String> {
        {
            let mut inner = self.inner.write().unwrap();
            inner.recipients.clear();
        }
        for (i, line) in lines.into_iter().enumerate() {
            let idx = i as u32;
            self.set_recipient_with_uri(idx, &line.address)?;
            self.set_amount(idx, line.amount_sat);
        }
        self._trigger_changed();
        Ok(())
    }

    #[frb(sync)]
    pub fn clear_recipients(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.recipients.clear();
        self._trigger_changed();
    }

    #[frb(sync)]
    pub fn clear_amount(&self, recipient: u32) {
        let mut inner = self.inner.write().unwrap();
        if let Some(r) = inner.recipients.get_mut(recipient as usize) {
            if r.amount.is_some() {
                r.amount = None;
                self._trigger_changed();
            }
        }
    }

    /// Only returns `Some` if the amount is valid and a recipient address is provided.
    #[frb(sync)]
    pub fn amount(&self, recipient: u32) -> Result<u64, AmountError> {
        let available = self
            .available_amount(recipient)
            .ok_or(AmountError::UnspecifiedFeerate)?;
        if available == 0 {
            // TODO: Have amount below dust error.
            return Err(AmountError::NoAmountAvailable);
        }

        let r = self.recipient(recipient);

        let amount = match r
            .as_ref()
            .and_then(|r| r.amount)
            .ok_or(AmountError::UnspecifiedAmount)?
        {
            AmountType::SendMax => available,
            AmountType::Value(target) => {
                if target > available {
                    return Err(AmountError::TargetExceedsAvailable { target, available });
                }
                target
            }
        };

        let min_non_dust = if r.as_ref().map_or(false, |rr| rr.is_silent_payment()) {
            silent_payment_min_non_dust()
        } else {
            let addr = r
                .and_then(|r| r.address.clone())
                .ok_or(AmountError::UnspecifiedAddress)?;
            addr.script_pubkey().minimal_non_dust().to_sat()
        };
        if amount < min_non_dust {
            return Err(AmountError::AmountBelowDust { min_non_dust });
        }
        Ok(amount)
    }

    #[frb(sync)]
    pub fn is_send_max(&self, recipient: u32) -> bool {
        let inner = self.inner.read().unwrap();
        inner
            .recipients
            .get(recipient as usize)
            .map_or(false, |r| match r.amount {
                None => false,
                Some(t) => t.is_send_max(),
            })
    }

    #[frb(sync)]
    pub fn toggle_send_max(&self, recipient: u32, fallback_amount: Option<u64>) -> bool {
        let mut is_send_max = false;
        let mut inner = self.inner.write().unwrap();
        if let Some(r) = inner.recipients.get_mut(recipient as usize) {
            is_send_max = r.amount == Some(AmountType::SendMax);
            r.amount = if is_send_max {
                fallback_amount.map(AmountType::Value)
            } else {
                Some(AmountType::SendMax)
            };
            self._trigger_changed();
        }
        is_send_max
    }

    fn _trigger_changed(&self) {
        self.broadcast.add(&());
    }

    #[frb(sync)]
    pub fn try_finish(&self) -> Result<UnsignedTx, TryFinishTxError> {
        let master_appkey = self.master_appkey();

        let inner = self.inner.read().unwrap();
        let feerate = inner.feerate().ok_or(TryFinishTxError::MissingFeerate)?;
        let recipients = inner
            .recipients
            .iter()
            .filter_map(|r| Some((inner.send_recipient(r)?, r.amount?.value())))
            .collect::<Vec<_>>();

        if recipients.len() != inner.recipients.len() {
            return Err(TryFinishTxError::IncompleteRecipientValues);
        }
        drop(inner);

        let mut sw_inner = self.super_wallet.inner.lock().unwrap();
        sw_inner
            .send_to(master_appkey, recipients, feerate)
            .map(|template_tx| UnsignedTx { template_tx })
            .map_err(|_| TryFinishTxError::InsufficientBalance)
    }
}

#[derive(Debug)]
pub enum AmountError {
    UnspecifiedFeerate,
    UnspecifiedAmount,
    UnspecifiedAddress,
    NoAmountAvailable,
    AmountBelowDust { min_non_dust: u64 },
    TargetExceedsAvailable { target: u64, available: u64 },
}

#[derive(Debug)]
pub enum TryFinishTxError {
    /// Occurs when feerate target set to low/medium/high, however, we do not have feerate estimates.
    MissingFeerate,
    IncompleteRecipientValues,
    InsufficientBalance,
}

#[derive(serde::Deserialize)]
struct TomlRecipientsFile {
    recipients: Option<Vec<toml::Spanned<TomlRecipientItem>>>,
}

#[derive(serde::Deserialize)]
struct TomlRecipientItem {
    address: Option<toml::Spanned<toml::Value>>,
    amount_sat: Option<toml::Spanned<toml::Value>>,
    label: Option<toml::Value>,
}

fn byte_to_line(contents: &str, byte_offset: usize) -> usize {
    let offset = byte_offset.min(contents.len());
    contents[..offset].chars().filter(|&c| c == '\n').count() + 1
}

#[frb(sync)]
pub fn parse_recipients_file(
    contents: String,
    network: BitcoinNetwork,
) -> Result<Vec<RecipientLine>, String> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err("Recipients file is empty".to_string());
    }

    let is_toml = contents.contains("[[recipients]]")
        || contents.contains("[recipients]")
        || (trimmed.starts_with('[') && !trimmed.starts_with("[\""));

    if is_toml {
        parse_toml_recipients(&contents, network)
    } else {
        if let Ok(toml_file) = toml::from_str::<TomlRecipientsFile>(&contents) {
            if toml_file
                .recipients
                .as_ref()
                .map_or(false, |r| !r.is_empty())
            {
                return parse_toml_recipients(&contents, network);
            }
        }
        parse_csv_recipients(&contents, network)
    }
}

fn parse_toml_recipients(
    contents: &str,
    network: BitcoinNetwork,
) -> Result<Vec<RecipientLine>, String> {
    let parsed: TomlRecipientsFile =
        toml::from_str(contents).map_err(|e| format!("TOML parse error: {}", e))?;

    let recipients = parsed
        .recipients
        .ok_or_else(|| "No [[recipients]] found in TOML file".to_string())?;

    if recipients.is_empty() {
        return Err("No recipients found in TOML file".to_string());
    }

    let mut errors = Vec::new();
    let mut result = Vec::new();

    for spanned_item in recipients {
        let item_line = byte_to_line(contents, spanned_item.span().start);
        let item = spanned_item.into_inner();

        let label = match item.label {
            Some(toml::Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            _ => None,
        };

        let mut addr_str_opt = None;
        let addr_line = if let Some(spanned_addr) = item.address {
            let l = byte_to_line(contents, spanned_addr.span().start);
            match spanned_addr.into_inner() {
                toml::Value::String(s) => {
                    addr_str_opt = Some(s);
                }
                _ => {
                    errors.push(format!("Line {l}: address must be a string"));
                }
            }
            l
        } else {
            errors.push(format!("Line {item_line}: missing address"));
            item_line
        };

        let mut amount_opt = None;
        let amt_line = if let Some(spanned_amt) = item.amount_sat {
            let l = byte_to_line(contents, spanned_amt.span().start);
            match spanned_amt.into_inner() {
                toml::Value::Integer(val) => {
                    if val < 0 {
                        errors.push(format!("Line {l}: amount must be positive"));
                    } else {
                        amount_opt = Some(val as u64);
                    }
                }
                _ => {
                    errors.push(format!("Line {l}: amount_sat must be an integer"));
                }
            }
            l
        } else {
            errors.push(format!("Line {item_line}: missing amount_sat"));
            item_line
        };

        let mut is_sp = false;
        let mut addr_valid = false;
        let mut min_non_dust = 330;

        if let Some(addr_str) = &addr_str_opt {
            let trimmed_addr = addr_str.trim();
            if SilentPaymentRecipient::from_address(trimmed_addr, network).is_some() {
                is_sp = true;
                addr_valid = true;
                min_non_dust = silent_payment_min_non_dust();
            } else if let Some(addr) = bitcoin::Address::from_str(trimmed_addr)
                .ok()
                .and_then(|a| a.require_network(network).ok())
            {
                addr_valid = true;
                min_non_dust = addr.script_pubkey().minimal_non_dust().to_sat();
            } else {
                errors.push(format!("Line {addr_line}: invalid address \"{addr_str}\""));
            }
        }

        if let Some(amt) = amount_opt {
            if amt < min_non_dust {
                errors.push(format!(
                    "Line {amt_line}: amount {amt} sat is below dust threshold ({min_non_dust} sat)"
                ));
            }
        }

        if let (Some(addr_str), Some(amount_sat)) = (addr_str_opt, amount_opt) {
            if addr_valid && amount_sat >= min_non_dust {
                result.push(RecipientLine {
                    label,
                    address: addr_str.trim().to_string(),
                    amount_sat,
                    is_silent_payment: is_sp,
                });
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }

    if result.is_empty() {
        return Err("No valid recipients found in TOML file".to_string());
    }

    Ok(result)
}

fn parse_csv_recipients(
    contents: &str,
    network: BitcoinNetwork,
) -> Result<Vec<RecipientLine>, String> {
    let mut errors = Vec::new();
    let mut result = Vec::new();
    let mut is_first_non_empty = true;

    for (line_idx, line) in contents.lines().enumerate() {
        let line_no = line_idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, ',').collect();
        if is_first_non_empty {
            is_first_non_empty = false;
            if parts[0]
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case("address")
            {
                continue; // Header row
            }
        }

        if parts.len() < 2 {
            errors.push(format!(
                "Line {line_no}: expected CSV format 'address,amount_sat[,label]'"
            ));
            continue;
        }

        let addr_str = parts[0].trim().trim_matches('"');
        let amount_str = parts[1].trim().trim_matches('"');
        let label = if parts.len() >= 3 {
            let l = parts[2].trim().trim_matches('"');
            if l.is_empty() {
                None
            } else {
                Some(l.to_string())
            }
        } else {
            None
        };

        let amount_opt = match amount_str.parse::<u64>() {
            Ok(amt) => Some(amt),
            Err(_) => {
                errors.push(format!("Line {line_no}: invalid amount '{amount_str}'"));
                None
            }
        };

        let mut is_sp = false;
        let mut addr_valid = false;
        let mut min_non_dust = 330;

        if SilentPaymentRecipient::from_address(addr_str, network).is_some() {
            is_sp = true;
            addr_valid = true;
            min_non_dust = silent_payment_min_non_dust();
        } else if let Some(addr) = bitcoin::Address::from_str(addr_str)
            .ok()
            .and_then(|a| a.require_network(network).ok())
        {
            addr_valid = true;
            min_non_dust = addr.script_pubkey().minimal_non_dust().to_sat();
        } else {
            errors.push(format!("Line {line_no}: invalid address \"{addr_str}\""));
        }

        if let Some(amt) = amount_opt {
            if amt < min_non_dust {
                errors.push(format!(
                    "Line {line_no}: amount {amt} sat is below dust threshold ({min_non_dust} sat)"
                ));
            }
        }

        if let Some(amount_sat) = amount_opt {
            if addr_valid && amount_sat >= min_non_dust {
                result.push(RecipientLine {
                    label,
                    address: addr_str.to_string(),
                    amount_sat,
                    is_silent_payment: is_sp,
                });
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }

    if result.is_empty() {
        return Err("No recipients found in CSV file".to_string());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sp_address() -> String {
        let scan = [
            0x02, 0x20, 0xbc, 0xfa, 0xc5, 0xb9, 0x9e, 0x04, 0xad, 0x1a, 0x06, 0xdd, 0xfb, 0x01,
            0x6e, 0xe1, 0x35, 0x82, 0x60, 0x9d, 0x60, 0xb6, 0x29, 0x1e, 0x98, 0xd0, 0x1a, 0x9b,
            0xc9, 0xa1, 0x6c, 0x96, 0xd4,
        ];
        let spend = [
            0x02, 0x5c, 0xc9, 0x85, 0x6d, 0x6f, 0x83, 0x75, 0x35, 0x0e, 0x12, 0x39, 0x78, 0xda,
            0xac, 0x20, 0x0c, 0x26, 0x0c, 0xb5, 0xb5, 0xae, 0x83, 0x10, 0x6c, 0xab, 0x90, 0x48,
            0x4d, 0xcd, 0x8f, 0xcf, 0x36,
        ];
        let recipient = SilentPaymentRecipient {
            scan_key: frostsnap_core::schnorr_fun::fun::Point::from_slice(&scan).unwrap(),
            spend_key: frostsnap_core::schnorr_fun::fun::Point::from_slice(&spend).unwrap(),
        };
        recipient.address(bitcoin::Network::Testnet).unwrap()
    }

    const TEST_TB1_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    #[test]
    fn test_parse_recipients_toml() {
        let toml_data = format!(
            r#"
[[recipients]]
address = "{TEST_TB1_ADDR}"
amount_sat = 50000
label = "Alice"
scan_key_hex = "deadbeef"

[[recipients]]
address = "{TEST_TB1_ADDR}"
amount_sat = 60000
"#
        );
        let res = parse_recipients_file(toml_data, BitcoinNetwork::Testnet).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].label, Some("Alice".to_string()));
        assert_eq!(res[0].address, TEST_TB1_ADDR);
        assert_eq!(res[0].amount_sat, 50000);
        assert_eq!(res[0].is_silent_payment, false);

        assert_eq!(res[1].label, None);
        assert_eq!(res[1].amount_sat, 60000);
    }

    #[test]
    fn test_parse_recipients_csv() {
        let csv_data =
            format!("address,amount_sat,label\n{TEST_TB1_ADDR},50000,Bob\n{TEST_TB1_ADDR},75000\n");
        let res = parse_recipients_file(csv_data, BitcoinNetwork::Testnet).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].label, Some("Bob".to_string()));
        assert_eq!(res[0].address, TEST_TB1_ADDR);
        assert_eq!(res[0].amount_sat, 50000);
        assert_eq!(res[0].is_silent_payment, false);

        assert_eq!(res[1].label, None);
        assert_eq!(res[1].amount_sat, 75000);
    }

    #[test]
    fn test_parse_recipients_bad_address() {
        let csv_data = "badaddress123,50000,Fail\n";
        let err = parse_recipients_file(csv_data.to_string(), BitcoinNetwork::Testnet).unwrap_err();
        assert!(err.contains("Line 1: invalid address"));

        let toml_data = r#"
[[recipients]]
address = "badaddress123"
amount_sat = 50000
"#;
        let err_toml =
            parse_recipients_file(toml_data.to_string(), BitcoinNetwork::Testnet).unwrap_err();
        assert!(err_toml.contains("Line 3: invalid address"));
    }

    #[test]
    fn test_parse_recipients_dust_amount() {
        let csv_data = format!("{TEST_TB1_ADDR},10,Dusty\n");
        let err = parse_recipients_file(csv_data, BitcoinNetwork::Testnet).unwrap_err();
        assert!(err.contains("Line 1: amount 10 sat is below dust threshold"));

        let toml_data = format!(
            r#"
[[recipients]]
address = "{TEST_TB1_ADDR}"
amount_sat = 5
"#
        );
        let err_toml = parse_recipients_file(toml_data, BitcoinNetwork::Testnet).unwrap_err();
        assert!(err_toml.contains("Line 4: amount 5 sat is below dust threshold"));
    }

    #[test]
    fn test_parse_recipients_mixed_tsp1_tb1() {
        let sp_addr = test_sp_address();
        let csv_data = format!("{sp_addr},50000,Silent\n{TEST_TB1_ADDR},60000,Standard\n");
        let res = parse_recipients_file(csv_data, BitcoinNetwork::Testnet).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].is_silent_payment, true);
        assert_eq!(res[0].label, Some("Silent".to_string()));
        assert_eq!(res[0].amount_sat, 50000);

        assert_eq!(res[1].is_silent_payment, false);
        assert_eq!(res[1].label, Some("Standard".to_string()));
        assert_eq!(res[1].amount_sat, 60000);

        let toml_data = format!(
            r#"
[[recipients]]
address = "{sp_addr}"
amount_sat = 70000

[[recipients]]
address = "{TEST_TB1_ADDR}"
amount_sat = 80000
"#
        );
        let res_toml = parse_recipients_file(toml_data, BitcoinNetwork::Testnet).unwrap();
        assert_eq!(res_toml.len(), 2);
        assert_eq!(res_toml[0].is_silent_payment, true);
        assert_eq!(res_toml[1].is_silent_payment, false);
    }

    #[test]
    fn test_clear_recipients() {
        // A BuildTxState needs a funded wallet, so this exercises the recipients it clears.
        let mut inner = BuildTxInner {
            confirmation_estimates: None,
            confirmation_target: ConfirmationTarget::Medium,
            recipients: vec![],
            access_id: None,
            signers: HashSet::new(),
            silent_payment_recipients: Default::default(),
        };
        inner.recipients.clear();
        {
            let r = inner.get_or_create_recipient(0);
            r.address = Some(
                bitcoin::Address::from_str(TEST_TB1_ADDR)
                    .unwrap()
                    .require_network(bitcoin::Network::Testnet)
                    .unwrap(),
            );
            r.amount = Some(AmountType::Value(10000));
        }
        {
            let r = inner.get_or_create_recipient(1);
            r.address = Some(
                bitcoin::Address::from_str(TEST_TB1_ADDR)
                    .unwrap()
                    .require_network(bitcoin::Network::Testnet)
                    .unwrap(),
            );
            r.amount = Some(AmountType::Value(20000));
        }
        assert_eq!(inner.recipients.len(), 2);
        inner.recipients.clear();
        assert_eq!(inner.recipients.len(), 0);
        {
            let r = inner.get_or_create_recipient(0);
            r.address = Some(
                bitcoin::Address::from_str(TEST_TB1_ADDR)
                    .unwrap()
                    .require_network(bitcoin::Network::Testnet)
                    .unwrap(),
            );
            r.amount = Some(AmountType::Value(12345));
        }
        assert_eq!(inner.recipients.len(), 1);
    }
}
