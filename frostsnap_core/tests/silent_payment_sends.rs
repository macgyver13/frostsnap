//! Checks on silent payment sends: the template must spend this wallet's own inputs, and each
//! silent payment address must be the one for the keys it pays.

use bitcoin::{hashes::Hash, Amount, Network, OutPoint, Txid};
use frostsnap_core::{
    bitcoin_transaction::{LocalSpk, PromptDestination, PushInput, TransactionTemplate},
    device::KeyPurpose,
    silent_payments::SilentPaymentRecipient,
    tweak::{BitcoinBip32Path, NormalIndex},
    MasterAppkey, SignTaskError, WireSignTask,
};
use schnorr_fun::fun::{g, marker::*, Point, Scalar, G};

const NETWORK: Network = Network::Bitcoin;

fn purpose() -> KeyPurpose {
    KeyPurpose::Bitcoin(NETWORK)
}

fn scalar(byte: u8) -> Scalar {
    Scalar::<Secret, Zero>::from_bytes_mod_order([byte; 32])
        .non_zero()
        .unwrap()
}

fn public(secret: Scalar) -> Point {
    g!(secret * G).normalize().non_zero().unwrap()
}

/// A silent payment recipient with keys from `scan` and `spend`, and its address.
fn recipient(scan: u8, spend: u8) -> (SilentPaymentRecipient, String) {
    let recipient = SilentPaymentRecipient {
        scan_key: public(scalar(scan)),
        spend_key: public(scalar(spend)),
    };
    let address = recipient.address(NETWORK).unwrap();
    (recipient, address)
}

fn master_appkey() -> MasterAppkey {
    MasterAppkey::derive_from_rootkey(G.normalize())
}

fn local_spk(master_appkey: MasterAppkey, bip32_path: BitcoinBip32Path) -> LocalSpk {
    LocalSpk {
        master_appkey,
        bip32_path,
    }
}

fn owned_input(template: &mut TransactionTemplate, master_appkey: MasterAppkey, sats: u64) {
    template.push_imaginary_owned_input(
        local_spk(
            master_appkey,
            BitcoinBip32Path::external(NormalIndex::new(0).unwrap()),
        ),
        Amount::from_sat(sats),
    );
}

#[test]
fn silent_payment_send_refuses_foreign_inputs() {
    let master = master_appkey();
    let (recipient, address) = recipient(0x61, 0x62);

    let mut template = TransactionTemplate::new();
    owned_input(&mut template, master, 100_000);
    let foreign = bitcoin::TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(
            [&[0x51u8, 0x20][..], &[0xee; 32][..]].concat(),
        ),
    };
    template.push_foreign_input(PushInput::spend_outpoint(
        &foreign,
        OutPoint {
            txid: Txid::from_byte_array([9u8; 32]),
            vout: 0,
        },
    ));
    template.push_silent_payment_output(Amount::from_sat(50_000), recipient, address);

    let result = WireSignTask::BitcoinTransaction(template).check(master, purpose());
    assert!(matches!(result, Err(SignTaskError::SilentPaymentInputs)));
}

#[test]
fn silent_payment_send_refuses_an_address_that_is_not_its_keys() {
    let master = master_appkey();
    let (mismatched, _) = recipient(0x71, 0x72);
    let (_, other_address) = recipient(0x73, 0x74);

    let mut template = TransactionTemplate::new();
    owned_input(&mut template, master, 100_000);
    template.push_silent_payment_output(Amount::from_sat(50_000), mismatched, other_address);

    let result = WireSignTask::BitcoinTransaction(template).check(master, purpose());
    assert!(matches!(
        result,
        Err(SignTaskError::SilentPaymentAddressMismatch)
    ));
}

#[test]
fn a_template_with_holes_is_not_signable() {
    let master = master_appkey();
    let (recipient, address) = recipient(0x81, 0x82);

    let mut template = TransactionTemplate::new();
    owned_input(&mut template, master, 100_000);
    template.push_silent_payment_output(Amount::from_sat(50_000), recipient, address);

    let result = WireSignTask::BitcoinTransaction(template).check(master, purpose());
    assert!(matches!(
        result,
        Err(SignTaskError::SilentPaymentScriptMissing)
    ));
}

/// Before the ECDH derives its script, a silent payment output is sized as the P2TR output it will
/// become, so the fee rate the devices review is the fee rate of the send they sign.
#[test]
fn a_pending_silent_payment_output_has_the_fee_rate_of_the_final_send() {
    let master = master_appkey();
    let (recipient, address) = recipient(0x83, 0x84);

    let mut pending = TransactionTemplate::new();
    owned_input(&mut pending, master, 100_000);
    pending.push_silent_payment_output(Amount::from_sat(50_000), recipient, address);

    let mut p2tr = TransactionTemplate::new();
    owned_input(&mut p2tr, master, 100_000);
    p2tr.push_foreign_output(bitcoin::TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(
            [&[0x51u8, 0x20][..], &[0xee; 32][..]].concat(),
        ),
    });

    assert_eq!(
        pending.as_seen_by(master).feerate(),
        p2tr.as_seen_by(master).feerate()
    );
}

/// The signer is shown the address the recipient gave, and a send to a silent payment with one
/// change output keeps the change hidden, the same as a send to an ordinary address.
#[test]
fn prompt_shows_the_silent_payment_address_and_hides_single_change() {
    let master = master_appkey();
    let (recipient, address) = recipient(0x91, 0x92);

    let mut template = TransactionTemplate::new();
    owned_input(&mut template, master, 100_000);
    template.push_silent_payment_output(Amount::from_sat(50_000), recipient, address.clone());
    template.push_owned_output(
        Amount::from_sat(40_000),
        local_spk(
            master,
            BitcoinBip32Path::internal(NormalIndex::new(0).unwrap()),
        ),
    );

    let prompt = template.as_seen_by(master).user_prompt(NETWORK);
    assert_eq!(prompt.recipients.len(), 1);
    assert_eq!(
        prompt.recipients[0].destination,
        PromptDestination::SilentPayment(address)
    );
    assert_eq!(prompt.recipients[0].amount, Amount::from_sat(50_000));
    assert_eq!(prompt.recipients[0].owned, None);
}
