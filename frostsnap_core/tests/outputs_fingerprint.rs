//! The outputs fingerprint and the check code the user compares between the app and the device.

use bitcoin::{Address, Amount, Network, TxOut};
use frostsnap_core::{
    bitcoin_transaction::{fingerprint_code, TransactionTemplate},
    silent_payments::SilentPaymentRecipient,
};
use schnorr_fun::fun::{g, marker::*, Scalar, G};
use std::collections::BTreeMap;
use std::str::FromStr;

fn sp_recipient(scan: u8, spend: u8) -> (SilentPaymentRecipient, String) {
    let point = |byte: u8| {
        let secret = Scalar::<Secret, Zero>::from_bytes_mod_order([byte; 32])
            .non_zero()
            .unwrap();
        g!(secret * G).normalize().non_zero().unwrap()
    };
    let recipient = SilentPaymentRecipient {
        scan_key: point(scan),
        spend_key: point(spend),
    };
    let address = recipient.address(Network::Bitcoin).unwrap();
    (recipient, address)
}

fn mainnet_address(s: &str) -> Address {
    Address::from_str(s)
        .unwrap()
        .require_network(Network::Bitcoin)
        .unwrap()
}

fn pay(template: &mut TransactionTemplate, sats: u64, address: &Address) {
    template.push_foreign_output(TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: address.script_pubkey(),
    });
}

#[test]
fn outputs_fingerprint_fixed_vector() {
    let mut template = TransactionTemplate::new();
    pay(
        &mut template,
        100_000,
        &mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    );
    pay(
        &mut template,
        250_000,
        &mainnet_address("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"),
    );

    let code = fingerprint_code(&template.outputs_fingerprint(Network::Bitcoin));
    assert_eq!(code, "1a50 e39a 473d 614f ffd1 dade fd42 85bb");
}

#[test]
fn outputs_fingerprint_is_stable_across_with_sp_scripts() {
    let mut template = TransactionTemplate::new();
    pay(
        &mut template,
        100_000,
        &mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    );
    let (recipient, address) = sp_recipient(1, 2);
    template.push_silent_payment_output(Amount::from_sat(50_000), recipient, address);
    let before = template.outputs_fingerprint(Network::Bitcoin);

    let shared_secrets = BTreeMap::from([(recipient.scan_key, G.normalize())]);
    let filled = template.with_sp_scripts(&shared_secrets).unwrap();
    assert_eq!(before, filled.outputs_fingerprint(Network::Bitcoin));
}

#[test]
fn outputs_fingerprint_changes_on_amount_address_or_order() {
    let addr1 = mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    let addr2 = mainnet_address("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
    let make = |val1: u64, a1: &Address, val2: u64, a2: &Address| {
        let mut template = TransactionTemplate::new();
        pay(&mut template, val1, a1);
        pay(&mut template, val2, a2);
        template.outputs_fingerprint(Network::Bitcoin)
    };
    let base = make(100_000, &addr1, 250_000, &addr2);
    for changed in [
        make(100_001, &addr1, 250_000, &addr2),
        make(100_000, &addr1, 250_001, &addr2),
        make(100_000, &addr2, 250_000, &addr2),
        make(250_000, &addr2, 100_000, &addr1),
    ] {
        assert_ne!(base, changed);
    }

    let sp = |sats: u64, (recipient, address): (SilentPaymentRecipient, String)| {
        let mut template = TransactionTemplate::new();
        template.push_silent_payment_output(Amount::from_sat(sats), recipient, address);
        template.outputs_fingerprint(Network::Bitcoin)
    };
    let sp_base = sp(100_000, sp_recipient(1, 2));
    assert_ne!(sp_base, sp(100_001, sp_recipient(1, 2)));
    assert_ne!(sp_base, sp(100_000, sp_recipient(3, 4)));
}
