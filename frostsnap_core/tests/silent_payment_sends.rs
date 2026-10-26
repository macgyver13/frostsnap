//! Silent payment sends from a threshold wallet: the checks a template must pass, the ECDH round
//! that derives the silent payment scripts, and the rejections of a tampered ECDH request.

use bitcoin::{hashes::Hash, Amount, Network, OutPoint, Txid};
use frostsnap_core::{
    bitcoin_transaction::{LocalSpk, PromptDestination, PushInput, TransactionTemplate},
    coordinator::{CoordinatorSend, SignSession, StartSignError},
    device::KeyPurpose,
    message::signing::SpEcdhSessionId,
    message::{
        signing::{CoordinatorSigning, DeviceSigning},
        CoordinatorToDeviceMessage, DeviceToCoordinatorMessage,
    },
    silent_payments::SilentPaymentRecipient,
    tweak::{BitcoinBip32Path, NormalIndex},
    AccessStructureRef, DeviceId, MasterAppkey, SignTaskError, WireSignTask,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use schnorr_fun::{
    fun::{g, marker::*, Point, Scalar, G},
    Schnorr,
};
use std::collections::{BTreeMap, BTreeSet};

mod common;
mod env;
use crate::common::{Run, Send, TEST_ENCRYPTION_KEY};
use crate::env::TestEnv;

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

/// A 2-of-3 bitcoin wallet with its nonces ready, and the coordinator's view of its key.
struct Wallet {
    run: Run,
    env: TestEnv,
    rng: ChaCha20Rng,
    access_structure_ref: AccessStructureRef,
    master_appkey: MasterAppkey,
}

fn wallet(seed: u8) -> Wallet {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut env = TestEnv::default();
    let run = Run::start_after_keygen_and_nonces(3, 2, &mut env, &mut rng, 1, purpose());
    let access_structure_ref = run
        .coordinator
        .iter_access_structures()
        .next()
        .unwrap()
        .access_structure_ref();
    let master_appkey = run
        .coordinator
        .get_frost_key(access_structure_ref.key_id)
        .unwrap()
        .complete_key
        .master_appkey;
    Wallet {
        run,
        env,
        rng,
        access_structure_ref,
        master_appkey,
    }
}

/// Starts an ECDH round for a send of one silent payment to `recipient`, asking `devices`.
/// Returns the session and the requests, which the caller delivers.
fn start_ecdh_with(
    wallet: &mut Wallet,
    recipient: (SilentPaymentRecipient, String),
    devices: &BTreeSet<DeviceId>,
) -> (SpEcdhSessionId, Vec<CoordinatorSend>) {
    let mut template = TransactionTemplate::new();
    owned_input(&mut template, wallet.master_appkey, 100_000);
    template.push_silent_payment_output(Amount::from_sat(50_000), recipient.0, recipient.1);
    wallet
        .run
        .coordinator
        .start_sp_ecdh(
            wallet.access_structure_ref,
            WireSignTask::BitcoinTransaction(template),
            devices,
            TEST_ENCRYPTION_KEY,
            &mut wallet.rng,
        )
        .unwrap()
}

/// Starts an ECDH round asking the first two devices, which is a threshold, and delivers it.
fn start_ecdh(wallet: &mut Wallet, recipient: (SilentPaymentRecipient, String)) {
    let devices: BTreeSet<_> = wallet.run.device_vec().into_iter().take(2).collect();
    let (_, sends) = start_ecdh_with(wallet, recipient, &devices);
    wallet.run.extend(sends);
}

fn asked_device(send: &CoordinatorSend) -> DeviceId {
    let CoordinatorSend::ToDevice { destinations, .. } = send else {
        panic!("an ECDH request is addressed to a device");
    };
    *destinations.iter().next().expect("one destination")
}

#[test]
fn silent_payment_ecdh_round_with_a_threshold_completes() {
    let mut wallet = wallet(21);
    start_ecdh(&mut wallet, recipient(0x91, 0x92));
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();
}

#[test]
fn device_refuses_an_ecdh_request_for_other_scan_keys() {
    let mut wallet = wallet(23);
    start_ecdh(&mut wallet, recipient(0xa1, 0xa2));

    let result =
        wallet
            .run
            .run_until(&mut wallet.env, &mut wallet.rng, |run| {
                for send in run.message_queue.iter_mut() {
                    if let Send::CoordinatorToDevice {
                        message:
                            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpEcdh(
                                request,
                            )),
                        ..
                    } = send
                    {
                        request.scan_keys.push(public(scalar(0xa3)));
                    }
                }
                run.message_queue.is_empty()
            });
    let error = result.expect_err("the device must refuse the tampered request");
    assert!(
        error
            .to_string()
            .contains("silent payment ECDH request does not match its transaction"),
        "refused for the wrong reason: {error}"
    );
}

#[test]
fn coordinator_refuses_a_device_with_a_bad_proof() {
    let mut wallet = wallet(11);
    start_ecdh(&mut wallet, recipient(0x41, 0x42));

    let result = wallet
        .run
        .run_until(&mut wallet.env, &mut wallet.rng, |run| {
            for send in run.message_queue.iter_mut() {
                if let Send::DeviceToCoordinator {
                    message:
                        DeviceToCoordinatorMessage::Signing(DeviceSigning::SpEcdhShares {
                            shares, ..
                        }),
                    ..
                } = send
                {
                    shares[0].proof = [0u8; 64];
                }
            }
            run.message_queue.is_empty()
        });
    let error = result.expect_err("the coordinator must refuse the bad proof");
    assert!(
        error
            .to_string()
            .contains("silent payment ECDH share has a bad proof"),
        "refused for the wrong reason: {error}"
    );
}

/// A local send asks every selected device, then signs with the ones that answered once there is a
/// threshold. The devices are asked with the proofs, and the signed transaction pays the silent
/// payment output a derived script.
#[test]
fn local_silent_payment_send_signs_with_the_devices_that_answered() {
    let mut wallet = wallet(31);
    let selected: BTreeSet<_> = wallet.run.device_vec().into_iter().collect();
    let (ecdh_session, sends) = start_ecdh_with(&mut wallet, recipient(0x31, 0x32), &selected);
    assert_eq!(sends.len(), 3, "one request per selected device");

    // The third device never answers.
    let signers: BTreeSet<_> = sends.iter().take(2).map(asked_device).collect();
    wallet.run.extend(sends.into_iter().take(2));
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();

    let session_id = wallet
        .run
        .coordinator
        .start_sign_sp(ecdh_session, &mut wallet.rng)
        .unwrap();
    let signing_set: BTreeSet<_> = wallet
        .run
        .coordinator
        .active_signing_sessions_by_ssid()
        .get(&session_id)
        .unwrap()
        .init
        .nonces
        .keys()
        .copied()
        .collect();
    assert_eq!(signing_set, signers);

    for device_id in &signers {
        let sign_req =
            wallet
                .run
                .coordinator
                .request_device_sign(session_id, *device_id, TEST_ENCRYPTION_KEY);
        wallet.run.extend(sign_req);
    }
    assert!(
        wallet.run.message_queue.iter().all(|send| matches!(
            send,
            Send::CoordinatorToDevice {
                message: CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpSign(_)),
                ..
            }
        )),
        "the devices must be asked with RequestSpSign"
    );
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();

    let Some(SignSession::Finished(finished)) = wallet.run.coordinator.get_sign_session(session_id)
    else {
        panic!("the send should have finished");
    };
    let checked = finished
        .init
        .group_request
        .sign_task
        .clone()
        .check(wallet.master_appkey, purpose())
        .unwrap();
    let signatures = wallet.env.signatures.get(&session_id).unwrap();
    assert!(checked.verify_final_signatures(&Schnorr::<sha2::Sha256>::verify_only(), signatures));

    let WireSignTask::BitcoinTransaction(paid) = &finished.init.group_request.sign_task else {
        panic!("expected a bitcoin transaction");
    };
    let output = paid.silent_payment_outputs().next().unwrap();
    assert!(output
        .script
        .as_ref()
        .is_some_and(|script| script.is_p2tr()));
}

#[test]
fn local_ecdh_refuses_to_open_signing_before_a_threshold_has_answered() {
    let mut wallet = wallet(33);
    let selected: BTreeSet<_> = wallet.run.device_vec().into_iter().take(2).collect();
    let (ecdh_session, sends) = start_ecdh_with(&mut wallet, recipient(0x33, 0x34), &selected);
    // Only one of the two answers.
    wallet.run.extend(sends.into_iter().take(1));
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();

    let result = wallet
        .run
        .coordinator
        .start_sign_sp(ecdh_session, &mut wallet.rng);
    assert!(
        matches!(
            result,
            Err(StartSignError::NotEnoughDevicesSelected { selected: 1, .. })
        ),
        "got {result:?}"
    );
}

/// A device rederives the silent payment scripts from the proofs before it shows a sign request,
/// so a host that swaps a script is refused.
#[test]
fn device_refuses_a_sign_request_whose_script_does_not_match_the_proofs() {
    let mut wallet = wallet(35);
    let selected: BTreeSet<_> = wallet.run.device_vec().into_iter().take(2).collect();
    let (ecdh_session, sends) = start_ecdh_with(&mut wallet, recipient(0x35, 0x36), &selected);
    wallet.run.extend(sends);
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();
    let session_id = wallet
        .run
        .coordinator
        .start_sign_sp(ecdh_session, &mut wallet.rng)
        .unwrap();
    for device_id in &selected {
        let sign_req =
            wallet
                .run
                .coordinator
                .request_device_sign(session_id, *device_id, TEST_ENCRYPTION_KEY);
        wallet.run.extend(sign_req);
    }

    let result =
        wallet
            .run
            .run_until(&mut wallet.env, &mut wallet.rng, |run| {
                for send in run.message_queue.iter_mut() {
                    if let Send::CoordinatorToDevice {
                        message:
                            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpSign(
                                request,
                            )),
                        ..
                    } = send
                    {
                        let WireSignTask::BitcoinTransaction(template) =
                            &mut request.request_sign.group_sign_req.sign_task
                        else {
                            unreachable!("a silent payment send is a bitcoin transaction")
                        };
                        // A well formed P2TR script, from a secret that is not the wallet's ECDH.
                        let scan_key = template.silent_payment_scan_keys()[0];
                        let not_the_ecdh = BTreeMap::from([(scan_key, public(scalar(0x99)))]);
                        *template = template.with_sp_scripts(&not_the_ecdh).unwrap();
                    }
                }
                run.message_queue.is_empty()
            });
    let error = result.expect_err("the device must refuse the swapped script");
    assert!(
        error
            .to_string()
            .contains("silent payment output scripts do not match the ECDH shares"),
        "refused for the wrong reason: {error}"
    );
}
