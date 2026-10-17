//! Silent payment sends from a threshold wallet: the ECDH round, the signing round that checks it,
//! and the rejections when a message is tampered with on the way.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{hashes::Hash, Amount, Network, OutPoint, Txid};
use frostsnap_core::{
    bitcoin_transaction::{LocalSpk, TransactionTemplate},
    coordinator::StartSignError,
    device::KeyPurpose,
    message::{
        signing::{CoordinatorSigning, DeviceSigning, RequestSpSign},
        CoordinatorToDeviceMessage, DeviceToCoordinatorMessage,
    },
    silent_payments::{self, output_keys, SilentPaymentRecipient},
    tweak::{AppTweak, BitcoinBip32Path, Xpub},
    AccessStructureRef, DeviceId, MasterAppkey, SignSessionId, SignTaskError, WireSignTask,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use schnorr_fun::{
    frost::{PairedSecretShare, SecretShare, ShareIndex},
    fun::{g, hex, marker::*, poly, s, Point, Scalar, G},
    Schnorr,
};
use serde_json::Value;

use frostsnap_core::test::{
    RunSingleCoordinator as Run, Send, TestDeviceKeyGen, TestEnv, TEST_ENCRYPTION_KEY,
};

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

fn share_index(index: usize) -> ShareIndex {
    Scalar::<Public, Zero>::from(index).non_zero().unwrap()
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

fn owned_path(external: bool, index: u32) -> BitcoinBip32Path {
    if external {
        BitcoinBip32Path::external(index)
    } else {
        BitcoinBip32Path::internal(index)
    }
}

/// The root secret, recovered from the shares of `devices` as a test-only reconstruction.
fn reconstruct_root_secret(
    run: &Run,
    access_structure_ref: AccessStructureRef,
    devices: &BTreeSet<DeviceId>,
) -> Scalar {
    let key = run
        .coordinator
        .get_frost_key(access_structure_ref.key_id)
        .unwrap();
    let contrib = key
        .complete_key
        .coord_share_decryption_contrib(
            access_structure_ref.access_structure_id,
            *devices.iter().next().unwrap(),
            TEST_ENCRYPTION_KEY,
        )
        .unwrap()
        .1;
    let shares = devices
        .iter()
        .map(|device| {
            let index = key
                .access_structures()
                .next()
                .unwrap()
                .device_to_share_indicies()[device];
            let share = run.devices[device]
                .get_encrypted_share(access_structure_ref, index)
                .unwrap()
                .decrypt(access_structure_ref, contrib, &mut TestDeviceKeyGen)
                .unwrap();
            (index, share.share)
        })
        .collect::<Vec<_>>();

    let indices = shares.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let root = shares
        .iter()
        .fold(Scalar::<Secret, Zero>::zero(), |acc, (index, share)| {
            let lambda = poly::eval_basis_poly_at_0(*index, indices.iter().copied());
            s!(acc + lambda * share)
        });
    root.non_zero().unwrap()
}

/// The BIP352 output keys of `recipients`, computed from the input secrets directly: the wallet's
/// root secret is taken whole, each input secret comes from `derive_xonly_key`, and the sum is run
/// through `input_hash` and the shared secret with no threshold involved.
fn expected_output_keys(
    root_secret: Scalar,
    inputs: &[(BitcoinBip32Path, OutPoint)],
    recipients: &[SilentPaymentRecipient],
) -> Vec<[u8; 32]> {
    let root_key = public(root_secret);
    let full_app_share = Xpub::from_rootkey(PairedSecretShare::new_unchecked(
        SecretShare {
            index: share_index(1),
            share: root_secret.mark_zero(),
        },
        root_key,
    ))
    .rootkey_to_master_appkey();

    let a_sum = inputs
        .iter()
        .fold(Scalar::<Secret, Zero>::zero(), |sum, (path, _)| {
            let secret = AppTweak::Bitcoin(*path)
                .derive_xonly_key(&full_app_share)
                .share();
            s!(sum + secret)
        })
        .non_zero()
        .unwrap();

    let outpoints = inputs
        .iter()
        .map(|(_, outpoint)| *outpoint)
        .collect::<Vec<_>>();
    let smallest = silent_payments::smallest_outpoint(&outpoints).unwrap();
    let input_hash = silent_payments::input_hash(&smallest, public(a_sum)).unwrap();

    let shared_secrets = recipients
        .iter()
        .map(|recipient| recipient.scan_key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|scan_key| {
            let secret = g!((input_hash * a_sum) * scan_key)
                .normalize()
                .non_zero()
                .unwrap();
            (scan_key, secret)
        })
        .collect::<BTreeMap<_, _>>();
    output_keys(recipients, &shared_secrets).unwrap()
}

/// A template spending imaginary coins of `master` at `inputs` (path and value), with the outputs
/// given by `outputs`: silent payment `(value, recipient, address)`, then foreign `(value, script)`.
struct SendSpec {
    inputs: Vec<(BitcoinBip32Path, u64)>,
    silent: Vec<(u64, SilentPaymentRecipient, String)>,
    change: Option<(BitcoinBip32Path, u64)>,
}

impl SendSpec {
    fn template(&self, master_appkey: MasterAppkey) -> TransactionTemplate {
        let mut template = TransactionTemplate::new();
        for (path, sats) in &self.inputs {
            template.push_imaginary_owned_input(
                LocalSpk {
                    master_appkey,
                    bip32_path: *path,
                },
                Amount::from_sat(*sats),
            );
        }
        for (sats, recipient, address) in &self.silent {
            template.push_silent_payment_output(
                Amount::from_sat(*sats),
                *recipient,
                address.clone(),
            );
        }
        if let Some((path, sats)) = self.change {
            template.push_owned_output(
                Amount::from_sat(sats),
                LocalSpk {
                    master_appkey,
                    bip32_path: path,
                },
            );
        }
        template
    }
}

/// The outpoints of the template's inputs, in order, as the template reports them.
fn input_outpoints(template: &TransactionTemplate) -> Vec<OutPoint> {
    template
        .inputs()
        .iter()
        .map(|input| input.outpoint())
        .collect()
}

struct Setup {
    run: Run,
    env: TestEnv,
    rng: ChaCha20Rng,
    access_structure_ref: AccessStructureRef,
    master_appkey: MasterAppkey,
}

/// A 2-of-3 bitcoin key with nonces ready.
fn setup(seed: u8) -> Setup {
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
    Setup {
        run,
        env,
        rng,
        access_structure_ref,
        master_appkey,
    }
}

/// The two devices that run the ECDH and the two that sign, in the same 2-of-3 wallet.
fn ecdh_and_signing_sets(run: &Run) -> (BTreeSet<DeviceId>, BTreeSet<DeviceId>) {
    let devices = run.device_vec();
    let ecdh = devices[0..2].iter().copied().collect();
    let signing = devices[1..3].iter().copied().collect();
    (ecdh, signing)
}

/// Runs the ECDH round for `template` on `ecdh`, leaving the session ready to open a signing
/// session.
fn run_ecdh(
    setup: &mut Setup,
    template: &TransactionTemplate,
    ecdh: &BTreeSet<DeviceId>,
) -> frostsnap_core::message::signing::SpEcdhSessionId {
    let (session, sends) = setup
        .run
        .coordinator
        .start_sp_ecdh(
            setup.access_structure_ref,
            WireSignTask::BitcoinTransaction(template.clone()),
            ecdh,
            TEST_ENCRYPTION_KEY,
            &mut setup.rng,
        )
        .unwrap();
    setup.run.extend(sends);
    setup
        .run
        .run_until_finished(&mut setup.env, &mut setup.rng)
        .unwrap();
    session
}

/// Opens the signing session from the ECDH `session` and drives it to completion.
fn sign_from_ecdh(
    setup: &mut Setup,
    session: frostsnap_core::message::signing::SpEcdhSessionId,
    signing: &BTreeSet<DeviceId>,
) -> SignSessionId {
    let session_id = setup
        .run
        .coordinator
        .start_sp_sign(session, signing, &mut setup.rng)
        .unwrap();
    for device in signing {
        let sign_req =
            setup
                .run
                .coordinator
                .request_device_sign(session_id, *device, TEST_ENCRYPTION_KEY);
        setup.run.extend(sign_req);
    }
    setup
        .run
        .run_until_finished(&mut setup.env, &mut setup.rng)
        .unwrap();
    session_id
}

/// The completed template of a finished silent payment signing session.
fn completed_template(run: &Run, session_id: SignSessionId) -> WireSignTask {
    run.coordinator
        .finished_signing_sessions()
        .get(&session_id)
        .unwrap()
        .init
        .group_request
        .sign_task
        .clone()
}

/// The x-only key that each silent payment output of `task` pays to, in output order.
fn paid_keys(task: &WireSignTask) -> Vec<[u8; 32]> {
    let WireSignTask::BitcoinTransaction(template) = task else {
        panic!("expected a bitcoin transaction")
    };
    template
        .silent_payment_outputs()
        .map(|sp| {
            let script = sp.script.as_ref().expect("completed outputs have scripts");
            assert!(script.is_p2tr());
            script.as_bytes()[2..34].try_into().unwrap()
        })
        .collect()
}

/// Asserts the finished session produced valid signatures and pays the silent payment outputs the
/// keys that the test computes independently.
fn assert_sp_send_is_correct(
    setup: &Setup,
    session_id: SignSessionId,
    root_secret: Scalar,
    expected_inputs: &[(BitcoinBip32Path, OutPoint)],
    recipients: &[SilentPaymentRecipient],
) {
    let task = completed_template(&setup.run, session_id);
    let checked = task
        .clone()
        .check(setup.master_appkey, purpose())
        .expect("the completed send is a valid sign task");
    let schnorr = Schnorr::<sha2::Sha256>::verify_only();
    assert!(checked.verify_final_signatures(&schnorr, &setup.env.signatures[&session_id]));

    assert_eq!(
        paid_keys(&task),
        expected_output_keys(root_secret, expected_inputs, recipients),
        "silent payment outputs must match an independent BIP352 computation"
    );
}

fn inputs_with_outpoints(
    template: &TransactionTemplate,
    paths: &[BitcoinBip32Path],
) -> Vec<(BitcoinBip32Path, OutPoint)> {
    paths
        .iter()
        .copied()
        .zip(input_outpoints(template))
        .collect()
}

#[test]
fn silent_payment_send_from_two_of_three_with_split_ecdh_and_signing_sets() {
    let mut setup = setup(42);
    let (ecdh, signing) = ecdh_and_signing_sets(&setup.run);
    let (recipient, address) = recipient(0x11, 0x12);

    let spec = SendSpec {
        inputs: vec![
            (owned_path(true, 7), 42_000),
            (owned_path(false, 42), 1_337_000),
        ],
        silent: vec![(50_000, recipient, address)],
        change: Some((owned_path(false, 3), 1_200_000)),
    };
    let template = spec.template(setup.master_appkey);
    let inputs = inputs_with_outpoints(&template, &[owned_path(true, 7), owned_path(false, 42)]);

    let session = run_ecdh(&mut setup, &template, &ecdh);
    let session_id = sign_from_ecdh(&mut setup, session, &signing);

    let root_secret = reconstruct_root_secret(&setup.run, setup.access_structure_ref, &ecdh);
    assert_sp_send_is_correct(&setup, session_id, root_secret, &inputs, &[recipient]);
}

#[test]
fn silent_payment_send_with_several_inputs_recipients_and_ordinary_outputs() {
    let mut setup = setup(7);
    let (ecdh, signing) = ecdh_and_signing_sets(&setup.run);
    let (first, first_address) = recipient(0x21, 0x22);
    let (second, second_address) = recipient(0x21, 0x23);
    let (third, third_address) = recipient(0x24, 0x25);

    let paths = [
        owned_path(true, 0),
        owned_path(false, 1),
        owned_path(true, 5),
    ];
    let spec = SendSpec {
        inputs: vec![
            (paths[0], 100_000),
            (paths[1], 200_000),
            (paths[2], 300_000),
        ],
        silent: vec![
            (50_000, first, first_address),
            (50_000, second, second_address),
            (50_000, third, third_address),
        ],
        change: Some((owned_path(false, 2), 200_000)),
    };
    let template = spec.template(setup.master_appkey);
    let inputs = inputs_with_outpoints(&template, &paths);

    let session = run_ecdh(&mut setup, &template, &ecdh);
    let session_id = sign_from_ecdh(&mut setup, session, &signing);

    let root_secret = reconstruct_root_secret(&setup.run, setup.access_structure_ref, &ecdh);
    assert_sp_send_is_correct(
        &setup,
        session_id,
        root_secret,
        &inputs,
        &[first, second, third],
    );
}

/// The silent payment sign request in flight to a device, if `send` is one.
fn sp_sign_request(send: &mut Send) -> Option<&mut RequestSpSign> {
    match send {
        Send::CoordinatorToDevice {
            message: CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpSign(request)),
            ..
        } => Some(request.as_mut()),
        _ => None,
    }
}

/// The sign send used by the device tests: one silent payment output and a change output.
fn device_test_spec(master_appkey: MasterAppkey) -> (TransactionTemplate, SilentPaymentRecipient) {
    let (recipient, address) = recipient(0x31, 0x32);
    let spec = SendSpec {
        inputs: vec![(owned_path(true, 1), 90_000)],
        silent: vec![(60_000, recipient, address)],
        change: Some((owned_path(false, 4), 20_000)),
    };
    (spec.template(master_appkey), recipient)
}

/// Runs the device test send up to its signing requests, corrupts the requests in flight with
/// `corrupt`, and returns the reason the devices refused the run.
fn refusal_of_corrupted_requests(corrupt: impl Fn(&mut Send)) -> String {
    let mut setup = setup(9);
    let (ecdh, signing) = ecdh_and_signing_sets(&setup.run);
    let (template, _) = device_test_spec(setup.master_appkey);

    let session = run_ecdh(&mut setup, &template, &ecdh);
    let session_id = setup
        .run
        .coordinator
        .start_sp_sign(session, &signing, &mut setup.rng)
        .unwrap();
    for device in &signing {
        let sign_req =
            setup
                .run
                .coordinator
                .request_device_sign(session_id, *device, TEST_ENCRYPTION_KEY);
        setup.run.extend(sign_req);
    }

    let result = setup.run.run_until(&mut setup.env, &mut setup.rng, |run| {
        for send in run.message_queue_mut().iter_mut() {
            corrupt(send);
        }
        run.message_queue().is_empty()
    });
    result
        .expect_err("the devices must refuse the corrupted request")
        .to_string()
}

/// A completed template with the first silent payment script replaced by a fixed other key.
fn with_other_sp_script(task: &WireSignTask) -> WireSignTask {
    let WireSignTask::BitcoinTransaction(template) = task else {
        panic!("expected a bitcoin transaction")
    };
    // The key is 32 bytes in the encoding, so its first occurrence is the script's.
    let encoded = bincode::encode_to_vec(template, bincode::config::standard()).unwrap();
    let key = paid_keys(task)[0];
    let other = public(scalar(0x79)).to_xonly_bytes();
    let at = encoded
        .windows(32)
        .position(|window| window == key)
        .expect("the key is in the encoding");
    let mut tampered = encoded.clone();
    tampered[at..at + 32].copy_from_slice(&other);
    let (decoded, _) = bincode::decode_from_slice(&tampered, bincode::config::standard())
        .expect("still a template");
    WireSignTask::BitcoinTransaction(decoded)
}

#[test]
fn device_refuses_a_tampered_ecdh_share() {
    let refusal = refusal_of_corrupted_requests(|send| {
        if let Some(request) = sp_sign_request(send) {
            request.sp_proofs.shares[0].ecdh_share = public(scalar(0x77));
        }
    });
    assert!(
        refusal.contains("silent payment ECDH share has a bad proof"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn device_refuses_a_bad_proof() {
    let refusal = refusal_of_corrupted_requests(|send| {
        if let Some(request) = sp_sign_request(send) {
            // Another share's proof, which is valid for that share and not for this one.
            let other = request.sp_proofs.shares[1].proof;
            request.sp_proofs.shares[0].proof = other;
        }
    });
    assert!(
        refusal.contains("silent payment ECDH share has a bad proof"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn device_refuses_an_app_poly_that_does_not_match_the_access_structure() {
    let refusal = refusal_of_corrupted_requests(|send| {
        if let Some(request) = sp_sign_request(send) {
            request.sp_proofs.app_poly[1] = public(scalar(0x78)).mark_zero();
        }
    });
    assert!(
        refusal.contains("app polynomial does not match the access structure"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn device_refuses_a_template_whose_silent_payment_script_is_not_derived() {
    let refusal = refusal_of_corrupted_requests(|send| {
        if let Some(request) = sp_sign_request(send) {
            request.request_sign.group_sign_req.sign_task =
                with_other_sp_script(&request.request_sign.group_sign_req.sign_task);
        }
    });
    assert!(
        refusal.contains("silent payment output scripts do not match the ECDH shares"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn device_refuses_fewer_ecdh_shares_than_the_threshold() {
    let setup = setup(9);
    let master_appkey = setup.master_appkey;
    let (holes, _) = device_test_spec(master_appkey);

    let refusal = refusal_of_corrupted_requests(|send| {
        if let Some(request) = sp_sign_request(send) {
            // One of the two shares: its proof is valid, and the scripts are rederived from it so
            // they match the bundle. Only the threshold check can catch it.
            let first = request.sp_proofs.shares[0].share_index;
            request
                .sp_proofs
                .shares
                .retain(|share| share.share_index == first);
            let secrets = holes
                .sp_shared_secrets(master_appkey, &request.sp_proofs.shares)
                .expect("a single share still combines");
            let scripts = holes
                .with_sp_scripts(&secrets)
                .expect("scripts derive from the single share");
            request.request_sign.group_sign_req.sign_task =
                WireSignTask::BitcoinTransaction(scripts);
        }
    });
    assert!(
        refusal.contains("fewer silent payment ECDH shares than the threshold"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn device_refuses_a_template_with_a_missing_silent_payment_script() {
    let setup = setup(9);
    let (template, _) = device_test_spec(setup.master_appkey);
    let holes = WireSignTask::BitcoinTransaction(template);

    let refusal = refusal_of_corrupted_requests(|send| {
        if let Some(request) = sp_sign_request(send) {
            request.request_sign.group_sign_req.sign_task = holes.clone();
        }
    });
    assert!(
        refusal.contains("A silent payment output has no script yet"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn device_refuses_silent_payment_outputs_sent_without_their_proofs() {
    let refusal = refusal_of_corrupted_requests(|send| {
        let Send::CoordinatorToDevice { message, .. } = send else {
            return;
        };
        let CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpSign(request)) =
            message
        else {
            return;
        };
        let plain = CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(
            request.request_sign.clone(),
        )));
        *message = plain;
    });
    assert!(
        refusal.contains("silent payment outputs without their proofs"),
        "refused for the wrong reason: {refusal}"
    );
}

#[test]
fn coordinator_refuses_a_device_with_a_bad_proof() {
    let mut setup = setup(11);
    let (ecdh, _) = ecdh_and_signing_sets(&setup.run);
    let (recipient, address) = recipient(0x41, 0x42);
    let spec = SendSpec {
        inputs: vec![(owned_path(true, 3), 90_000)],
        silent: vec![(60_000, recipient, address)],
        change: None,
    };
    let template = spec.template(setup.master_appkey);
    let (_, sends) = setup
        .run
        .coordinator
        .start_sp_ecdh(
            setup.access_structure_ref,
            WireSignTask::BitcoinTransaction(template),
            &ecdh,
            TEST_ENCRYPTION_KEY,
            &mut setup.rng,
        )
        .unwrap();
    setup.run.extend(sends);

    let result = setup.run.run_until(&mut setup.env, &mut setup.rng, |run| {
        for send in run.message_queue_mut().iter_mut() {
            if let Send::DeviceToCoordinator {
                message:
                    DeviceToCoordinatorMessage::Signing(DeviceSigning::SpEcdhShares { shares, .. }),
                ..
            } = send
            {
                shares[0].proof = [0u8; 64];
            }
        }
        run.message_queue().is_empty()
    });
    let error = result.expect_err("the coordinator must refuse the bad proof");
    assert!(
        error
            .to_string()
            .contains("silent payment ECDH share has a bad proof"),
        "refused for the wrong reason: {error}"
    );
}

#[test]
fn silent_payment_ecdh_survives_a_coordinator_restart() {
    let mut setup = setup(13);
    let (ecdh, signing) = ecdh_and_signing_sets(&setup.run);
    let (recipient, address) = recipient(0x51, 0x52);
    let paths = [owned_path(true, 9), owned_path(false, 10)];
    let spec = SendSpec {
        inputs: vec![(paths[0], 500_000), (paths[1], 600_000)],
        silent: vec![(70_000, recipient, address)],
        change: Some((owned_path(false, 11), 1_000_000)),
    };
    let template = spec.template(setup.master_appkey);
    let inputs = inputs_with_outpoints(&template, &paths);

    let session = run_ecdh(&mut setup, &template, &ecdh);

    // Restart: the coordinator is rebuilt from its mutations alone.
    setup.run.check_mutations();
    setup.run.coordinator = setup.run.start_coordinator.clone();

    let session_id = sign_from_ecdh(&mut setup, session, &signing);
    let root_secret = reconstruct_root_secret(&setup.run, setup.access_structure_ref, &ecdh);
    assert_sp_send_is_correct(&setup, session_id, root_secret, &inputs, &[recipient]);
}

#[test]
fn silent_payment_send_refuses_foreign_inputs() {
    let mut setup = setup(15);
    let (ecdh, _) = ecdh_and_signing_sets(&setup.run);
    let (recipient, address) = recipient(0x61, 0x62);

    let mut template = TransactionTemplate::new();
    template.push_imaginary_owned_input(
        LocalSpk {
            master_appkey: setup.master_appkey,
            bip32_path: owned_path(true, 0),
        },
        Amount::from_sat(100_000),
    );
    let foreign = bitcoin::TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(
            [&[0x51u8, 0x20][..], &[0xee; 32][..]].concat(),
        ),
    };
    template.push_foreign_input(
        frostsnap_core::bitcoin_transaction::PushInput::spend_outpoint(
            &foreign,
            OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
        ),
    );
    template.push_silent_payment_output(Amount::from_sat(50_000), recipient, address);

    let result = setup.run.coordinator.start_sp_ecdh(
        setup.access_structure_ref,
        WireSignTask::BitcoinTransaction(template),
        &ecdh,
        TEST_ENCRYPTION_KEY,
        &mut setup.rng,
    );
    assert!(matches!(
        result,
        Err(StartSignError::SignTask(SignTaskError::SilentPaymentInputs))
    ));
}

#[test]
fn silent_payment_send_refuses_an_address_that_is_not_its_keys() {
    let mut setup = setup(17);
    let (ecdh, _) = ecdh_and_signing_sets(&setup.run);
    let (mismatched, _) = recipient(0x71, 0x72);
    let (_, other_address) = recipient(0x73, 0x74);

    let spec = SendSpec {
        inputs: vec![(owned_path(true, 0), 100_000)],
        silent: vec![(50_000, mismatched, other_address)],
        change: None,
    };
    let result = setup.run.coordinator.start_sp_ecdh(
        setup.access_structure_ref,
        WireSignTask::BitcoinTransaction(spec.template(setup.master_appkey)),
        &ecdh,
        TEST_ENCRYPTION_KEY,
        &mut setup.rng,
    );
    assert!(matches!(
        result,
        Err(StartSignError::SignTask(
            SignTaskError::SilentPaymentAddressMismatch
        ))
    ));
}

#[test]
fn a_template_with_holes_is_not_signable() {
    let setup = setup(19);
    let (recipient, address) = recipient(0x81, 0x82);
    let spec = SendSpec {
        inputs: vec![(owned_path(true, 0), 100_000)],
        silent: vec![(50_000, recipient, address)],
        change: None,
    };
    let holes = WireSignTask::BitcoinTransaction(spec.template(setup.master_appkey));
    assert!(matches!(
        holes.check(setup.master_appkey, purpose()),
        Err(SignTaskError::SilentPaymentScriptMissing)
    ));
}

/// Every recipient in the BIP352 sending vectors has the address the vector gives for its keys.
#[test]
fn recipient_addresses_match_bip352_vectors() {
    let cases: Value =
        serde_json::from_str(include_str!("data/bip352_sending_vectors.json")).unwrap();
    let point =
        |value: &Value| Point::from_slice(&hex::decode(value.as_str().unwrap()).unwrap()).unwrap();
    let mut checked = 0;
    for case in cases.as_array().unwrap() {
        for sending in case["sending"].as_array().unwrap() {
            for entry in sending["given"]["recipients"].as_array().unwrap() {
                let address = entry["address"].as_str().unwrap();
                let network = if address.starts_with("tsp1") {
                    Network::Testnet
                } else {
                    Network::Bitcoin
                };
                let recipient = SilentPaymentRecipient {
                    scan_key: point(&entry["scan_pub_key"]),
                    spend_key: point(&entry["spend_pub_key"]),
                };
                assert_eq!(
                    recipient.address(network).as_deref(),
                    Some(address),
                    "{}",
                    case["comment"]
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
}
