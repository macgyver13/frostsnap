//! Trusted silent payment contacts: adding one with a threshold of devices, and the checks a send
//! to one must pass.

use bitcoin::{hashes::Hash, Amount, Network, OutPoint, Txid};
use frostsnap_core::{
    bitcoin_transaction::{LocalSpk, PromptContact, PushInput, TransactionTemplate},
    coordinator::StartSignError,
    device::KeyPurpose,
    message::{
        signing::{CoordinatorSigning, RequestSpContactSign},
        CoordinatorToDeviceMessage,
    },
    silent_payments::{
        verify_contact_shares, ChangeSetError, ContactChange, ContactChangeSet, SignedSpContact,
        SignedSpContactChanges, SilentPaymentRecipient, SpContactChanges, SpContactDetails,
    },
    tweak::BitcoinBip32Path,
    AccessStructureRef, DeviceId, MasterAppkey, SignTaskError, WireSignTask,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use schnorr_fun::{
    fun::{g, marker::*, Point, Scalar, G},
    Schnorr,
};
use std::collections::{BTreeMap, BTreeSet};

use frostsnap_core::test::{RunSingleCoordinator as Run, TestEnv, TEST_ENCRYPTION_KEY};

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

fn details(name: &str, scan: u8, spend: u8) -> SpContactDetails {
    SpContactDetails {
        name: name.into(),
        recipient: SilentPaymentRecipient {
            scan_key: public(scalar(scan)),
            spend_key: public(scalar(spend)),
        },
    }
}

/// A 2-of-3 bitcoin key, ready to sign.
struct Wallet {
    run: Run,
    env: TestEnv,
    rng: ChaCha20Rng,
    access_structure_ref: AccessStructureRef,
    master: MasterAppkey,
    devices: Vec<DeviceId>,
}

impl Wallet {
    fn new() -> Self {
        let mut env = TestEnv::default();
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let run = Run::start_after_keygen_and_nonces(3, 2, &mut env, &mut rng, 1, purpose());
        let key = run.coordinator.iter_keys().next().unwrap().clone();
        let access_structure_ref = key
            .access_structures()
            .next()
            .unwrap()
            .access_structure_ref();
        let devices = run.device_vec();
        Self {
            run,
            env,
            rng,
            access_structure_ref,
            master: key.complete_key.master_appkey,
            devices,
        }
    }

    fn signers(&self, indices: &[usize]) -> BTreeSet<DeviceId> {
        indices.iter().map(|i| self.devices[*i]).collect()
    }

    /// `changes` to the book as it is now.
    fn change_set(&self, changes: Vec<ContactChange>) -> ContactChangeSet {
        ContactChangeSet {
            head: self
                .run
                .coordinator
                .sp_contact_book_head(self.access_structure_ref.key_id),
            changes,
        }
    }

    /// Runs the ECDH round of `changes` on `signers`, stopping before anything is signed.
    fn changes_ecdh(
        &mut self,
        changes: Vec<ContactChange>,
        signers: &[usize],
    ) -> frostsnap_core::message::signing::SpContactSessionId {
        let set = self.change_set(changes);
        let signers = self.signers(signers);
        let (session_id, sends) = self
            .run
            .coordinator
            .start_sp_contact(
                self.access_structure_ref,
                set,
                &signers,
                TEST_ENCRYPTION_KEY,
                &mut self.rng,
            )
            .unwrap();
        self.run.extend(sends);
        self.run
            .run_until_finished(&mut self.env, &mut self.rng)
            .unwrap();
        session_id
    }

    /// Runs the ECDH round of adding `details` on `signers`.
    fn contact_ecdh(
        &mut self,
        details: SpContactDetails,
        signers: &[usize],
    ) -> frostsnap_core::message::signing::SpContactSessionId {
        self.changes_ecdh(vec![ContactChange::Add(details)], signers)
    }

    /// Confirms and signs `changes` on `signers` and applies them to the book.
    fn change_book(
        &mut self,
        changes: Vec<ContactChange>,
        signers: &[usize],
    ) -> SignedSpContactChanges {
        let sign_session = sign_changes(self, changes, signers);
        self.run
            .coordinator
            .finish_sp_contact(sign_session)
            .unwrap()
    }

    fn add_contact(&mut self, details: SpContactDetails, signers: &[usize]) -> SignedSpContact {
        let name = details.name.clone();
        self.change_book(vec![ContactChange::Add(details)], signers);
        self.contact(&name).unwrap()
    }

    fn contact(&self, name: &str) -> Option<SignedSpContact> {
        self.run
            .coordinator
            .sp_contact_book(self.access_structure_ref.key_id)?
            .by_name(name)
            .cloned()
    }

    fn names(&self) -> Vec<String> {
        let mut names = self
            .run
            .coordinator
            .sp_contacts(self.access_structure_ref.key_id)
            .map(|contact| contact.contact.details.name.clone())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn template_paying(&self, contact: &SignedSpContact) -> TransactionTemplate {
        let mut template = TransactionTemplate::new();
        template.push_imaginary_owned_input(
            LocalSpk {
                master_appkey: self.master,
                bip32_path: BitcoinBip32Path::external(0),
            },
            Amount::from_sat(100_000),
        );
        let address = contact
            .contact
            .details
            .recipient
            .address(NETWORK)
            .expect("address");
        template.push_silent_payment_output(Amount::from_sat(50_000), contact.clone(), address);
        template
    }

    /// The contact's sign request for `device`, ready to be tampered with.
    fn contact_sign_request(
        &mut self,
        details: SpContactDetails,
        signers: &[usize],
        device: usize,
    ) -> RequestSpContactSign {
        let session_id = self.contact_ecdh(details, signers);
        let sign_session = self
            .run
            .coordinator
            .start_sp_contact_sign(session_id, &mut self.rng)
            .unwrap();
        let request = self.run.coordinator.request_device_sign(
            sign_session,
            self.devices[device],
            TEST_ENCRYPTION_KEY,
        );
        RequestSpContactSign {
            proofs: request.sp_contact_proofs.expect("a contact has proofs"),
            request_sign: request.request_sign,
        }
    }

    fn device_accepts(&mut self, device: usize, message: CoordinatorSigning) -> bool {
        let id = self.devices[device];
        self.run
            .devices
            .get_mut(&id)
            .unwrap()
            .recv_coordinator_message(CoordinatorToDeviceMessage::Signing(message), &mut self.rng)
            .is_ok()
    }
}

#[test]
fn any_quorum_adds_the_same_contact_under_the_wallet_signature() {
    let mut wallet = Wallet::new();
    let details = details("Alice", 0x11, 0x12);

    let key_id = wallet.access_structure_ref.key_id;
    let by_first = wallet.add_contact(details.clone(), &[0, 1]);
    assert_eq!(wallet.run.coordinator.sp_contacts(key_id).count(), 1);
    wallet.change_book(vec![ContactChange::Remove(details.clone())], &[0, 2]);
    assert_eq!(wallet.run.coordinator.sp_contacts(key_id).count(), 0);
    let by_last = wallet.add_contact(details, &[1, 2]);

    assert_eq!(by_first.contact.account_ecdh, by_last.contact.account_ecdh);
    assert!(by_first.verify(wallet.master, NETWORK));
    assert!(by_last.verify(wallet.master, NETWORK));
}

/// A send to a contact is an ordinary sign request, and a device that never confirmed the contact
/// signs it. `a_bip352_receiver_finds_every_output_paid_to_a_contact` checks the scripts.
#[test]
fn a_device_that_never_confirmed_the_contact_signs_a_send() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Bob", 0x21, 0x22), &[0, 1]);

    let template = wallet
        .template_paying(&contact)
        .with_contact_sp_scripts(wallet.master)
        .unwrap();
    let task = WireSignTask::BitcoinTransaction(template);

    let signers = wallet.signers(&[1, 2]);
    let session = wallet
        .run
        .coordinator
        .start_sign(
            wallet.access_structure_ref,
            task.clone(),
            &signers,
            &mut wallet.rng,
        )
        .unwrap();
    for device in &signers {
        let request =
            wallet
                .run
                .coordinator
                .request_device_sign(session, *device, TEST_ENCRYPTION_KEY);
        assert_eq!(request.sp_contact_proofs, None);
        wallet.run.extend(request);
    }
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();
    let checked = task.check(wallet.master, purpose()).unwrap();
    assert!(checked.verify_final_signatures(
        &Schnorr::<sha2::Sha256>::verify_only(),
        wallet.env.signatures.get(&session).unwrap()
    ));
}

#[test]
fn a_send_refuses_a_contact_the_wallet_did_not_sign() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Carol", 0x31, 0x32), &[0, 1]);
    let check = |contact: SignedSpContact, wallet: &Wallet| {
        WireSignTask::BitcoinTransaction(wallet.template_paying(&contact))
            .check(wallet.master, purpose())
    };

    let mut renamed = contact.clone();
    renamed.contact.details.name = "Mallory".into();
    assert!(matches!(
        check(renamed, &wallet),
        Err(SignTaskError::SilentPaymentUntrustedContact)
    ));

    let mut other_spend_key = contact.clone();
    other_spend_key.contact.details.recipient.spend_key = public(scalar(0x33));
    assert!(matches!(
        check(other_spend_key, &wallet),
        Err(SignTaskError::SilentPaymentUntrustedContact)
    ));

    let mut other_ecdh = contact.clone();
    other_ecdh.contact.account_ecdh = public(scalar(0x34));
    assert!(matches!(
        check(other_ecdh, &wallet),
        Err(SignTaskError::SilentPaymentUntrustedContact)
    ));

    // Valid for this wallet, not for another.
    let other_wallet = MasterAppkey::derive_from_rootkey(G.normalize());
    assert!(!contact.verify(other_wallet, NETWORK));
}

#[test]
fn a_send_refuses_scripts_the_contact_does_not_derive() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Dave", 0x41, 0x42), &[0, 1]);
    let template = wallet.template_paying(&contact);

    assert!(matches!(
        WireSignTask::BitcoinTransaction(template.clone()).check(wallet.master, purpose()),
        Err(SignTaskError::SilentPaymentScriptMissing)
    ));

    let scan_key = contact.contact.details.recipient.scan_key;
    let wrong = template
        .with_sp_scripts(&BTreeMap::from([(scan_key, public(scalar(0x43)))]))
        .unwrap();
    assert!(matches!(
        WireSignTask::BitcoinTransaction(wrong).check(wallet.master, purpose()),
        Err(SignTaskError::SilentPaymentScriptMismatch)
    ));
}

#[test]
fn a_send_refuses_an_address_that_is_not_the_contacts() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Erin", 0x51, 0x52), &[0, 1]);
    let other_address = details("Other", 0x53, 0x54)
        .recipient
        .address(NETWORK)
        .unwrap();

    let mut template = TransactionTemplate::new();
    template.push_imaginary_owned_input(
        LocalSpk {
            master_appkey: wallet.master,
            bip32_path: BitcoinBip32Path::external(0),
        },
        Amount::from_sat(100_000),
    );
    template.push_silent_payment_output(Amount::from_sat(50_000), contact, other_address);
    assert!(matches!(
        WireSignTask::BitcoinTransaction(template).check(wallet.master, purpose()),
        Err(SignTaskError::SilentPaymentAddressMismatch)
    ));
}

#[test]
fn a_send_refuses_foreign_inputs() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Frank", 0x61, 0x62), &[0, 1]);
    let mut template = wallet.template_paying(&contact);
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
    assert!(matches!(
        WireSignTask::BitcoinTransaction(template).check(wallet.master, purpose()),
        Err(SignTaskError::SilentPaymentInputs)
    ));
}

/// Before its script is derived, a silent payment output is sized as the P2TR output it will
/// become, so the fee rate is the same as the final send's.
#[test]
fn an_unfilled_output_has_the_fee_rate_of_the_final_send() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Grace", 0x71, 0x72), &[0, 1]);
    let pending = wallet.template_paying(&contact);
    let filled = pending.with_contact_sp_scripts(wallet.master).unwrap();
    assert_eq!(pending.feerate(), filled.feerate());
}

/// The signer is shown the contact, and a send with one change output keeps the change hidden.
#[test]
fn the_prompt_shows_the_contact_and_hides_single_change() {
    let mut wallet = Wallet::new();
    let contact = wallet.add_contact(details("Heidi", 0x81, 0x82), &[0, 1]);
    let address = contact.contact.details.recipient.address(NETWORK).unwrap();
    let mut template = wallet.template_paying(&contact);
    template.push_owned_output(
        Amount::from_sat(40_000),
        LocalSpk {
            master_appkey: wallet.master,
            bip32_path: BitcoinBip32Path::internal(0),
        },
    );

    let prompt = template.user_prompt(NETWORK);
    assert!(prompt.foreign_recipients.is_empty());
    assert_eq!(
        prompt.silent_payment_recipients,
        vec![PromptContact {
            name: "Heidi".into(),
            address,
            amount: Amount::from_sat(50_000),
        }]
    );
}

#[test]
fn a_contact_is_not_signed_below_the_threshold() {
    let mut wallet = Wallet::new();
    let signers = wallet.signers(&[0]);
    let set = wallet.change_set(vec![ContactChange::Add(details("Judy", 0x93, 0x94))]);
    let refused = wallet.run.coordinator.start_sp_contact(
        wallet.access_structure_ref,
        set,
        &signers,
        TEST_ENCRYPTION_KEY,
        &mut wallet.rng,
    );
    assert!(matches!(
        refused,
        Err(StartSignError::NotEnoughDevicesSelected { .. })
    ));

    // Asked two devices, only one has answered.
    let session_id = wallet.contact_ecdh(details("Ivan", 0x91, 0x92), &[0, 1]);
    let session = wallet
        .run
        .coordinator
        .sp_contact_session(session_id)
        .unwrap();
    assert_eq!(session.shares.len(), 2);
    let signers = wallet.signers(&[0, 1]);
    let set = wallet.change_set(vec![ContactChange::Add(details("Ivan", 0x91, 0x92))]);
    let (unanswered, _sends) = wallet
        .run
        .coordinator
        .start_sp_contact(
            wallet.access_structure_ref,
            set,
            &signers,
            TEST_ENCRYPTION_KEY,
            &mut wallet.rng,
        )
        .unwrap();
    assert!(matches!(
        wallet
            .run
            .coordinator
            .start_sp_contact_sign(unanswered, &mut wallet.rng),
        Err(StartSignError::NotEnoughDevicesSelected { .. })
    ));
}

#[test]
fn a_device_only_signs_the_contact_its_user_confirmed() {
    let mut wallet = Wallet::new();
    let details = details("Kim", 0xa1, 0xa2);

    let request = wallet.contact_sign_request(details.clone(), &[0, 1], 0);
    assert!(wallet.device_accepts(
        0,
        CoordinatorSigning::RequestSpContactSign(Box::new(request.clone()))
    ));

    // Without its proofs.
    assert!(!wallet.device_accepts(
        0,
        CoordinatorSigning::RequestSign(Box::new(request.request_sign.clone()))
    ));

    // With fewer proofs than the threshold.
    let mut below_threshold = request.clone();
    below_threshold.proofs.shares[0].pop();
    assert!(!wallet.device_accepts(
        0,
        CoordinatorSigning::RequestSpContactSign(Box::new(below_threshold))
    ));

    // With a value the proofs do not give.
    let mut wrong_ecdh = request.clone();
    let WireSignTask::SpContactChanges(changes) = &request.request_sign.group_sign_req.sign_task
    else {
        panic!("a contact request signs contact changes");
    };
    wrong_ecdh.request_sign.group_sign_req.sign_task =
        WireSignTask::SpContactChanges(Box::new(SpContactChanges {
            set: changes.set.clone(),
            account_ecdh: vec![public(scalar(0xa3))],
        }));
    assert!(!wallet.device_accepts(
        0,
        CoordinatorSigning::RequestSpContactSign(Box::new(wrong_ecdh))
    ));

    // After a restart or cancel the approval is gone. The coordinator sends the request again on
    // every reconnect, so the device ignores it instead of failing.
    let id = wallet.devices[0];
    let device = wallet.run.devices.get_mut(&id).unwrap();
    device.clear_tmp_data();
    let sends = device
        .recv_coordinator_message(
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpContactSign(
                Box::new(request),
            )),
            &mut wallet.rng,
        )
        .unwrap();
    assert!(sends.is_empty());
}

/// A proof only counts for the record its device confirmed, so devices shown different records
/// can't be combined. The scan key is the same here, as a swapped spend key would leave it.
#[test]
fn a_proof_does_not_carry_over_to_other_details() {
    let mut wallet = Wallet::new();
    let confirmed = details("Lee", 0xb1, 0xb2);
    let session_id = wallet.contact_ecdh(confirmed.clone(), &[0, 1]);
    let session = wallet
        .run
        .coordinator
        .sp_contact_session(session_id)
        .unwrap()
        .clone();
    let shares = session
        .shares
        .values()
        .map(|shares| shares[0])
        .collect::<Vec<_>>();
    let key = wallet
        .run
        .coordinator
        .get_access_structure(wallet.access_structure_ref)
        .unwrap()
        .app_shared_key();

    assert!(verify_contact_shares(&key, &confirmed, NETWORK, &shares).is_ok());

    let mut other_spend_key = confirmed.clone();
    other_spend_key.recipient.spend_key = public(scalar(0xb3));
    assert!(verify_contact_shares(&key, &other_spend_key, NETWORK, &shares).is_err());

    let mut other_name = confirmed.clone();
    other_name.name = "Mallory".into();
    assert!(verify_contact_shares(&key, &other_name, NETWORK, &shares).is_err());

    assert!(verify_contact_shares(&key, &confirmed, Network::Testnet, &shares).is_err());
}

/// A device that holds more than one share of an access structure must answer with the one the
/// coordinator expects from it.
#[test]
fn a_device_answers_with_the_share_the_request_names() {
    use frostsnap_core::{
        coordinator::CoordinatorSend,
        message::{signing::CoordinatorSigning, CoordinatorToDeviceMessage},
    };
    let mut wallet = Wallet::new();
    let signers = wallet.signers(&[0, 1]);
    let set = wallet.change_set(vec![ContactChange::Add(details("Pia", 0xe1, 0xe2))]);
    let (_, sends) = wallet
        .run
        .coordinator
        .start_sp_contact(
            wallet.access_structure_ref,
            set,
            &signers,
            TEST_ENCRYPTION_KEY,
            &mut wallet.rng,
        )
        .unwrap();
    let request_for = |device: DeviceId| {
        sends
            .iter()
            .find_map(|send| match send {
                CoordinatorSend::ToDevice {
                    message:
                        CoordinatorToDeviceMessage::Signing(
                            CoordinatorSigning::RequestSpContactEcdh(request),
                        ),
                    destinations,
                } if destinations.contains(&device) => Some((**request).clone()),
                _ => None,
            })
            .unwrap()
    };
    let mut request = request_for(wallet.devices[0]);
    let other_index = request_for(wallet.devices[1]).share_index;
    assert_ne!(request.share_index, other_index);

    let mut device_accepts = |request| {
        let id = wallet.devices[0];
        wallet
            .run
            .devices
            .get_mut(&id)
            .unwrap()
            .recv_coordinator_message(
                CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSpContactEcdh(
                    Box::new(request),
                )),
                &mut wallet.rng,
            )
            .is_ok()
    };
    assert!(device_accepts(request.clone()));
    request.share_index = other_index;
    assert!(!device_accepts(request));
}

/// A device forgets its approval when it restarts, so the share it gave can no longer be followed
/// by its signature. The coordinator drops the share of a device that disconnects and asks again.
#[test]
fn a_disconnected_device_is_asked_for_its_share_again() {
    let mut wallet = Wallet::new();
    let session_id = wallet.contact_ecdh(details("Olga", 0xd1, 0xd2), &[0, 1]);
    wallet
        .run
        .coordinator
        .forget_sp_contact_shares_from(wallet.devices[0]);
    let shares = |wallet: &Wallet| {
        wallet
            .run
            .coordinator
            .sp_contact_session(session_id)
            .unwrap()
            .shares
            .keys()
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(shares(&wallet), [wallet.devices[1]]);

    let request = wallet
        .run
        .coordinator
        .request_sp_contact_ecdh(session_id, wallet.devices[0], TEST_ENCRYPTION_KEY)
        .unwrap();
    wallet.run.extend([request]);
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();
    assert_eq!(
        shares(&wallet),
        wallet.signers(&[0, 1]).into_iter().collect::<Vec<_>>()
    );
}

/// The devices sign right after the holds with no second prompt, so each device asked must have
/// a nonce for that signature before anyone holds.
#[test]
fn a_contact_is_not_started_without_nonces() {
    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let mut run = Run::start_after_keygen(3, 2, &mut env, &mut rng, purpose());
    let access_structure_ref = run
        .coordinator
        .iter_keys()
        .next()
        .unwrap()
        .access_structures()
        .next()
        .unwrap()
        .access_structure_ref();
    let signers = run.device_vec().into_iter().take(2).collect();
    let set = ContactChangeSet {
        head: run
            .coordinator
            .sp_contact_book_head(access_structure_ref.key_id),
        changes: vec![ContactChange::Add(details("Quinn", 0xf1, 0xf2))],
    };
    assert!(matches!(
        run.coordinator.start_sp_contact(
            access_structure_ref,
            set,
            &signers,
            TEST_ENCRYPTION_KEY,
            &mut rng,
        ),
        Err(StartSignError::NotEnoughNoncesForDevice(_))
    ));
}

#[test]
fn contact_names_are_short_printable_ascii() {
    let check = |name: &str| details(name, 1, 2).has_valid_name();
    assert!(check("Alice @ work"));
    assert!(check(&"x".repeat(20)));
    assert!(!check(""));
    assert!(!check(&"x".repeat(21)));
    assert!(!check("Al\u{0456}ce"));
    assert!(!check("Alice\n"));

    let mut wallet = Wallet::new();
    let signers = wallet.signers(&[0, 1]);
    let set = wallet.change_set(vec![ContactChange::Add(details("", 1, 2))]);
    assert!(matches!(
        wallet.run.coordinator.start_sp_contact(
            wallet.access_structure_ref,
            set,
            &signers,
            TEST_ENCRYPTION_KEY,
            &mut wallet.rng,
        ),
        Err(StartSignError::SignTask(
            SignTaskError::SilentPaymentInvalidContactChanges
        ))
    ));
}

#[test]
fn a_contact_name_cannot_be_reused() {
    let mut wallet = Wallet::new();
    let added = wallet.add_contact(details("Alice", 1, 2), &[0, 1]);
    let signers = wallet.signers(&[0, 1]);
    for name in ["Alice", "aLICE"] {
        let set = wallet.change_set(vec![ContactChange::Add(details(name, 3, 4))]);
        assert!(matches!(
            wallet.run.coordinator.start_sp_contact(
                wallet.access_structure_ref,
                set,
                &signers,
                TEST_ENCRYPTION_KEY,
                &mut wallet.rng,
            ),
            Err(StartSignError::SpContactChanges(ChangeSetError::NameTaken))
        ));
    }
    let key_id = wallet.access_structure_ref.key_id;
    assert_eq!(
        wallet
            .run
            .coordinator
            .sp_contacts(key_id)
            .collect::<Vec<_>>(),
        vec![&added]
    );
}

/// Runs adding `details` on `signers` until the devices have signed, without storing the contact.
fn sign_contact(
    wallet: &mut Wallet,
    details: SpContactDetails,
    signers: &[usize],
) -> frostsnap_core::SignSessionId {
    sign_changes(wallet, vec![ContactChange::Add(details)], signers)
}

/// Runs `changes` on `signers` until the devices have signed, without applying them.
fn sign_changes(
    wallet: &mut Wallet,
    changes: Vec<ContactChange>,
    signers: &[usize],
) -> frostsnap_core::SignSessionId {
    let session_id = wallet.changes_ecdh(changes, signers);
    let sign_session = wallet
        .run
        .coordinator
        .start_sp_contact_sign(session_id, &mut wallet.rng)
        .unwrap();
    for device in wallet.signers(signers) {
        let request =
            wallet
                .run
                .coordinator
                .request_device_sign(sign_session, device, TEST_ENCRYPTION_KEY);
        wallet.run.extend(request);
    }
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();
    sign_session
}

/// The user can leave as the last device signs, before the app stores the contact. Cancelling then
/// forgets the finished session, and a restart does not store a contact the user walked away from.
#[test]
fn a_contact_cancelled_after_signing_is_not_stored() {
    let mut wallet = Wallet::new();
    let sign_session = sign_contact(&mut wallet, details("Rae", 0x21, 0x22), &[0, 1]);
    wallet.run.coordinator.cancel_sign_session(sign_session);
    assert_eq!(wallet.run.coordinator.finished_signing_sessions().len(), 0);

    wallet.run.coordinator.clear_tmp_data();
    wallet.run.coordinator.settle_sp_contact_sessions();
    let key_id = wallet.access_structure_ref.key_id;
    assert_eq!(wallet.run.coordinator.sp_contacts(key_id).count(), 0);
}

/// Two change sets from the same head can both be signed. Whichever finishes first, the one with
/// the smaller digest is the book's.
#[test]
fn of_two_change_sets_from_one_head_the_smaller_digest_wins() {
    let mut wallet = Wallet::new();
    let first = sign_contact(&mut wallet, details("Bob", 0x31, 0x32), &[0, 1]);
    let second = sign_contact(&mut wallet, details("bob", 0x33, 0x34), &[1, 2]);
    let other = wallet.run.coordinator.clone();

    let second = wallet.run.coordinator.finish_sp_contact(second).unwrap();
    let first = wallet.run.coordinator.finish_sp_contact(first).unwrap();
    assert_eq!(wallet.run.coordinator.finished_signing_sessions().len(), 0);
    assert_eq!(first.changes.set.head, second.changes.set.head);

    let winner = [&first, &second]
        .into_iter()
        .min_by_key(|signed| signed.changes.set.digest(NETWORK))
        .unwrap();
    let key_id = wallet.access_structure_ref.key_id;
    let head = wallet.run.coordinator.sp_contact_book_head(key_id);
    assert_eq!(head, winner.changes.set.next_head(NETWORK));
    assert_eq!(
        wallet
            .run
            .coordinator
            .sp_contacts(key_id)
            .collect::<Vec<_>>(),
        winner.added_contacts(NETWORK).iter().collect::<Vec<_>>()
    );

    // Another coordinator that gets them the other way round agrees.
    let mut other = other;
    other.add_sp_contact_changes(key_id, first.clone()).unwrap();
    other
        .add_sp_contact_changes(key_id, second.clone())
        .unwrap();
    assert_eq!(other.sp_contact_book_head(key_id), head);
    // The losing set is known, not waiting for anything, and reported dropped.
    let loser = if winner == &first { &second } else { &first };
    let book = other.sp_contact_book(key_id).unwrap();
    assert!(!book.is_waiting_for_missing_set());
    assert_eq!(book.dropped(), [loser]);
}

/// A set from an old head that arrives late can't displace a set that already has a descendant:
/// the longer branch wins even when the late set has the smaller digest, on every coordinator
/// whatever the arrival order, and the late set is reported dropped.
#[test]
fn a_late_set_does_not_displace_a_set_with_a_descendant() {
    let mut wallet = Wallet::new();
    let fresh = wallet.run.coordinator.clone();
    let ray = details("Ray", 0xd1, 0xd2);
    let digest_from_empty = |details: &SpContactDetails| {
        ContactChangeSet {
            head: frostsnap_core::silent_payments::BookHead::empty(),
            changes: vec![ContactChange::Add(details.clone())],
        }
        .digest(NETWORK)
    };
    // A late set whose digest is smaller than Ray's, so the old rule would have picked it.
    let late_details = (0xe0..0xf0u8)
        .map(|byte| details("Sam", byte, byte + 0x10))
        .find(|late| digest_from_empty(late) < digest_from_empty(&ray))
        .unwrap();
    let first = sign_contact(&mut wallet, ray, &[0, 1]);
    let late = sign_contact(&mut wallet, late_details, &[1, 2]);
    let first = wallet.run.coordinator.finish_sp_contact(first).unwrap();
    let tom = wallet.change_book(
        vec![ContactChange::Add(details("Tom", 0xd5, 0xd6))],
        &[0, 2],
    );
    let late = wallet.run.coordinator.finish_sp_contact(late).unwrap();

    let key_id = wallet.access_structure_ref.key_id;
    let head = wallet.run.coordinator.sp_contact_book_head(key_id);
    assert_eq!(head, tom.changes.set.next_head(NETWORK));
    assert_eq!(wallet.names(), ["Ray", "Tom"]);
    let book = wallet.run.coordinator.sp_contact_book(key_id).unwrap();
    assert_eq!(book.dropped(), [&late]);

    let mut other = fresh;
    for signed in [late, tom, first] {
        other.add_sp_contact_changes(key_id, signed).unwrap();
    }
    assert_eq!(other.sp_contact_book_head(key_id), head);
    assert_eq!(other.sp_contact_book(key_id).unwrap().dropped().len(), 1);
}

/// The proofs of a contact's signing session are in memory, like its ECDH shares, so they never
/// reach the mutation log. After a restart a finished session is stored and an unfinished one
/// cancelled.
#[test]
fn a_restart_settles_contact_sessions() {
    let mut wallet = Wallet::new();
    let session_id = wallet.contact_ecdh(details("Mia", 0xc1, 0xc2), &[0, 1]);
    wallet
        .run
        .coordinator
        .start_sp_contact_sign(session_id, &mut wallet.rng)
        .unwrap();
    assert_eq!(wallet.run.coordinator.active_signing_sessions().count(), 1);

    wallet.run.coordinator.clear_tmp_data();
    wallet.run.coordinator.settle_sp_contact_sessions();
    assert_eq!(wallet.run.coordinator.active_signing_sessions().count(), 0);

    let details = details("Noor", 0xc3, 0xc4);
    let session_id = wallet.contact_ecdh(details, &[0, 1]);
    let sign_session = wallet
        .run
        .coordinator
        .start_sp_contact_sign(session_id, &mut wallet.rng)
        .unwrap();
    for device in wallet.signers(&[0, 1]) {
        let request =
            wallet
                .run
                .coordinator
                .request_device_sign(sign_session, device, TEST_ENCRYPTION_KEY);
        wallet.run.extend(request);
    }
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();

    wallet.run.coordinator.clear_tmp_data();
    wallet.run.coordinator.settle_sp_contact_sessions();
    let key_id = wallet.access_structure_ref.key_id;
    let names = wallet
        .run
        .coordinator
        .sp_contacts(key_id)
        .map(|contact| contact.contact.details.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(names, ["Noor"]);
    assert_eq!(wallet.run.coordinator.finished_signing_sessions().len(), 0);
}

/// A BIP352 receiver written from the BIP, sharing no code with the sender. It sees only the
/// transaction's prevout scripts and outpoints, and its own keys, and returns the output keys it
/// would look for, for k = 0 to `count - 1`.
fn bip352_receiver_output_keys(
    prevouts: &[(OutPoint, bitcoin::ScriptBuf)],
    scan_secret: &Scalar,
    spend_key: Point,
    count: u32,
) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let tagged = |tag: &str, data: &[u8]| -> Scalar<Public> {
        let tag = Sha256::digest(tag.as_bytes());
        let hash = Sha256::new()
            .chain_update(tag)
            .chain_update(tag)
            .chain_update(data)
            .finalize();
        Scalar::from_bytes(hash.into()).unwrap().non_zero().unwrap()
    };

    // A is the sum of the taproot output keys of the inputs, each lifted to even y.
    let a = prevouts
        .iter()
        .map(|(_, spk)| {
            assert!(spk.is_p2tr());
            Point::<EvenY>::from_xonly_bytes(spk.as_bytes()[2..34].try_into().unwrap()).unwrap()
        })
        .fold(Point::<Normal, Public, Zero>::zero(), |sum, p| {
            g!(sum + p).normalize()
        })
        .non_zero()
        .unwrap();
    // The smallest outpoint, compared as it is serialized: txid then vout, little endian.
    let smallest = prevouts
        .iter()
        .map(|(outpoint, _)| {
            let mut bytes = outpoint.txid.to_byte_array().to_vec();
            bytes.extend(outpoint.vout.to_le_bytes());
            bytes
        })
        .min()
        .unwrap();
    let input_hash = tagged("BIP0352/Inputs", &[&smallest[..], &a.to_bytes()].concat());
    let ecdh = g!(input_hash * scan_secret * a).normalize();
    (0..count)
        .map(|k| {
            let t_k = tagged(
                "BIP0352/SharedSecret",
                &[&ecdh.to_bytes()[..], &k.to_be_bytes()].concat(),
            );
            g!(spend_key + t_k * G)
                .normalize()
                .non_zero()
                .unwrap()
                .to_xonly_bytes()
        })
        .collect()
}

/// A receiver that knows only the BIP finds both outputs a send pays to one contact, from a
/// transaction with inputs at several derivation paths.
#[test]
fn a_bip352_receiver_finds_every_output_paid_to_a_contact() {
    let mut wallet = Wallet::new();
    let (scan, spend) = (0x41, 0x42);
    let contact = wallet.add_contact(details("Dave", scan, spend), &[0, 1]);
    let address = contact.contact.details.recipient.address(NETWORK).unwrap();

    let mut template = TransactionTemplate::new();
    for index in [0, 1, 7] {
        template.push_imaginary_owned_input(
            LocalSpk {
                master_appkey: wallet.master,
                bip32_path: BitcoinBip32Path::external(index),
            },
            Amount::from_sat(100_000),
        );
    }
    template.push_silent_payment_output(Amount::from_sat(50_000), contact.clone(), address.clone());
    template.push_silent_payment_output(Amount::from_sat(60_000), contact.clone(), address);
    let template = template.with_contact_sp_scripts(wallet.master).unwrap();

    let prevouts = template
        .inputs()
        .iter()
        .map(|input| (input.outpoint(), input.txout().script_pubkey))
        .collect::<Vec<_>>();
    let found = bip352_receiver_output_keys(
        &prevouts,
        &scalar(scan),
        contact.contact.details.recipient.spend_key,
        2,
    );
    let paid = template
        .silent_payment_outputs()
        .map(|output| output.script.as_ref().unwrap().as_bytes()[2..].to_vec())
        .collect::<Vec<_>>();
    assert_eq!(
        paid,
        found.iter().map(|key| key.to_vec()).collect::<Vec<_>>()
    );
}

/// One hold accepts a whole change set. Each device answers with one ECDH share per add, and the
/// book gets every contact, each with its own signature, in one step.
#[test]
fn a_change_set_of_three_adds_is_one_step() {
    let mut wallet = Wallet::new();
    let adds = [
        details("Ann", 0x11, 0x12),
        details("Ben", 0x13, 0x14),
        details("Cat", 0x15, 0x16),
    ];
    let changes = adds.iter().cloned().map(ContactChange::Add).collect();
    let session_id = wallet.changes_ecdh(changes, &[0, 2]);
    let session = wallet
        .run
        .coordinator
        .sp_contact_session(session_id)
        .unwrap();
    assert!(session.shares.values().all(|shares| shares.len() == 3));

    let sign_session = wallet
        .run
        .coordinator
        .start_sp_contact_sign(session_id, &mut wallet.rng)
        .unwrap();
    for device in wallet.signers(&[0, 2]) {
        let request =
            wallet
                .run
                .coordinator
                .request_device_sign(sign_session, device, TEST_ENCRYPTION_KEY);
        wallet.run.extend(request);
    }
    wallet
        .run
        .run_until_finished(&mut wallet.env, &mut wallet.rng)
        .unwrap();
    let signed = wallet
        .run
        .coordinator
        .finish_sp_contact(sign_session)
        .unwrap();

    assert!(signed.verify(wallet.master, NETWORK));
    assert_eq!(signed.signatures.len(), 3);
    assert_eq!(wallet.names(), ["Ann", "Ben", "Cat"]);
    let key_id = wallet.access_structure_ref.key_id;
    assert_eq!(
        wallet.run.coordinator.sp_contact_book_head(key_id).version,
        1
    );
    for contact in wallet.run.coordinator.sp_contacts(key_id) {
        assert!(contact.verify(wallet.master, NETWORK));
    }
}

/// A rename is a remove and an add in one set. Removes apply first, so the new name can even be
/// the old one in another case.
#[test]
fn a_rename_is_one_change_set() {
    let mut wallet = Wallet::new();
    let bob = details("Bob", 0x21, 0x22);
    wallet.add_contact(bob.clone(), &[0, 1]);

    let mut robert = bob.clone();
    robert.name = "Robert".into();
    wallet.change_book(
        vec![
            ContactChange::Add(robert.clone()),
            ContactChange::Remove(bob.clone()),
        ],
        &[1, 2],
    );
    assert_eq!(wallet.names(), ["Robert"]);
    let renamed = wallet.contact("Robert").unwrap();
    assert!(renamed.verify(wallet.master, NETWORK));
    let key_id = wallet.access_structure_ref.key_id;
    assert_eq!(
        wallet.run.coordinator.sp_contact_book_head(key_id).version,
        2
    );

    let mut lowercase = robert.clone();
    lowercase.name = "robert".into();
    wallet.change_book(
        vec![ContactChange::Remove(robert), ContactChange::Add(lowercase)],
        &[0, 2],
    );
    assert_eq!(wallet.names(), ["robert"]);
}

/// A set that does not apply to the book is refused before any device is asked.
#[test]
fn a_change_set_must_apply_to_the_book() {
    let mut wallet = Wallet::new();
    let ann = details("Ann", 0x31, 0x32);
    wallet.add_contact(ann.clone(), &[0, 1]);
    let signers = wallet.signers(&[0, 1]);
    let start = |wallet: &mut Wallet, set: ContactChangeSet| {
        wallet.run.coordinator.start_sp_contact(
            wallet.access_structure_ref,
            set,
            &signers,
            TEST_ENCRYPTION_KEY,
            &mut wallet.rng,
        )
    };

    // A remove of an address the book has under another name.
    let mut other_name = ann.clone();
    other_name.name = "Anne".into();
    let set = wallet.change_set(vec![ContactChange::Remove(other_name)]);
    assert!(matches!(
        start(&mut wallet, set),
        Err(StartSignError::SpContactChanges(
            ChangeSetError::NoSuchContact
        ))
    ));

    // An add under a name still in use after the removes.
    let set = wallet.change_set(vec![
        ContactChange::Remove(ann.clone()),
        ContactChange::Add(details("Bea", 0x33, 0x34)),
        ContactChange::Add(details("bea", 0x35, 0x36)),
    ]);
    assert!(matches!(
        start(&mut wallet, set),
        Err(StartSignError::SignTask(
            SignTaskError::SilentPaymentInvalidContactChanges
        ))
    ));

    // A set started from an older head.
    let mut set = wallet.change_set(vec![ContactChange::Add(details("Cy", 0x37, 0x38))]);
    set.head = frostsnap_core::silent_payments::BookHead::empty();
    assert!(matches!(
        start(&mut wallet, set),
        Err(StartSignError::SpContactChanges(ChangeSetError::WrongHead))
    ));
}

/// A share whose proof doesn't check is refused when it arrives, and the device stays unanswered.
#[test]
fn a_tampered_contact_share_is_refused_on_arrival() {
    use frostsnap_core::message::{signing::DeviceSigning, DeviceToCoordinatorMessage};
    let mut wallet = Wallet::new();
    let session_id = wallet.contact_ecdh(details("Dee", 0x41, 0x42), &[0, 1]);
    let device = wallet.devices[0];
    let shares = wallet
        .run
        .coordinator
        .sp_contact_session(session_id)
        .unwrap()
        .shares[&device]
        .clone();
    wallet.run.coordinator.forget_sp_contact_shares_from(device);

    let send = |wallet: &mut Wallet, shares: Vec<_>| {
        wallet.run.coordinator.recv_device_message(
            device,
            DeviceToCoordinatorMessage::Signing(DeviceSigning::SpContactEcdhShare {
                session_id,
                shares,
            }),
        )
    };
    let mut tampered = shares.clone();
    tampered[0].proof[0] ^= 1;
    assert!(send(&mut wallet, tampered).is_err());
    let mut other_point = shares.clone();
    other_point[0].ecdh_share = public(scalar(0x43));
    assert!(send(&mut wallet, other_point).is_err());
    assert!(send(&mut wallet, vec![]).is_err());
    assert!(!wallet
        .run
        .coordinator
        .sp_contact_session(session_id)
        .unwrap()
        .shares
        .contains_key(&device));

    assert!(send(&mut wallet, shares).is_ok());
}

/// A signed change set from another coordinator only touches the book if it is this wallet's on
/// this network.
#[test]
fn a_forged_change_set_is_refused() {
    let mut wallet = Wallet::new();
    let fresh = wallet.run.coordinator.clone();
    let signed = wallet.change_book(
        vec![ContactChange::Add(details("Eve", 0x51, 0x52))],
        &[0, 1],
    );
    let key_id = wallet.access_structure_ref.key_id;

    let other_wallet = MasterAppkey::derive_from_rootkey(G.normalize());
    assert!(!signed.verify(other_wallet, NETWORK));
    assert!(!signed.verify(wallet.master, Network::Testnet));

    let mut forged_signature = signed.clone();
    forged_signature.signatures[0][63] ^= 1;
    let mut moved = signed.clone();
    moved.changes.set.head = wallet.run.coordinator.sp_contact_book_head(key_id);
    let mut other_ecdh = signed.clone();
    other_ecdh.changes.account_ecdh[0] = public(scalar(0x53));
    let mut renamed = signed.clone();
    renamed.changes.set.changes[0] = ContactChange::Add(details("Mallory", 0x51, 0x52));

    let mut other = fresh;
    for forged in [forged_signature, moved, other_ecdh, renamed] {
        assert!(other.add_sp_contact_changes(key_id, forged).is_err());
    }
    assert_eq!(
        other.sp_contact_book_head(key_id),
        frostsnap_core::silent_payments::BookHead::empty()
    );
    other.add_sp_contact_changes(key_id, signed).unwrap();
    assert_eq!(
        other.sp_contact_book_head(key_id),
        wallet.run.coordinator.sp_contact_book_head(key_id)
    );
}

/// A coordinator that missed a change set waits for it, a replayed old set changes nothing, and
/// sets arriving in any order give the same book.
#[test]
fn the_book_folds_the_same_whatever_the_arrival_order() {
    let mut wallet = Wallet::new();
    let fresh = wallet.run.coordinator.clone();
    let ann = details("Ann", 0x61, 0x62);
    let add_ann = wallet.change_book(vec![ContactChange::Add(ann.clone())], &[0, 1]);
    let add_ben = wallet.change_book(
        vec![ContactChange::Add(details("Ben", 0x63, 0x64))],
        &[1, 2],
    );
    let remove_ann = wallet.change_book(vec![ContactChange::Remove(ann)], &[0, 2]);
    let key_id = wallet.access_structure_ref.key_id;
    let head = wallet.run.coordinator.sp_contact_book_head(key_id);
    assert_eq!(head.version, 3);
    assert_eq!(wallet.names(), ["Ben"]);

    // The first set is missing: the later ones wait for it.
    let mut other = fresh;
    other
        .add_sp_contact_changes(key_id, remove_ann.clone())
        .unwrap();
    other.add_sp_contact_changes(key_id, add_ben).unwrap();
    assert_eq!(
        other.sp_contact_book_head(key_id),
        frostsnap_core::silent_payments::BookHead::empty()
    );
    assert_eq!(other.sp_contacts(key_id).count(), 0);
    assert!(other
        .sp_contact_book(key_id)
        .unwrap()
        .is_waiting_for_missing_set());

    other
        .add_sp_contact_changes(key_id, add_ann.clone())
        .unwrap();
    assert_eq!(other.sp_contact_book_head(key_id), head);
    let book = other.sp_contact_book(key_id).unwrap();
    assert!(!book.is_waiting_for_missing_set());
    assert!(book.has_passed(&frostsnap_core::silent_payments::BookHead::empty()));
    assert!(book.has_passed(&head));
    let after_ann = add_ann.changes.set.next_head(NETWORK);
    assert!(book.has_passed(&after_ann));
    assert!(book.applied(&add_ann.changes.set.digest(NETWORK)));
    assert_eq!(
        book.sets_after(&after_ann)
            .iter()
            .map(|signed| signed.changes.set.head.version)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(book.sets_after(&head).is_empty());
    assert_eq!(
        other.sp_contacts(key_id).collect::<Vec<_>>(),
        wallet
            .run
            .coordinator
            .sp_contacts(key_id)
            .collect::<Vec<_>>()
    );

    // Republishing the set that added Ann does not bring her back.
    other.add_sp_contact_changes(key_id, add_ann).unwrap();
    wallet
        .run
        .coordinator
        .add_sp_contact_changes(key_id, remove_ann)
        .unwrap();
    assert_eq!(other.sp_contact_book_head(key_id), head);
    assert_eq!(wallet.names(), ["Ben"]);
    assert!(other
        .sp_contacts(key_id)
        .all(|contact| contact.contact.details.name == "Ben"));
}
