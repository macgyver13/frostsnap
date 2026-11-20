//! Runs a wallet's shared contact book next to the app's coordinator: feeds the nostr channel's
//! contact events to [`ContactSync`], publishes what it asks for, and talks to the local device
//! through a UI protocol per ceremony.

use crate::api::nostr::contacts::ContactsState;
use crate::coordinator::FfiCoordinator;
use crate::frb_generated::StreamSink;
use frostsnap_coordinator::frostsnap_comms::CoordinatorSendMessage;
use frostsnap_coordinator::{Completion, DeviceMode, UiProtocol};
use frostsnap_core::{
    coordinator::{
        CoordinatorSend, CoordinatorToUserMessage, CoordinatorToUserSigningMessage,
        FrostCoordinator, KeyContext, ParticipantSignatureShares, StartSignError,
    },
    message::signing::SpContactSessionId,
    DeviceId, KeyId, SignSessionId, SymmetricKey,
};
use frostsnap_nostr::signing::contacts::{
    CeremonyStatus, ContactAction, ContactPublish, ContactSync,
};
use frostsnap_nostr::signing::ContactEvent;
use frostsnap_nostr::{ChannelHandle as InnerChannelHandle, EventId, Keys, PublicKey};
use rand::Rng;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::mpsc;

/// A republish waits this long, plus up to as long again at random, so that of the members
/// answering one head, usually only one publishes.
const REPUBLISH_DELAY: Duration = Duration::from_secs(2);

pub(crate) enum GlueMsg {
    Event(ContactEvent),
    DeviceConfirmed(EventId),
    DeviceDisconnected(DeviceId),
    Share(SignSessionId, ParticipantSignatureShares),
    RepublishDue(frostsnap_core::silent_payments::BookHead),
}

/// The `Sink` given to the channel client: contact events go to the glue's task.
pub(crate) struct ContactEventSink(pub mpsc::UnboundedSender<GlueMsg>);

impl frostsnap_coordinator::Sink<ContactEvent> for ContactEventSink {
    fn send(&self, event: ContactEvent) {
        let _ = self.0.send(GlueMsg::Event(event));
    }
}

/// What the glue shares with the UI protocol of one ceremony on the local device.
#[derive(Clone, Default)]
struct DeviceLink {
    outbox: Arc<Mutex<Vec<CoordinatorSendMessage>>>,
    sign_session: Arc<Mutex<Option<SignSessionId>>>,
    done: Arc<AtomicBool>,
}

pub(crate) struct ContactsGlue {
    pub(crate) sync: Mutex<ContactSync>,
    pub(crate) coord: FfiCoordinator,
    pub(crate) key_id: KeyId,
    pub(crate) network: bitcoin::Network,
    /// This member's nostr key.
    pub(crate) me: PublicKey,
    tx: mpsc::UnboundedSender<GlueMsg>,
    links: Mutex<BTreeMap<EventId, (DeviceId, DeviceLink)>>,
    /// The last error per ceremony, for the app to show (e.g. not enough nonces to offer).
    pub(crate) errors: Mutex<BTreeMap<EventId, String>>,
    sink: Mutex<Option<StreamSink<ContactsState>>>,
}

impl ContactsGlue {
    /// The book of `key`'s wallet, for the member `me`, who connected at `started_at`.
    pub(crate) fn new(
        key: KeyContext,
        me: PublicKey,
        started_at: u64,
        coord: FfiCoordinator,
        tx: mpsc::UnboundedSender<GlueMsg>,
    ) -> anyhow::Result<Self> {
        let network = key
            .purpose
            .bitcoin_network()
            .ok_or_else(|| anyhow::anyhow!("contacts need a bitcoin wallet"))?;
        Ok(Self {
            key_id: key.key_id(),
            network,
            me,
            sync: Mutex::new(ContactSync::new(key, me, started_at)),
            coord,
            tx,
            links: Default::default(),
            errors: Default::default(),
            sink: Default::default(),
        })
    }

    /// Runs `f` on the driver and the coordinator, persisting what it changes.
    pub(crate) fn with_sync<T>(
        &self,
        f: impl FnOnce(&mut ContactSync, &mut FrostCoordinator) -> T,
    ) -> anyhow::Result<T> {
        let mut sync = self.sync.lock().unwrap();
        let mut db = self.coord.db.lock().unwrap();
        let mut coordinator = self.coord.coordinator.lock().unwrap();
        coordinator.staged_mutate(&mut *db, |coordinator| Ok(f(&mut sync, coordinator)))
    }

    pub(crate) fn set_sink(&self, sink: StreamSink<ContactsState>) {
        *self.sink.lock().unwrap() = Some(sink);
        self.emit();
    }

    pub(crate) fn emit(&self) {
        let state = ContactsState::read(self);
        if let Some(sink) = &*self.sink.lock().unwrap() {
            let _ = sink.add(state);
        }
    }

    /// Asks `device_id` to confirm the ceremony `request_id`.
    pub(crate) fn confirm(
        &self,
        request_id: EventId,
        device_id: DeviceId,
        encryption_key: SymmetricKey,
    ) -> anyhow::Result<()> {
        let actions = self.with_sync(|sync, coordinator| {
            sync.confirm(coordinator, request_id, device_id, encryption_key)
        })??;
        let link = {
            let mut links = self.links.lock().unwrap();
            match links.get(&request_id) {
                Some((device, link)) if *device == device_id => link.clone(),
                _ => {
                    if let Some((_, old)) = links.remove(&request_id) {
                        old.done.store(true, Ordering::SeqCst);
                    }
                    let link = DeviceLink::default();
                    links.insert(request_id, (device_id, link.clone()));
                    self.coord.start_protocol(ContactDeviceProtocol {
                        request_id,
                        session_id: SpContactSessionId(request_id.0),
                        device_id,
                        connected: false,
                        link: link.clone(),
                        tx: self.tx.clone(),
                    });
                    link
                }
            }
        };
        for action in actions {
            if let ContactAction::ToDevice(send) = action {
                link.outbox.lock().unwrap().push(to_device(send));
            }
        }
        self.errors.lock().unwrap().remove(&request_id);
        self.emit();
        Ok(())
    }

    /// The task that feeds the driver, in order, everything that reaches it.
    pub(crate) async fn run(
        self: Arc<Self>,
        mut rx: mpsc::UnboundedReceiver<GlueMsg>,
        channel: InnerChannelHandle,
        keys: Keys,
    ) {
        while let Some(msg) = rx.recv().await {
            let result = match msg {
                GlueMsg::Event(event) => {
                    self.with_sync(|sync, coordinator| sync.on_event(coordinator, event))
                }
                GlueMsg::DeviceConfirmed(request_id) => self
                    .with_sync(|sync, coordinator| sync.device_confirmed(coordinator, request_id))
                    .and_then(|result| {
                        result.or_else(|e| {
                            // Shown on the ceremony.
                            // TODO: the app doesn't replenish a device's nonces for a contact
                            // ceremony. Reconnecting only helps where a top-up on connect is
                            // enabled. Upstream has it commented out.
                            let reason = match e {
                                StartSignError::NotEnoughNoncesForDevice(_) => {
                                    "the device needs more nonces: reconnect it and confirm again"
                                        .to_string()
                                }
                                e => format!("{e:?}"),
                            };
                            self.errors.lock().unwrap().insert(request_id, reason);
                            Ok(vec![])
                        })
                    }),
                GlueMsg::DeviceDisconnected(device_id) => {
                    self.sync.lock().unwrap().device_disconnected(device_id);
                    Ok(vec![])
                }
                GlueMsg::Share(session_id, shares) => {
                    Ok(self.sync.lock().unwrap().got_share(session_id, shares))
                }
                GlueMsg::RepublishDue(head) => {
                    self.with_sync(|sync, coordinator| sync.republish_due(coordinator, head))
                }
            };
            match result {
                Ok(actions) => self.execute(actions, &channel, &keys).await,
                Err(e) => tracing::error!(error = %e, "contact book update failed"),
            }
            self.finish_over();
            self.emit();
        }
    }

    pub(crate) async fn execute(
        &self,
        actions: Vec<ContactAction>,
        channel: &InnerChannelHandle,
        keys: &Keys,
    ) {
        for action in actions {
            match action {
                ContactAction::Publish(publish) => {
                    let result = match publish {
                        ContactPublish::Offer { request_id, offer } => {
                            channel.send_contact_offer(keys, request_id, offer).await
                        }
                        ContactPublish::Partial {
                            request_id,
                            offer_subset,
                            signature_shares,
                        } => {
                            channel
                                .send_sign_partial(keys, request_id, offer_subset, signature_shares)
                                .await
                        }
                        ContactPublish::Changes(signed) => {
                            channel.send_contact_changes(keys, signed).await
                        }
                        ContactPublish::Head(head) => channel.send_book_head(keys, head).await,
                    };
                    if let Err(e) = result {
                        tracing::warn!(error = %e, "failed to publish to the contact book");
                    }
                }
                ContactAction::ToDevice(_) => {
                    // Only `confirm` asks a device to confirm, and it routes the request itself.
                }
                ContactAction::SignOnDevice { session_id, send } => {
                    let links = self.links.lock().unwrap();
                    let link = links.values().find(|(device, _)| {
                        matches!(&send, CoordinatorSend::ToDevice { destinations, .. }
                            if destinations.contains(device))
                    });
                    if let Some((_, link)) = link {
                        *link.sign_session.lock().unwrap() = Some(session_id);
                        link.outbox.lock().unwrap().push(to_device(send));
                    }
                }
                ContactAction::ScheduleRepublish(head) => {
                    let tx = self.tx.clone();
                    let jitter =
                        rand::thread_rng().gen_range(0..REPUBLISH_DELAY.as_millis() as u64);
                    tokio::spawn(async move {
                        tokio::time::sleep(REPUBLISH_DELAY + Duration::from_millis(jitter)).await;
                        let _ = tx.send(GlueMsg::RepublishDue(head));
                    });
                }
            }
        }
    }

    /// Takes the UI protocol of every ceremony that is over off the stack.
    fn finish_over(&self) {
        let sync = self.sync.lock().unwrap();
        let coordinator = self.coord.coordinator.lock().unwrap();
        self.links.lock().unwrap().retain(|request_id, (_, link)| {
            let over = matches!(
                sync.status(&coordinator, *request_id),
                None | Some(CeremonyStatus::Published | CeremonyStatus::Dropped)
            );
            if over {
                link.done.store(true, Ordering::SeqCst);
            }
            !over
        });
    }
}

fn to_device(send: CoordinatorSend) -> CoordinatorSendMessage {
    send.try_into()
        .expect("a contact ceremony only sends to the local device")
}

/// The local device's part in one ceremony: delivers the confirm and sign requests when the
/// device is connected, and passes its answers to the glue.
struct ContactDeviceProtocol {
    request_id: EventId,
    session_id: SpContactSessionId,
    device_id: DeviceId,
    connected: bool,
    link: DeviceLink,
    tx: mpsc::UnboundedSender<GlueMsg>,
}

impl UiProtocol for ContactDeviceProtocol {
    fn is_complete(&self) -> Option<Completion> {
        self.link
            .done
            .load(Ordering::SeqCst)
            .then_some(Completion::Success)
    }

    fn connected(&mut self, id: DeviceId, state: DeviceMode) {
        if id == self.device_id && state == DeviceMode::Ready {
            self.connected = true;
        }
    }

    fn disconnected(&mut self, id: DeviceId) {
        if id == self.device_id {
            self.connected = false;
            let _ = self.tx.send(GlueMsg::DeviceDisconnected(id));
        }
    }

    fn process_to_user_message(&mut self, message: CoordinatorToUserMessage) -> bool {
        match message {
            CoordinatorToUserMessage::Signing(
                CoordinatorToUserSigningMessage::GotSpContactEcdhShare { session_id, from },
            ) if session_id == self.session_id && from == self.device_id => {
                let _ = self.tx.send(GlueMsg::DeviceConfirmed(self.request_id));
                true
            }
            CoordinatorToUserMessage::Signing(CoordinatorToUserSigningMessage::GotShare {
                session_id,
                from,
                shares,
            }) if from == self.device_id
                && *self.link.sign_session.lock().unwrap() == Some(session_id) =>
            {
                let _ = self.tx.send(GlueMsg::Share(session_id, shares));
                true
            }
            _ => false,
        }
    }

    fn poll(&mut self) -> Vec<CoordinatorSendMessage> {
        if !self.connected {
            return vec![];
        }
        core::mem::take(&mut *self.link.outbox.lock().unwrap())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
