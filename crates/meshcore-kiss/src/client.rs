//! Async handle to a MeshCore KISS Modem device.
//!
//! [`KissClient`] mirrors `meshcore_companion::client::CompanionClient`: a
//! channel pair over a background task that owns the serial port. Both emit
//! [`ClientEvent`] and accept [`OutboundFrame`], so the mesh transport treats
//! the two backends alike.
//!
//! # Lifecycle
//!
//! 1. [`KissClient::connect`] spawns the worker and returns immediately.
//! 2. Poll [`KissClient::recv`] for events.
//! 3. Send commands with [`KissClient::send`] or a clone of
//!    [`KissClient::sender`].
//! 4. Drop the client to shut the worker down.
//!
//! # Handshake
//!
//! On each successful open the worker queries the device for its identity,
//! radio parameters and transmit power, pushes the configured CSMA settings,
//! and emits [`ClientEvent::Connected`] carrying a `SelfInfo` synthesised from
//! those answers. The KISS firmware has no equivalent of the companion
//! protocol's `AppStart`, so the fields it cannot know are reported as zero.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use meshcore_companion::client::{ClientEvent, SendError};
use meshcore_companion::constants::ERR_CODE_UNSUPPORTED_CMD;
use meshcore_companion::frame::{InboundFrame, OutboundFrame};
use meshcore_companion::types::{BattAndStorage, SelfInfo};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_serial::SerialPortBuilderExt;
use tracing::{debug, info, warn};

use crate::error::{HwError, KissError};
use crate::hw::client::{HwLink, Unsolicited};
use crate::hw::frame::{HwRequest, HwResponse, RadioParams};
use crate::node::contacts::{ContactStore, DEFAULT_CONTACT_CAPACITY};
use crate::node::scope::FloodScope;
use crate::node::state::{NodeConfig, NodeOutput, NodeState};
use crate::radio::validate_radio_params;

/// Advert type reported for the BBS: a room server, matching `eeb3bf2`.
const ADV_TYPE_ROOM: u8 = 3;

/// KISS command numbers for the CSMA parameters.
const KISS_CMD_TX_DELAY: u8 = 0x01;
const KISS_CMD_PERSISTENCE: u8 = 0x02;
const KISS_CMD_SLOT_TIME: u8 = 0x03;
const KISS_CMD_TX_TAIL: u8 = 0x04;
const KISS_CMD_FULL_DUPLEX: u8 = 0x05;

/// How long the worker waits for radio traffic before re-checking commands.
const IDLE_POLL: Duration = Duration::from_millis(50);

/// How many packets may wait for the radio before the oldest is dropped.
const TX_QUEUE_LIMIT: usize = 32;

/// How often the contact table is written to disk when it has changed.
///
/// Path learning updates contacts often, so the writes are coalesced rather
/// than issued per change; an SD card on a Raspberry Pi does not want one write
/// per received packet.
const CONTACT_SAVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a transmission may go without a completion before it is retried.
///
/// A lost `TxDone` would otherwise wedge the transmitter for the rest of the
/// session, because the queue only advances when the previous packet completes.
const TX_DONE_TIMEOUT: Duration = Duration::from_secs(30);

/// Settings for a [`KissClient`].
#[derive(Debug, Clone)]
pub struct KissClientConfig {
    /// OS path to the serial device.
    pub port: String,
    /// Serial baud rate; MeshCore KISS Modem firmware uses 115 200.
    pub baud_rate: u32,
    /// Node name advertised on the mesh.
    pub node_name: String,
    /// Latitude multiplied by one million, or zero for no location.
    pub latitude_1e6: i32,
    /// Longitude multiplied by one million, or zero for no location.
    pub longitude_1e6: i32,
    /// How long a single SetHardware request may go unanswered.
    pub request_timeout: Duration,
    /// Delay before the first reopen attempt after a failure.
    pub reconnect_delay_initial: Duration,
    /// Longest delay between reopen attempts.
    pub reconnect_delay_max: Duration,
    /// Transmitter keyup delay in milliseconds.
    pub tx_delay_ms: u32,
    /// CSMA persistence parameter.
    pub persistence: u8,
    /// CSMA slot interval in milliseconds.
    pub slot_time_ms: u32,
    /// Post-transmit hold time in milliseconds.
    pub tx_tail_ms: u32,
    /// Whether to bypass CSMA.
    pub full_duplex: bool,
    /// Flood scope name, when the mesh requires transport codes on flooded
    /// packets. A name without a leading `#` gets one.
    pub flood_scope: Option<String>,
    /// Where the contact table is stored between runs.
    ///
    /// Companion firmware keeps contacts in the device's flash; a KISS modem
    /// does not, so without this every restart loses every node's stored path
    /// and the BBS cannot reply until each node re-adverts.
    pub contacts_path: Option<PathBuf>,
    /// How many contacts to keep before evicting the stalest.
    pub max_contacts: usize,
    /// Bytes each hop contributes to a routing path, 2 or 3.
    ///
    /// The transport re-sends this as `SetPathHashMode` on every connect, so
    /// this value only governs packets built before that command arrives.
    pub path_bytes: u8,
}

impl KissClientConfig {
    /// Settings for `port` with the defaults every other field accepts.
    #[must_use]
    pub fn new(port: impl Into<String>) -> Self {
        Self {
            port: port.into(),
            baud_rate: 115_200,
            node_name: String::new(),
            latitude_1e6: 0,
            longitude_1e6: 0,
            request_timeout: Duration::from_secs(2),
            reconnect_delay_initial: Duration::from_secs(1),
            reconnect_delay_max: Duration::from_secs(60),
            tx_delay_ms: 500,
            persistence: 63,
            slot_time_ms: 100,
            tx_tail_ms: 0,
            full_duplex: false,
            flood_scope: None,
            contacts_path: None,
            max_contacts: DEFAULT_CONTACT_CAPACITY,
            path_bytes: 3,
        }
    }
}

/// Async handle to a KISS Modem connection.
#[derive(Debug)]
pub struct KissClient {
    cmd_tx: mpsc::Sender<OutboundFrame>,
    event_rx: mpsc::Receiver<ClientEvent>,
}

impl KissClient {
    /// Spawn the serial worker and return a handle.
    ///
    /// The worker opens the port immediately and retries with exponential
    /// backoff when it cannot.
    #[must_use]
    pub fn connect(config: KissClientConfig) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (event_tx, event_rx) = mpsc::channel(64);
        tokio::spawn(run_worker(config, cmd_rx, event_tx));
        Self { cmd_tx, event_rx }
    }

    /// Queue a command for the device.
    ///
    /// # Errors
    ///
    /// Returns [`SendError`] when the worker has exited.
    pub async fn send(&self, frame: OutboundFrame) -> Result<(), SendError> {
        self.cmd_tx.send(frame).await.map_err(|e| SendError(e.0))
    }

    /// A cloneable sender for pushing commands from elsewhere.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<OutboundFrame> {
        self.cmd_tx.clone()
    }

    /// Receive the next event, or `None` once the worker has exited.
    pub async fn recv(&mut self) -> Option<ClientEvent> {
        self.event_rx.recv().await
    }
}

async fn run_worker(
    config: KissClientConfig,
    mut cmd_rx: mpsc::Receiver<OutboundFrame>,
    event_tx: mpsc::Sender<ClientEvent>,
) {
    let mut backoff = config.reconnect_delay_initial;
    let mut node: Option<NodeState> = None;
    loop {
        match session(&config, &mut cmd_rx, &event_tx, &mut node).await {
            SessionEnd::Shutdown => {
                info!("kiss: clean shutdown");
                return;
            }
            SessionEnd::Failed { error, ran } => {
                warn!(%error, port = %config.port, "kiss: session ended");
                if ran {
                    backoff = config.reconnect_delay_initial;
                }
                if event_tx
                    .send(ClientEvent::Disconnected { will_retry: true })
                    .await
                    .is_err()
                {
                    return;
                }
                debug!(?backoff, "kiss: reopening after backoff");
                sleep(backoff).await;
                backoff = (backoff * 2).min(config.reconnect_delay_max);
            }
        }
    }
}

enum SessionEnd {
    Shutdown,
    Failed {
        error: KissError,
        /// Whether the handshake completed before the failure.
        ///
        /// A session that actually ran resets the reconnect backoff, matching
        /// `CompanionClient`; without this a few early open failures leave a
        /// long-lived link waiting the full cap on its next blip.
        ran: bool,
    },
}

async fn session(
    config: &KissClientConfig,
    cmd_rx: &mut mpsc::Receiver<OutboundFrame>,
    event_tx: &mpsc::Sender<ClientEvent>,
    carried: &mut Option<NodeState>,
) -> SessionEnd {
    let stream = match tokio_serial::new(&config.port, config.baud_rate).open_native_async() {
        Ok(stream) => stream,
        Err(error) => {
            return SessionEnd::Failed {
                error: open_error(&config.port, error),
                ran: false,
            }
        }
    };
    info!(port = %config.port, baud = config.baud_rate, "kiss: port opened");

    let mut link = HwLink::new(stream, config.request_timeout);
    let self_info = match handshake(config, &mut link).await {
        Ok(info) => info,
        Err(error) => return SessionEnd::Failed { error, ran: false },
    };
    let pubkey = self_info.pubkey;

    if event_tx
        .send(ClientEvent::Connected {
            self_info: Some(self_info),
        })
        .await
        .is_err()
    {
        return SessionEnd::Shutdown;
    }

    let mut node = match carried.take() {
        Some(node) if node.identity() == pubkey => node,
        _ => {
            let mut fresh = NodeState::new(pubkey, node_config(config));
            if let Some(path) = config.contacts_path.as_deref() {
                let restored = ContactStore::load(path, config.max_contacts);
                if !restored.is_empty() {
                    info!(
                        contacts = restored.len(),
                        path = %path.display(),
                        "kiss: restored the contact table"
                    );
                }
                *fresh.contacts_mut() = restored;
            }
            fresh
        }
    };
    if let Some(name) = config.flood_scope.as_deref() {
        match FloodScope::derive(&mut link, name).await {
            Ok(scope) => {
                info!(scope = %name, key = %hex16(scope.key()), "kiss: flood scope active");
                node.set_scope(Some(scope));
            }
            Err(error) => return SessionEnd::Failed { error, ran: false },
        }
    }

    let mut session = Session {
        link,
        node,
        tx_queue: VecDeque::new(),
        in_flight: None,
        pending_packet: None,
        last_persist: Instant::now(),
    };

    loop {
        tokio::select! {
            command = cmd_rx.recv() => {
                let Some(command) = command else {
                    return SessionEnd::Shutdown;
                };
                if let Err(error) = session.handle_command(command, event_tx).await {
                    *carried = Some(session.node);
                    return SessionEnd::Failed { error, ran: true };
                }
            }
            result = session.link.pump(IDLE_POLL) => {
                if let Err(error) = result {
                    *carried = Some(session.node);
                    return SessionEnd::Failed { error, ran: true };
                }
            }
        }

        if let Err(error) = session.drain_radio(event_tx).await {
            *carried = Some(session.node);
            return SessionEnd::Failed { error, ran: true };
        }
        if let Err(error) = session.pump_tx().await {
            *carried = Some(session.node);
            return SessionEnd::Failed { error, ran: true };
        }
        session.node.expire_pending(Instant::now());
        session.persist_contacts(config);
    }
}

struct Session<S> {
    link: HwLink<S>,
    node: NodeState,
    tx_queue: VecDeque<Vec<u8>>,
    in_flight: Option<(Vec<u8>, Instant)>,
    pending_packet: Option<Vec<u8>>,
    last_persist: Instant,
}

impl<S> Session<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    async fn drain_radio(&mut self, event_tx: &mpsc::Sender<ClientEvent>) -> Result<(), KissError> {
        while let Some(event) = self.link.next_unsolicited() {
            match event {
                Unsolicited::Packet { bytes } => {
                    if let Some(previous) = self.pending_packet.replace(bytes) {
                        self.process_packet(previous, None, event_tx).await?;
                    }
                }
                Unsolicited::RxMeta { snr_db, .. } => {
                    if let Some(packet) = self.pending_packet.take() {
                        self.process_packet(packet, Some(snr_db), event_tx).await?;
                    }
                }
                Unsolicited::TxDone { success } => {
                    if !success {
                        warn!("kiss: the radio reported a failed transmission");
                    }
                    self.in_flight = None;
                }
                Unsolicited::Error(HwError::TxBusy) => {
                    if let Some((packet, _)) = self.in_flight.take() {
                        debug!("kiss: transmitter busy, requeueing the packet");
                        self.tx_queue.push_front(packet);
                    }
                }
                Unsolicited::Error(error) => {
                    warn!(%error, "kiss: unsolicited device error");
                    self.in_flight = None;
                }
            }
        }

        if let Some(packet) = self.pending_packet.take() {
            self.process_packet(packet, None, event_tx).await?;
        }
        Ok(())
    }

    async fn process_packet(
        &mut self,
        raw: Vec<u8>,
        snr_db: Option<f32>,
        event_tx: &mpsc::Sender<ClientEvent>,
    ) -> Result<(), KissError> {
        let output = self
            .node
            .handle_inbound_packet(&mut self.link, &raw, snr_db)
            .await?;
        self.dispatch(output, event_tx).await
    }

    async fn dispatch(
        &mut self,
        output: NodeOutput,
        event_tx: &mpsc::Sender<ClientEvent>,
    ) -> Result<(), KissError> {
        for frame in output.frames {
            if event_tx.send(ClientEvent::Frame(frame)).await.is_err() {
                return Ok(());
            }
        }
        for packet in output.transmit {
            if self.tx_queue.len() >= TX_QUEUE_LIMIT {
                warn!("kiss: transmit queue full, dropping the oldest packet");
                self.tx_queue.pop_front();
            }
            self.tx_queue.push_back(packet);
        }
        Ok(())
    }

    fn persist_contacts(&mut self, config: &KissClientConfig) {
        let Some(path) = config.contacts_path.as_deref() else {
            return;
        };
        if !self.node.contacts().is_dirty() || self.last_persist.elapsed() < CONTACT_SAVE_INTERVAL {
            return;
        }
        self.last_persist = Instant::now();
        if let Err(error) = self.node.contacts_mut().save(path) {
            warn!(%error, path = %path.display(), "kiss: could not save the contact table");
        }
    }

    async fn pump_tx(&mut self) -> Result<(), KissError> {
        if let Some((packet, started)) = self.in_flight.take() {
            if started.elapsed() < TX_DONE_TIMEOUT {
                self.in_flight = Some((packet, started));
                return Ok(());
            }
            warn!(
                "kiss: no transmit completion within {:?}, requeueing the packet",
                TX_DONE_TIMEOUT
            );
            self.tx_queue.push_front(packet);
        }

        let Some(packet) = self.tx_queue.pop_front() else {
            return Ok(());
        };
        if let Ok(decoded) = crate::packet::Packet::decode(&packet) {
            debug!(
                payload_type = ?decoded.payload_type(),
                route = ?decoded.route_type(),
                path_hash_size = decoded.path_hash_size(),
                hops = decoded.path_hash_count(),
                path_length = format!("{:#04x}", decoded.path_length),
                transport_codes = ?decoded.transport_codes,
                len = packet.len(),
                "kiss: transmitting"
            );
        }
        self.link.send_data(&packet).await?;
        self.in_flight = Some((packet, Instant::now()));
        Ok(())
    }

    async fn handle_command(
        &mut self,
        command: OutboundFrame,
        event_tx: &mpsc::Sender<ClientEvent>,
    ) -> Result<(), KissError> {
        match command {
            OutboundFrame::AppStart { .. } | OutboundFrame::DeviceQuery { .. } => Ok(()),

            OutboundFrame::GetContacts { since } => {
                let contacts: Vec<_> = self
                    .node
                    .contacts()
                    .modified_since(since)
                    .into_iter()
                    .cloned()
                    .collect();
                let most_recent = self.node.contacts().most_recent_lastmod();
                let mut frames = vec![InboundFrame::ContactsStart {
                    count: u32::try_from(contacts.len()).unwrap_or(u32::MAX),
                }];
                frames.extend(contacts.into_iter().map(InboundFrame::Contact));
                frames.push(InboundFrame::EndOfContacts {
                    most_recent_lastmod: most_recent,
                });
                self.dispatch(
                    NodeOutput {
                        frames,
                        transmit: Vec::new(),
                    },
                    event_tx,
                )
                .await
            }

            OutboundFrame::SyncNextMessage => {
                let frame = self.node.sync_next_message();
                self.emit(frame, event_tx).await
            }

            OutboundFrame::SendTxtMsg {
                txt_type,
                attempt,
                timestamp,
                pubkey_prefix,
                text,
            } => {
                let output = self
                    .node
                    .send_text(
                        &mut self.link,
                        pubkey_prefix,
                        txt_type,
                        attempt,
                        timestamp,
                        text,
                    )
                    .await?;
                self.dispatch(output, event_tx).await
            }

            OutboundFrame::SendSelfAdvert { flood } => {
                let timestamp = unix_now();
                let raw = self
                    .node
                    .build_self_advert(&mut self.link, flood, timestamp)
                    .await?;
                self.dispatch(
                    NodeOutput {
                        frames: vec![InboundFrame::Ok],
                        transmit: vec![raw],
                    },
                    event_tx,
                )
                .await
            }

            OutboundFrame::SetAdvertName { name } => {
                self.node.set_node_name(name);
                self.emit(InboundFrame::Ok, event_tx).await
            }

            OutboundFrame::SetAdvertLatlon { lat_1e6, lon_1e6 } => {
                self.node.set_location(lat_1e6, lon_1e6);
                self.emit(InboundFrame::Ok, event_tx).await
            }

            OutboundFrame::SetPathHashMode { mode } => {
                let bytes = mode.saturating_add(1);
                self.node.set_path_hash_size(bytes);
                info!(path_bytes = bytes, "kiss: path-hash width applied");
                self.emit(InboundFrame::Ok, event_tx).await
            }

            OutboundFrame::ResetPath { pubkey } => {
                self.node.reset_path(&pubkey);
                self.emit(InboundFrame::Ok, event_tx).await
            }

            OutboundFrame::RemoveContact { pubkey } => {
                self.node.remove_contact(&pubkey);
                self.emit(InboundFrame::Ok, event_tx).await
            }

            OutboundFrame::SetRadioParams {
                frequency_hz,
                bandwidth_hz,
                spreading_factor,
                coding_rate,
            } => {
                let params = RadioParams {
                    frequency_hz,
                    bandwidth_hz,
                    spreading_factor,
                    coding_rate,
                };
                if let Err(error) = validate_radio_params(&params) {
                    warn!(
                        %error,
                        "kiss: refusing to write radio parameters that cannot work"
                    );
                    return self.emit(unsupported(), event_tx).await;
                }
                let response = self.link.request(HwRequest::SetRadio(params)).await?;
                self.emit(ok_or_err(response), event_tx).await
            }

            OutboundFrame::SetRadioTxPower { power_dbm } => {
                let dbm = u8::try_from(power_dbm.max(0)).unwrap_or(u8::MAX);
                let response = self.link.request(HwRequest::SetTxPower { dbm }).await?;
                self.emit(ok_or_err(response), event_tx).await
            }

            OutboundFrame::GetBattAndStorage => {
                let frame = match self.link.request(HwRequest::GetBattery).await? {
                    HwResponse::Battery { millivolts } => {
                        InboundFrame::BattAndStorage(BattAndStorage {
                            millivolts,
                            used_kb: 0,
                            total_kb: 0,
                        })
                    }
                    other => {
                        debug!(
                            ?other,
                            "kiss: battery query returned an unexpected response"
                        );
                        unsupported()
                    }
                };
                self.emit(frame, event_tx).await
            }

            OutboundFrame::SetAutoaddConfig { .. } | OutboundFrame::SetOtherParams { .. } => {
                self.emit(InboundFrame::Ok, event_tx).await
            }

            OutboundFrame::GetAutoaddConfig => {
                self.emit(InboundFrame::AutoaddConfig { config: 0x0F }, event_tx)
                    .await
            }

            other => {
                debug!(?other, "kiss: unsupported command");
                self.emit(unsupported(), event_tx).await
            }
        }
    }

    async fn emit(
        &mut self,
        frame: InboundFrame,
        event_tx: &mpsc::Sender<ClientEvent>,
    ) -> Result<(), KissError> {
        let _ = event_tx.send(ClientEvent::Frame(frame)).await;
        Ok(())
    }
}

fn node_config(config: &KissClientConfig) -> NodeConfig {
    NodeConfig {
        node_name: config.node_name.clone(),
        latitude_1e6: config.latitude_1e6,
        longitude_1e6: config.longitude_1e6,
        path_hash_size: config.path_bytes.clamp(1, 3),
        flood_scope: config.flood_scope.clone(),
    }
}

fn hex16(key: [u8; 16]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

async fn handshake<S>(
    config: &KissClientConfig,
    link: &mut HwLink<S>,
) -> Result<SelfInfo, KissError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    match link.request(HwRequest::Ping).await? {
        HwResponse::Pong => {}
        other => {
            return Err(KissError::malformed(format!(
                "device did not answer Ping with Pong; got {other:?}. Check that it runs \
                 MeshCore KISS Modem firmware and that the baud rate is correct"
            )))
        }
    }

    let pubkey = match link.request(HwRequest::GetIdentity).await? {
        HwResponse::Identity { pubkey } => pubkey,
        other => {
            return Err(KissError::malformed(format!(
                "expected identity, got {other:?}"
            )))
        }
    };

    let radio = match link.request(HwRequest::GetRadio).await? {
        HwResponse::Radio(params) => params,
        other => {
            return Err(KissError::malformed(format!(
                "expected radio, got {other:?}"
            )))
        }
    };

    let tx_power_dbm = match link.request(HwRequest::GetTxPower).await? {
        HwResponse::TxPower { dbm } => dbm,
        other => {
            return Err(KissError::malformed(format!(
                "expected tx power, got {other:?}"
            )))
        }
    };

    if let Err(error) = validate_radio_params(&radio) {
        warn!(
            %error,
            frequency_hz = radio.frequency_hz,
            "kiss: the device reports radio parameters that cannot work; it will not reach the \
             mesh until they are corrected. Check [plugins.mesh.radio] and note the values are \
             in hertz"
        );
    }

    if let HwResponse::DeviceName { name } = link.request(HwRequest::GetDeviceName).await? {
        info!(device = %name, "kiss: device identified");
    }

    push_csma(config, link).await?;

    Ok(self_info(config, pubkey, radio, tx_power_dbm))
}

async fn push_csma<S>(config: &KissClientConfig, link: &mut HwLink<S>) -> Result<(), KissError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let settings = [
        (KISS_CMD_TX_DELAY, tenths_of_ms(config.tx_delay_ms)),
        (KISS_CMD_PERSISTENCE, config.persistence),
        (KISS_CMD_SLOT_TIME, tenths_of_ms(config.slot_time_ms)),
        (KISS_CMD_TX_TAIL, tenths_of_ms(config.tx_tail_ms)),
        (KISS_CMD_FULL_DUPLEX, u8::from(config.full_duplex)),
    ];
    for (command, value) in settings {
        link.send_kiss(command, &[value]).await?;
    }
    Ok(())
}

fn tenths_of_ms(millis: u32) -> u8 {
    u8::try_from(millis / 10).unwrap_or(u8::MAX)
}

fn self_info(
    config: &KissClientConfig,
    pubkey: [u8; 32],
    radio: RadioParams,
    tx_power_dbm: u8,
) -> SelfInfo {
    SelfInfo {
        adv_type: ADV_TYPE_ROOM,
        tx_power_dbm,
        pubkey,
        latitude: config.latitude_1e6,
        longitude: config.longitude_1e6,
        multi_acks: 0,
        advert_loc_policy: 0,
        telemetry_modes: 0,
        manual_add_contacts: 0,
        frequency_khz: radio.frequency_hz / 1_000,
        bandwidth_hz: radio.bandwidth_hz,
        spreading_factor: radio.spreading_factor,
        coding_rate: radio.coding_rate,
        node_name: config.node_name.clone(),
    }
}

fn ok_or_err(response: HwResponse) -> InboundFrame {
    match response {
        HwResponse::Ok => InboundFrame::Ok,
        HwResponse::Error(error) => {
            warn!(%error, "kiss: device rejected a setting");
            InboundFrame::Err {
                error_code: ERR_CODE_UNSUPPORTED_CMD,
            }
        }
        other => {
            debug!(?other, "kiss: unexpected response to a setter");
            InboundFrame::Ok
        }
    }
}

fn unsupported() -> InboundFrame {
    InboundFrame::Err {
        error_code: ERR_CODE_UNSUPPORTED_CMD,
    }
}

fn open_error(port: &str, error: tokio_serial::Error) -> KissError {
    if matches!(
        error.kind(),
        tokio_serial::ErrorKind::Io(std::io::ErrorKind::PermissionDenied)
    ) {
        return KissError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "permission denied opening serial port {port}: the service user is not in the \
                 group that owns the device (usually `dialout`). Add it with \
                 `sudo usermod -aG dialout <user>` and log out and back in. \
                 See docs/OPERATIONS.md."
            ),
        ));
    }
    KissError::Io(std::io::Error::other(format!(
        "could not open serial port {port}: {error}"
    )))
}
