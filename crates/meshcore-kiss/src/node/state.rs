//! The MeshCore node state machine.
//!
//! [`NodeState`] turns raw LoRa packets into the companion-frame vocabulary
//! `bbs-mesh` consumes, and turns its commands back into packets. It owns the
//! contact table, path learning, duplicate suppression, the inbound message
//! queue and the pending-acknowledgement table.
//!
//! Every cryptographic step is a request to the modem through [`HwLink`].
//!
//! # Addressing
//!
//! MeshCore addresses a packet by the first byte of the destination's public
//! key, so collisions between contacts are ordinary. An inbound encrypted
//! payload is attributed by trying each candidate contact's shared secret and
//! treating [`HwError::MacFailed`] as "not this one".

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use meshcore_companion::frame::InboundFrame;
use meshcore_companion::types::{ContactMsg, SentResult};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use crate::error::{HwError, KissError};
use crate::hw::client::HwLink;
use crate::hw::frame::{HwRequest, HwResponse};
use crate::node::ack::{ack_hash_input, expected_ack_from_digest, inbound_ack_hash, PendingAcks};
use crate::node::contacts::ContactStore;
use crate::node::scope::FloodScope;
use crate::packet::{
    AdvertBody, EncryptedBody, Packet, PathBody, PayloadType, RouteType, TxtMsgPlain,
    MAX_PACKET_PAYLOAD,
};

/// Node type advertised for the BBS: a room server.
///
/// Companion apps categorise nodes by this value and will not list the BBS as a
/// BBS unless it advertises as a room. Advertising as a chat node was fixed in
/// `eeb3bf2` for the companion path; the KISS path must match.
pub const ADV_TYPE_ROOM: u8 = 3;

/// How many recently seen packet identifiers are remembered.
const SEEN_CAPACITY: usize = 128;

/// How many inbound messages may queue before the oldest is dropped.
const INBOX_CAPACITY: usize = 64;

/// How long a sent message waits for its acknowledgement before being forgotten.
const PENDING_ACK_TTL: Duration = Duration::from_secs(300);

/// How many random bytes are fetched from the modem at a time.
const RANDOM_BATCH: u8 = 32;

/// Settings the node needs that do not come from the device.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Name carried in the self-advert.
    pub node_name: String,
    /// Latitude multiplied by one million, or zero for no location.
    pub latitude_1e6: i32,
    /// Longitude multiplied by one million, or zero for no location.
    pub longitude_1e6: i32,
    /// Bytes each hop contributes to a path, 1 to 3.
    pub path_hash_size: u8,
    /// Flood scope name, when the mesh requires transport codes.
    pub flood_scope: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: String::new(),
            latitude_1e6: 0,
            longitude_1e6: 0,
            path_hash_size: 3,
            flood_scope: None,
        }
    }
}

/// What handling one event produced.
#[derive(Debug, Default, PartialEq)]
pub struct NodeOutput {
    /// Frames to hand to the mesh transport.
    pub frames: Vec<InboundFrame>,
    /// Raw packets to transmit.
    pub transmit: Vec<Vec<u8>>,
}

impl NodeOutput {
    fn frame(frame: InboundFrame) -> Self {
        Self {
            frames: vec![frame],
            transmit: Vec::new(),
        }
    }
}

/// Identify a packet by payload type and the whole payload.
///
/// The firmware keys its duplicate table on a hash of the payload type and the
/// full payload (`Packet::calculatePacketHash`), deliberately excluding the
/// header, path length and path, because every repeater rewrites those as the
/// packet floods. Hashing a prefix instead would collapse distinct packets that
/// share a leading field: an advert opens with a 32-byte public key, so every
/// advert from one node would look like a repeat of the first.
///
/// This is a hash-table key, not a security boundary, so FNV-1a is enough and
/// keeps the node free of host-side cryptography.
fn packet_identity(packet: &Packet) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in std::iter::once(packet.payload_type() as u8).chain(packet.payload.iter().copied()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// A message awaiting its end-to-end acknowledgement.
#[derive(Debug, Clone)]
struct PendingSend {
    pubkey: [u8; 32],
}

/// The MeshCore node.
pub struct NodeState {
    identity: [u8; 32],
    config: NodeConfig,
    contacts: ContactStore,
    seen: VecDeque<u64>,
    inbox: VecDeque<ContactMsg>,
    pending: PendingAcks<PendingSend>,
    random_pool: Vec<u8>,
    scope: Option<FloodScope>,
}

impl NodeState {
    /// Create a node with the device's identity and the operator's settings.
    #[must_use]
    pub fn new(identity: [u8; 32], config: NodeConfig) -> Self {
        Self {
            identity,
            config,
            contacts: ContactStore::default(),
            seen: VecDeque::with_capacity(SEEN_CAPACITY),
            inbox: VecDeque::new(),
            pending: PendingAcks::new(),
            random_pool: Vec::new(),
            scope: None,
        }
    }

    /// The configured flood scope name, when the mesh requires one.
    #[must_use]
    pub fn scope_name(&self) -> Option<&str> {
        self.config.flood_scope.as_deref()
    }

    /// Install the derived flood scope key.
    pub fn set_scope(&mut self, scope: Option<FloodScope>) {
        self.scope = scope;
    }

    /// Whether outbound packets carry a transport code.
    #[must_use]
    pub fn has_scope(&self) -> bool {
        self.scope.is_some()
    }

    /// The contact table.
    #[must_use]
    pub fn contacts(&self) -> &ContactStore {
        &self.contacts
    }

    /// The contact table, mutably.
    pub fn contacts_mut(&mut self) -> &mut ContactStore {
        &mut self.contacts
    }

    /// The node's own public key.
    #[must_use]
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }

    /// Replace the advertised node name.
    pub fn set_node_name(&mut self, name: String) {
        self.config.node_name = name;
    }

    /// Replace the advertised location.
    pub fn set_location(&mut self, latitude_1e6: i32, longitude_1e6: i32) {
        self.config.latitude_1e6 = latitude_1e6;
        self.config.longitude_1e6 = longitude_1e6;
    }

    /// Set how many bytes each hop contributes to a path.
    pub fn set_path_hash_size(&mut self, size: u8) {
        self.config.path_hash_size = size.clamp(1, 3);
    }

    /// How many messages are waiting to be synced.
    #[must_use]
    pub fn queued_messages(&self) -> usize {
        self.inbox.len()
    }

    /// Pop the next queued message, or report that there are none.
    pub fn sync_next_message(&mut self) -> InboundFrame {
        match self.inbox.pop_front() {
            Some(message) => InboundFrame::ContactMsgRecv(message),
            None => InboundFrame::NoMoreMessages,
        }
    }

    /// Forget a contact's stored path so the next send floods.
    pub fn reset_path(&mut self, pubkey: &[u8; 32]) -> bool {
        self.contacts.reset_path(pubkey)
    }

    /// Drop a contact and its cached shared secret.
    pub fn remove_contact(&mut self, pubkey: &[u8; 32]) -> bool {
        self.contacts.remove(pubkey)
    }

    /// Drop pending acknowledgements that will never arrive.
    pub fn expire_pending(&mut self, now: Instant) {
        let expired = self.pending.expire(now, PENDING_ACK_TTL);
        if !expired.is_empty() {
            debug!(
                count = expired.len(),
                "kiss: pending acknowledgements timed out"
            );
        }
    }

    async fn finish_packet<S>(
        &self,
        link: &mut HwLink<S>,
        route: RouteType,
        payload_type: PayloadType,
        path: &[u8],
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut packet = Packet::build(
            route,
            payload_type,
            self.config.path_hash_size,
            path,
            payload,
        );

        if let Some(scope) = self.scope {
            let code = scope
                .transport_code(link, payload_type, &packet.payload)
                .await?;
            let scoped = match route {
                RouteType::Flood | RouteType::TransportFlood => RouteType::TransportFlood,
                RouteType::Direct | RouteType::TransportDirect => RouteType::TransportDirect,
            };
            packet.header = (packet.header & !0x03) | (scoped as u8);
            packet.transport_codes = Some([code, 0]);
        }

        Ok(packet.encode())
    }

    /// Build a signed self-advert ready to transmit.
    ///
    /// # Errors
    ///
    /// Returns an error when the modem fails to sign the advert.
    pub async fn build_self_advert<S>(
        &mut self,
        link: &mut HwLink<S>,
        flood: bool,
        timestamp: u32,
    ) -> Result<Vec<u8>, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let location = if self.config.latitude_1e6 == 0 && self.config.longitude_1e6 == 0 {
            None
        } else {
            Some((self.config.latitude_1e6, self.config.longitude_1e6))
        };
        let name = if self.config.node_name.is_empty() {
            None
        } else {
            Some(self.config.node_name.as_str())
        };

        let mut advert =
            AdvertBody::unsigned(self.identity, timestamp, ADV_TYPE_ROOM, location, name);
        advert.signature = match link
            .request(HwRequest::SignData {
                data: advert.signed_bytes(),
            })
            .await?
        {
            HwResponse::Signature { signature } => signature,
            other => {
                return Err(KissError::malformed(format!(
                    "expected a signature for the self-advert, got {other:?}"
                )))
            }
        };

        let route = if flood {
            RouteType::Flood
        } else {
            RouteType::Direct
        };
        self.finish_packet(link, route, PayloadType::Advert, &[], advert.encode())
            .await
    }

    /// Send a text message to the contact identified by a six-byte key prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when the modem fails a cryptographic request.
    pub async fn send_text<S>(
        &mut self,
        link: &mut HwLink<S>,
        pubkey_prefix: [u8; 6],
        txt_type: u8,
        attempt: u8,
        timestamp: u32,
        text: String,
    ) -> Result<NodeOutput, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Some(contact) = self.contacts.by_prefix(&pubkey_prefix) else {
            warn!(
                prefix = ?pubkey_prefix,
                "kiss: no contact matches the recipient prefix"
            );
            return Ok(NodeOutput::frame(InboundFrame::Sent(SentResult {
                is_flood: false,
                expected_ack: 0,
                timeout_ms: 0,
            })));
        };
        let pubkey = contact.pubkey;
        let out_path_len = contact.out_path_len;
        let out_path = contact.out_path;

        let plain = TxtMsgPlain {
            timestamp,
            txt_type,
            attempt: attempt & 0x03,
            text,
            extended_attempt: if attempt > 3 { attempt } else { 0 },
        };

        let secret = self.shared_secret(link, &pubkey).await?;
        let (mac, ciphertext) = match link
            .request(HwRequest::EncryptData {
                key: secret,
                plaintext: plain.encode(),
            })
            .await?
        {
            HwResponse::Encrypted { mac, ciphertext } => (mac, ciphertext),
            HwResponse::Error(error) => return Err(KissError::Device(error)),
            other => {
                return Err(KissError::malformed(format!(
                    "expected ciphertext, got {other:?}"
                )))
            }
        };

        let body = EncryptedBody {
            dest_hash: pubkey[0],
            src_hash: self.identity[0],
            mac,
            ciphertext,
        };
        let payload = body.encode();
        if payload.len() > MAX_PACKET_PAYLOAD {
            warn!(
                len = payload.len(),
                "kiss: refusing an oversized text message"
            );
            return Ok(NodeOutput::frame(InboundFrame::Sent(SentResult {
                is_flood: false,
                expected_ack: 0,
                timeout_ms: 0,
            })));
        }

        let is_flood = out_path_len < 0;
        let (route, path) = if is_flood {
            (RouteType::Flood, Vec::new())
        } else {
            let len = usize::try_from(out_path_len).unwrap_or(0);
            (RouteType::Direct, out_path[..len].to_vec())
        };
        let raw = self
            .finish_packet(link, route, PayloadType::TxtMsg, &path, payload)
            .await?;

        let digest = self
            .hash(link, &ack_hash_input(&plain, &self.identity))
            .await?;
        let expected_ack = expected_ack_from_digest(&digest);
        let timeout_ms = self.airtime_ms(link, raw.len()).await?;

        self.pending.insert(expected_ack, PendingSend { pubkey });

        Ok(NodeOutput {
            frames: vec![InboundFrame::Sent(SentResult {
                is_flood,
                expected_ack,
                timeout_ms,
            })],
            transmit: vec![raw],
        })
    }

    /// Handle one raw packet received by the radio.
    ///
    /// # Errors
    ///
    /// Returns an error when the modem fails a cryptographic request. A
    /// malformed or unattributable packet is dropped without error.
    pub async fn handle_inbound_packet<S>(
        &mut self,
        link: &mut HwLink<S>,
        raw: &[u8],
        snr_db: Option<f32>,
    ) -> Result<NodeOutput, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let packet = match Packet::decode(raw) {
            Ok(packet) => packet,
            Err(error) => {
                debug!(%error, "kiss: dropping an undecodable packet");
                return Ok(NodeOutput::default());
            }
        };

        if self.already_seen(&packet) {
            debug!("kiss: dropping a duplicate packet");
            return Ok(NodeOutput::default());
        }

        match packet.payload_type() {
            PayloadType::Advert => self.handle_advert(link, &packet).await,
            PayloadType::TxtMsg => self.handle_encrypted(link, &packet, snr_db).await,
            PayloadType::Path => self.handle_encrypted(link, &packet, snr_db).await,
            PayloadType::Ack => Ok(self.handle_ack_payload(&packet.payload)),
            other => {
                debug!(?other, "kiss: ignoring an unsupported payload type");
                Ok(NodeOutput::default())
            }
        }
    }

    async fn handle_advert<S>(
        &mut self,
        link: &mut HwLink<S>,
        packet: &Packet,
    ) -> Result<NodeOutput, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let advert = match AdvertBody::parse(&packet.payload) {
            Ok(advert) => advert,
            Err(error) => {
                debug!(%error, "kiss: dropping a malformed advert");
                return Ok(NodeOutput::default());
            }
        };

        if advert.pubkey == self.identity {
            return Ok(NodeOutput::default());
        }

        let valid = match link
            .request(HwRequest::VerifySignature {
                pubkey: advert.pubkey,
                signature: advert.signature,
                data: advert.signed_bytes(),
            })
            .await?
        {
            HwResponse::Verify { valid } => valid,
            other => {
                debug!(
                    ?other,
                    "kiss: advert verification returned an unexpected response"
                );
                false
            }
        };
        if !valid {
            debug!("kiss: dropping an advert whose signature did not verify");
            return Ok(NodeOutput::default());
        }

        let is_new = self.contacts.upsert_from_advert(&advert);
        let mut output = NodeOutput::default();

        if packet.route_type().is_flood()
            && !packet.path.is_empty()
            && self.contacts.set_path(&advert.pubkey, &packet.path)
        {
            output.frames.push(InboundFrame::PathUpdated {
                pubkey: advert.pubkey,
            });
        }

        match self.contacts.by_pubkey(&advert.pubkey) {
            Some(contact) if is_new => output
                .frames
                .insert(0, InboundFrame::NewAdvert(contact.clone())),
            Some(_) => output.frames.insert(
                0,
                InboundFrame::Advert {
                    pubkey: advert.pubkey,
                },
            ),
            None => {}
        }

        Ok(output)
    }

    async fn handle_encrypted<S>(
        &mut self,
        link: &mut HwLink<S>,
        packet: &Packet,
        snr_db: Option<f32>,
    ) -> Result<NodeOutput, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let body = match EncryptedBody::parse(&packet.payload) {
            Ok(body) => body,
            Err(error) => {
                debug!(%error, "kiss: dropping a malformed encrypted payload");
                return Ok(NodeOutput::default());
            }
        };

        if body.dest_hash != self.identity[0] {
            return Ok(NodeOutput::default());
        }

        let candidates: Vec<[u8; 32]> = self
            .contacts
            .by_hash(body.src_hash)
            .into_iter()
            .map(|contact| contact.pubkey)
            .collect();

        for pubkey in candidates {
            let secret = self.shared_secret(link, &pubkey).await?;
            let plaintext = match link
                .request(HwRequest::DecryptData {
                    key: secret,
                    mac: body.mac,
                    ciphertext: body.ciphertext.clone(),
                })
                .await?
            {
                HwResponse::Decrypted { plaintext } => plaintext,
                HwResponse::Error(HwError::MacFailed) => continue,
                HwResponse::Error(error) => return Err(KissError::Device(error)),
                other => {
                    debug!(?other, "kiss: unexpected response while decrypting");
                    continue;
                }
            };

            return match packet.payload_type() {
                PayloadType::TxtMsg => {
                    self.accept_text(link, packet, &pubkey, &plaintext, snr_db)
                        .await
                }
                PayloadType::Path => Ok(self.accept_path(&pubkey, &plaintext)),
                other => {
                    debug!(?other, "kiss: decrypted an unsupported payload type");
                    Ok(NodeOutput::default())
                }
            };
        }

        debug!(
            src_hash = body.src_hash,
            "kiss: no known contact could decrypt the payload"
        );
        Ok(NodeOutput::default())
    }

    async fn accept_text<S>(
        &mut self,
        link: &mut HwLink<S>,
        packet: &Packet,
        pubkey: &[u8; 32],
        plaintext: &[u8],
        snr_db: Option<f32>,
    ) -> Result<NodeOutput, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let plain = match TxtMsgPlain::parse(plaintext) {
            Ok(plain) => plain,
            Err(error) => {
                debug!(%error, "kiss: dropping an unparsable text message");
                return Ok(NodeOutput::default());
            }
        };

        let mut output = NodeOutput::default();

        if packet.route_type().is_flood()
            && !packet.path.is_empty()
            && self.contacts.set_path(pubkey, &packet.path)
        {
            output
                .frames
                .push(InboundFrame::PathUpdated { pubkey: *pubkey });
        }

        let mut prefix = [0u8; 6];
        prefix.copy_from_slice(&pubkey[..6]);
        let message = ContactMsg {
            sender_key_prefix: prefix,
            path_len: packet.path_hash_count(),
            txt_type: plain.txt_type,
            timestamp: plain.timestamp,
            text: plain.text.clone(),
            snr: snr_db,
        };
        if self.inbox.len() >= INBOX_CAPACITY {
            warn!("kiss: inbound queue full, dropping the oldest message");
            self.inbox.pop_front();
        }
        self.inbox.push_back(message);
        output.frames.push(InboundFrame::MsgWaiting);

        let digest = self.hash(link, &ack_hash_input(&plain, pubkey)).await?;
        let random_byte = self.random_byte(link).await?;
        let ack_hash = inbound_ack_hash(&digest, plain.extended_attempt, random_byte);

        let contact_path = self
            .contacts
            .by_pubkey(pubkey)
            .map(|contact| (contact.out_path_len, contact.out_path));

        let raw = if packet.route_type().is_flood() {
            let secret = self.shared_secret(link, pubkey).await?;
            self.build_path_return(link, pubkey, secret, &packet.path, &ack_hash)
                .await?
        } else {
            let (len, path) = contact_path.unwrap_or((-1, [0u8; 64]));
            let (route, path) = if len < 0 {
                (RouteType::Flood, Vec::new())
            } else {
                let len = usize::try_from(len).unwrap_or(0);
                (RouteType::Direct, path[..len].to_vec())
            };
            Some(
                self.finish_packet(link, route, PayloadType::Ack, &path, ack_hash.to_vec())
                    .await?,
            )
        };

        if let Some(raw) = raw {
            output.transmit.push(raw);
        }
        Ok(output)
    }

    async fn build_path_return<S>(
        &mut self,
        link: &mut HwLink<S>,
        pubkey: &[u8; 32],
        secret: [u8; 32],
        path: &[u8],
        ack_hash: &[u8; 6],
    ) -> Result<Option<Vec<u8>>, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let plaintext = PathBody {
            path: path.to_vec(),
            extra_type: Some(PayloadType::Ack as u8),
            extra: ack_hash.to_vec(),
        }
        .encode();

        let (mac, ciphertext) = match link
            .request(HwRequest::EncryptData {
                key: secret,
                plaintext,
            })
            .await?
        {
            HwResponse::Encrypted { mac, ciphertext } => (mac, ciphertext),
            other => {
                debug!(?other, "kiss: could not encrypt the path return");
                return Ok(None);
            }
        };

        let body = EncryptedBody {
            dest_hash: pubkey[0],
            src_hash: self.identity[0],
            mac,
            ciphertext,
        };
        Ok(Some(
            self.finish_packet(
                link,
                RouteType::Flood,
                PayloadType::Path,
                &[],
                body.encode(),
            )
            .await?,
        ))
    }

    fn accept_path(&mut self, pubkey: &[u8; 32], plaintext: &[u8]) -> NodeOutput {
        let body = match PathBody::parse(plaintext) {
            Ok(body) => body,
            Err(error) => {
                debug!(%error, "kiss: dropping a malformed path return");
                return NodeOutput::default();
            }
        };

        let mut output = NodeOutput::default();
        if self.contacts.set_path(pubkey, &body.path) {
            output
                .frames
                .push(InboundFrame::PathUpdated { pubkey: *pubkey });
        }

        if body.extra_type == Some(PayloadType::Ack as u8) {
            let bundled = self.handle_ack_payload(&body.extra);
            output.frames.extend(bundled.frames);
        }

        output
    }

    fn handle_ack_payload(&mut self, payload: &[u8]) -> NodeOutput {
        let Some(bytes) = payload.get(..4) else {
            debug!("kiss: dropping a truncated acknowledgement");
            return NodeOutput::default();
        };
        let crc = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        match self.pending.take(crc) {
            Some(pending) => {
                debug!(
                    crc,
                    recipient = ?&pending.pubkey[..6],
                    "kiss: message delivery confirmed"
                );
                NodeOutput::frame(InboundFrame::SendConfirmed { crc })
            }
            None => {
                debug!(crc, "kiss: acknowledgement matched no pending message");
                NodeOutput::default()
            }
        }
    }

    fn already_seen(&mut self, packet: &Packet) -> bool {
        let key = packet_identity(packet);
        if self.seen.contains(&key) {
            return true;
        }
        if self.seen.len() >= SEEN_CAPACITY {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        false
    }

    async fn shared_secret<S>(
        &mut self,
        link: &mut HwLink<S>,
        pubkey: &[u8; 32],
    ) -> Result<[u8; 32], KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Some(secret) = self.contacts.cached_secret(pubkey) {
            return Ok(*secret);
        }
        let secret = match link
            .request(HwRequest::KeyExchange {
                peer_pubkey: *pubkey,
            })
            .await?
        {
            HwResponse::SharedSecret { secret } => secret,
            other => {
                return Err(KissError::malformed(format!(
                    "expected a shared secret, got {other:?}"
                )))
            }
        };
        self.contacts.store_secret(pubkey, secret);
        Ok(secret)
    }

    async fn hash<S>(&self, link: &mut HwLink<S>, data: &[u8]) -> Result<[u8; 32], KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match link
            .request(HwRequest::Hash {
                data: data.to_vec(),
            })
            .await?
        {
            HwResponse::Hash { digest } => Ok(digest),
            other => Err(KissError::malformed(format!(
                "expected a digest, got {other:?}"
            ))),
        }
    }

    async fn random_byte<S>(&mut self, link: &mut HwLink<S>) -> Result<u8, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Some(byte) = self.random_pool.pop() {
            return Ok(byte);
        }
        match link
            .request(HwRequest::GetRandom { len: RANDOM_BATCH })
            .await?
        {
            HwResponse::Random { bytes } if !bytes.is_empty() => {
                self.random_pool = bytes;
                Ok(self.random_pool.pop().unwrap_or(0))
            }
            other => {
                debug!(?other, "kiss: random request failed, falling back to zero");
                Ok(0)
            }
        }
    }

    async fn airtime_ms<S>(&self, link: &mut HwLink<S>, packet_len: usize) -> Result<u32, KissError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let len = u8::try_from(packet_len).unwrap_or(u8::MAX);
        match link
            .request(HwRequest::GetAirtime { packet_len: len })
            .await?
        {
            HwResponse::Airtime { millis } => Ok(millis.saturating_mul(4).max(4_000)),
            other => {
                debug!(
                    ?other,
                    "kiss: airtime query failed, using a default timeout"
                );
                Ok(10_000)
            }
        }
    }
}
