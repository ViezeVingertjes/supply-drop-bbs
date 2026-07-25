//! MeshCore v1 packet and payload bodies.
//!
//! The wire format is `[header][transport_codes?][path_length][path][payload]`,
//! as documented in the firmware's `docs/packet_format.md`. Every multi-byte
//! field is little-endian.
//!
//! The header packs three fields: the route type in bits 0-1, the payload type
//! in bits 2-5, and the payload version in bits 6-7. The four transport-code
//! bytes are present only for the two transport route types. `path_length` is
//! not a byte count — it packs a hop count in bits 0-5 and the path hash size
//! minus one in bits 6-7, so the path occupies `hop_count * hash_size` bytes.
//!
//! Payload bodies are modelled only as far as this crate needs them: adverts,
//! the encrypted envelope shared by request, response, text and path payloads,
//! and the plaintext inside a text message. Everything else stays raw bytes.

use crate::error::KissError;

/// Maximum path length in bytes, from the firmware's `MAX_PATH_SIZE`.
pub const MAX_PATH_SIZE: usize = 64;

/// Maximum payload length in bytes, from the firmware's `MAX_PACKET_PAYLOAD`.
pub const MAX_PACKET_PAYLOAD: usize = 184;

/// Maximum encoded packet length in bytes, from the firmware's
/// `MAX_TRANS_UNIT`.
pub const MAX_TRANS_UNIT: usize = 255;

/// Length of the fixed part of an advert payload: public key, timestamp and
/// signature, with the appdata following it.
pub const ADVERT_PREFIX_LEN: usize = 32 + 4 + 64;

/// Advert appdata flag: latitude and longitude follow the flags byte.
pub const ADV_FLAG_HAS_LOCATION: u8 = 0x10;

/// Advert appdata flag: a reserved two-byte feature field is present.
pub const ADV_FLAG_HAS_FEATURE1: u8 = 0x20;

/// Advert appdata flag: a second reserved two-byte feature field is present.
pub const ADV_FLAG_HAS_FEATURE2: u8 = 0x40;

/// Advert appdata flag: the remainder of the appdata is the node name.
pub const ADV_FLAG_HAS_NAME: u8 = 0x80;

/// How a packet is routed through the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RouteType {
    /// Flood routing, with transport codes in the header.
    TransportFlood = 0x00,
    /// Flood routing: every repeater rebroadcasts and appends its hash.
    Flood = 0x01,
    /// Direct routing along the path carried by the packet.
    Direct = 0x02,
    /// Direct routing, with transport codes in the header.
    TransportDirect = 0x03,
}

impl RouteType {
    /// Read the route type from a packet header's low two bits.
    #[must_use]
    pub fn from_bits(header: u8) -> Self {
        match header & 0x03 {
            0x00 => Self::TransportFlood,
            0x01 => Self::Flood,
            0x02 => Self::Direct,
            _ => Self::TransportDirect,
        }
    }

    /// Whether packets of this route type carry four transport-code bytes.
    #[must_use]
    pub fn has_transport_codes(self) -> bool {
        matches!(self, Self::TransportFlood | Self::TransportDirect)
    }

    /// Whether this route type floods the packet across the mesh.
    #[must_use]
    pub fn is_flood(self) -> bool {
        matches!(self, Self::Flood | Self::TransportFlood)
    }

    /// Whether this route type follows the packet's own path.
    #[must_use]
    pub fn is_direct(self) -> bool {
        matches!(self, Self::Direct | Self::TransportDirect)
    }
}

/// The kind of payload a packet carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PayloadType {
    /// Request: destination and source hashes, MAC, then ciphertext.
    Req = 0x00,
    /// Response to a request or an anonymous request.
    Response = 0x01,
    /// Text message.
    TxtMsg = 0x02,
    /// Acknowledgement, carrying a four-byte checksum.
    Ack = 0x03,
    /// Node advertisement.
    Advert = 0x04,
    /// Unverified group text message.
    GrpTxt = 0x05,
    /// Unverified group datagram.
    GrpData = 0x06,
    /// Anonymous request, prefixed with the sender's public key.
    AnonReq = 0x07,
    /// Returned path, optionally bundling another payload.
    Path = 0x08,
    /// Path trace, collecting the SNR of each hop.
    Trace = 0x09,
    /// One packet of a multi-part sequence.
    Multipart = 0x0A,
    /// Unencrypted control and discovery data.
    Control = 0x0B,
    /// Reserved by the protocol.
    Reserved12 = 0x0C,
    /// Reserved by the protocol.
    Reserved13 = 0x0D,
    /// Reserved by the protocol.
    Reserved14 = 0x0E,
    /// Custom raw payload with application-defined encryption.
    RawCustom = 0x0F,
}

impl PayloadType {
    /// Read the payload type from a packet header's bits 2-5.
    #[must_use]
    pub fn from_bits(header: u8) -> Self {
        match (header >> 2) & 0x0F {
            0x00 => Self::Req,
            0x01 => Self::Response,
            0x02 => Self::TxtMsg,
            0x03 => Self::Ack,
            0x04 => Self::Advert,
            0x05 => Self::GrpTxt,
            0x06 => Self::GrpData,
            0x07 => Self::AnonReq,
            0x08 => Self::Path,
            0x09 => Self::Trace,
            0x0A => Self::Multipart,
            0x0B => Self::Control,
            0x0C => Self::Reserved12,
            0x0D => Self::Reserved13,
            0x0E => Self::Reserved14,
            _ => Self::RawCustom,
        }
    }
}

/// A MeshCore v1 packet.
///
/// `path` holds exactly `path_hash_count() * path_hash_size()` bytes for any
/// packet produced by [`Packet::decode`], and hand-built packets are expected
/// to preserve that relationship: [`Packet::encode`] writes `path_length` and
/// `path` as given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Route type, payload type and payload version, packed.
    pub header: u8,
    /// The two transport codes, present only for transport route types.
    pub transport_codes: Option<[u16; 2]>,
    /// Hop count in bits 0-5, path hash size minus one in bits 6-7.
    pub path_length: u8,
    /// Accumulated or supplied path hashes.
    pub path: Vec<u8>,
    /// Payload bytes, interpreted according to [`Packet::payload_type`].
    pub payload: Vec<u8>,
}

impl Packet {
    /// Parse a raw LoRa packet.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Malformed`] when the input is truncated, when the
    /// path hash size code is the reserved `0b11`, when the path exceeds
    /// [`MAX_PATH_SIZE`], when the payload is empty or exceeds
    /// [`MAX_PACKET_PAYLOAD`], or when the whole packet exceeds
    /// [`MAX_TRANS_UNIT`].
    pub fn decode(raw: &[u8]) -> Result<Self, KissError> {
        if raw.len() > MAX_TRANS_UNIT {
            return Err(KissError::malformed(format!(
                "packet is {} bytes, over the {MAX_TRANS_UNIT}-byte transmission unit",
                raw.len()
            )));
        }
        let header = *raw
            .first()
            .ok_or_else(|| KissError::malformed("packet has no header byte"))?;
        let mut cursor = 1;

        let transport_codes = if RouteType::from_bits(header).has_transport_codes() {
            let bytes: [u8; 4] = raw
                .get(cursor..cursor + 4)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| KissError::malformed("packet truncated in transport codes"))?;
            cursor += 4;
            Some([
                u16::from_le_bytes([bytes[0], bytes[1]]),
                u16::from_le_bytes([bytes[2], bytes[3]]),
            ])
        } else {
            None
        };

        let path_length = *raw
            .get(cursor)
            .ok_or_else(|| KissError::malformed("packet has no path_length byte"))?;
        cursor += 1;
        if path_length >> 6 == 0b11 {
            return Err(KissError::malformed(
                "path_length uses the reserved 4-byte hash size",
            ));
        }
        let path_bytes = usize::from(path_length & 0x3F) * (usize::from(path_length >> 6) + 1);
        if path_bytes > MAX_PATH_SIZE {
            return Err(KissError::malformed(format!(
                "path is {path_bytes} bytes, over the {MAX_PATH_SIZE}-byte limit"
            )));
        }
        let path = raw
            .get(cursor..cursor + path_bytes)
            .ok_or_else(|| KissError::malformed("packet truncated in path"))?
            .to_vec();
        cursor += path_bytes;

        let payload = raw
            .get(cursor..)
            .ok_or_else(|| KissError::malformed("packet truncated before payload"))?
            .to_vec();
        if payload.is_empty() {
            return Err(KissError::malformed("packet has an empty payload"));
        }
        if payload.len() > MAX_PACKET_PAYLOAD {
            return Err(KissError::malformed(format!(
                "payload is {} bytes, over the {MAX_PACKET_PAYLOAD}-byte limit",
                payload.len()
            )));
        }

        Ok(Self {
            header,
            transport_codes,
            path_length,
            path,
            payload,
        })
    }

    /// Serialise the packet for transmission.
    ///
    /// Transport codes are written whenever [`Packet::route_type`] calls for
    /// them, defaulting to zeroes when the field is unset, so the output is
    /// always parseable by [`Packet::decode`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.path.len() + self.payload.len());
        out.push(self.header);
        if self.route_type().has_transport_codes() {
            let codes = self.transport_codes.unwrap_or([0, 0]);
            out.extend_from_slice(&codes[0].to_le_bytes());
            out.extend_from_slice(&codes[1].to_le_bytes());
        }
        out.push(self.path_length);
        out.extend_from_slice(&self.path);
        out.extend_from_slice(&self.payload);
        out
    }

    /// The packet's route type.
    #[must_use]
    pub fn route_type(&self) -> RouteType {
        RouteType::from_bits(self.header)
    }

    /// The packet's payload type.
    #[must_use]
    pub fn payload_type(&self) -> PayloadType {
        PayloadType::from_bits(self.header)
    }

    /// The payload format version, zero for the only version in use.
    #[must_use]
    pub fn payload_version(&self) -> u8 {
        (self.header >> 6) & 0x03
    }

    /// The width in bytes of each hash in [`Packet::path`].
    #[must_use]
    pub fn path_hash_size(&self) -> u8 {
        (self.path_length >> 6) + 1
    }

    /// The number of hashes in [`Packet::path`].
    #[must_use]
    pub fn path_hash_count(&self) -> u8 {
        self.path_length & 0x3F
    }
}

/// A decoded advert payload.
///
/// The appdata that follows the signature is modelled as its flags byte plus
/// the location and name it may carry. The two reserved feature fields are
/// skipped while parsing and are not retained, so an advert that uses them
/// does not re-serialise byte-for-byte; no released firmware sets those flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertBody {
    /// The advertising node's Ed25519 public key.
    pub pubkey: [u8; 32],
    /// Unix timestamp the advert was created at.
    pub timestamp: u32,
    /// Ed25519 signature over [`AdvertBody::signed_bytes`].
    pub signature: [u8; 64],
    /// Appdata flags: node type in the low nibble, presence bits above it.
    pub flags: u8,
    /// Latitude multiplied by one million, when the location flag is set.
    pub latitude_1e6: Option<i32>,
    /// Longitude multiplied by one million, when the location flag is set.
    pub longitude_1e6: Option<i32>,
    /// Node name, when the name flag is set and a name follows.
    pub name: Option<String>,
    /// The appdata exactly as it arrived, flags byte included.
    ///
    /// The signature covers these bytes verbatim, so they are kept rather than
    /// rebuilt from the parsed fields above. Rebuilding would drop reserved
    /// feature fields this crate does not model and would normalise a name
    /// that is not valid UTF-8, and either would make a genuine advert fail
    /// verification.
    pub appdata: Vec<u8>,
}

impl AdvertBody {
    /// Parse an advert payload.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Malformed`] when the payload is shorter than the
    /// public key, timestamp, signature and flags byte, or when a presence
    /// flag promises appdata that is not there.
    pub fn parse(payload: &[u8]) -> Result<Self, KissError> {
        let pubkey: [u8; 32] = payload
            .get(..32)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| KissError::malformed("advert truncated in public key"))?;
        let timestamp: [u8; 4] = payload
            .get(32..36)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| KissError::malformed("advert truncated in timestamp"))?;
        let signature: [u8; 64] = payload
            .get(36..ADVERT_PREFIX_LEN)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| KissError::malformed("advert truncated in signature"))?;

        let appdata = payload
            .get(ADVERT_PREFIX_LEN..)
            .ok_or_else(|| KissError::malformed("advert truncated before appdata"))?;
        let flags = *appdata
            .first()
            .ok_or_else(|| KissError::malformed("advert appdata has no flags byte"))?;
        let mut cursor = 1;

        let (latitude_1e6, longitude_1e6) = if flags & ADV_FLAG_HAS_LOCATION == 0 {
            (None, None)
        } else {
            let latitude: [u8; 4] = appdata
                .get(cursor..cursor + 4)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| KissError::malformed("advert truncated in latitude"))?;
            let longitude: [u8; 4] = appdata
                .get(cursor + 4..cursor + 8)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| KissError::malformed("advert truncated in longitude"))?;
            cursor += 8;
            (
                Some(i32::from_le_bytes(latitude)),
                Some(i32::from_le_bytes(longitude)),
            )
        };

        for flag in [ADV_FLAG_HAS_FEATURE1, ADV_FLAG_HAS_FEATURE2] {
            if flags & flag != 0 {
                cursor += 2;
                if cursor > appdata.len() {
                    return Err(KissError::malformed(
                        "advert truncated in a reserved feature field",
                    ));
                }
            }
        }

        let name = if flags & ADV_FLAG_HAS_NAME == 0 {
            None
        } else {
            let raw = appdata
                .get(cursor..)
                .ok_or_else(|| KissError::malformed("advert truncated before name"))?;
            let trimmed = trim_trailing_nuls(raw);
            if trimmed.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(trimmed).into_owned())
            }
        };

        Ok(Self {
            pubkey,
            timestamp: u32::from_le_bytes(timestamp),
            signature,
            flags,
            latitude_1e6,
            longitude_1e6,
            name,
            appdata: appdata.to_vec(),
        })
    }

    /// Build an unsigned advert ready for the device to sign.
    ///
    /// The appdata is composed here so that [`AdvertBody::signed_bytes`] is
    /// stable across the sign-then-send sequence. Fill [`AdvertBody::signature`]
    /// with the result of signing those bytes.
    #[must_use]
    pub fn unsigned(
        pubkey: [u8; 32],
        timestamp: u32,
        node_type: u8,
        location_1e6: Option<(i32, i32)>,
        name: Option<&str>,
    ) -> Self {
        let mut flags = node_type & 0x0F;
        if location_1e6.is_some() {
            flags |= ADV_FLAG_HAS_LOCATION;
        }
        if name.is_some() {
            flags |= ADV_FLAG_HAS_NAME;
        }

        let mut appdata = vec![flags];
        if let Some((latitude, longitude)) = location_1e6 {
            appdata.extend_from_slice(&latitude.to_le_bytes());
            appdata.extend_from_slice(&longitude.to_le_bytes());
        }
        if let Some(name) = name {
            appdata.extend_from_slice(name.as_bytes());
        }

        Self {
            pubkey,
            timestamp,
            signature: [0u8; 64],
            flags,
            latitude_1e6: location_1e6.map(|(latitude, _)| latitude),
            longitude_1e6: location_1e6.map(|(_, longitude)| longitude),
            name: name.map(str::to_owned),
            appdata,
        }
    }

    /// Serialise the advert as a packet payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ADVERT_PREFIX_LEN + 16);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.appdata);
        out
    }

    /// The bytes the signature covers: public key, timestamp and appdata.
    ///
    /// The signature itself sits between the timestamp and the appdata on the
    /// wire and is excluded here.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(36 + 16);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.appdata);
        out
    }
}

/// The encrypted envelope shared by request, response, text and path payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBody {
    /// First byte of the destination node's public key.
    pub dest_hash: u8,
    /// First byte of the source node's public key.
    pub src_hash: u8,
    /// Truncated MAC over the ciphertext.
    pub mac: [u8; 2],
    /// The encrypted body.
    pub ciphertext: Vec<u8>,
}

impl EncryptedBody {
    /// Parse an encrypted payload.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Malformed`] when the payload is shorter than the
    /// two hashes and the MAC.
    pub fn parse(payload: &[u8]) -> Result<Self, KissError> {
        let head: [u8; 4] = payload
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| KissError::malformed("encrypted payload truncated before ciphertext"))?;
        let ciphertext = payload
            .get(4..)
            .ok_or_else(|| KissError::malformed("encrypted payload has no ciphertext"))?
            .to_vec();
        Ok(Self {
            dest_hash: head[0],
            src_hash: head[1],
            mac: [head[2], head[3]],
            ciphertext,
        })
    }

    /// Serialise the envelope as a packet payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.ciphertext.len());
        out.push(self.dest_hash);
        out.push(self.src_hash);
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.ciphertext);
        out
    }
}

/// The plaintext inside a text-message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtMsgPlain {
    /// Unix timestamp the message was sent at.
    pub timestamp: u32,
    /// Message kind: plain text, CLI command, or signed plain text.
    pub txt_type: u8,
    /// Retransmission attempt as carried in the type byte, `0` to `3`.
    pub attempt: u8,
    /// The message text.
    pub text: String,
    /// The full attempt number, recovered from the byte past the terminator.
    ///
    /// The type byte has room for only two bits of attempt counter, so the
    /// firmware hides attempts above three at the tail of the payload. It is
    /// zero for attempts zero to three, where no tail byte is written.
    pub extended_attempt: u8,
}

impl TxtMsgPlain {
    /// Parse a decrypted text-message plaintext.
    ///
    /// The text ends at the first NUL, matching the firmware's `strlen` in
    /// `BaseChatMesh.cpp:242`. Stopping at the last non-zero byte instead
    /// would swallow the terminator and the extended attempt byte into the
    /// text for attempts above three, and would then produce the wrong
    /// acknowledgement hash.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Malformed`] when the plaintext is shorter than the
    /// timestamp and type byte, or when the text is not valid UTF-8.
    pub fn parse(plaintext: &[u8]) -> Result<Self, KissError> {
        let timestamp: [u8; 4] = plaintext
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| KissError::malformed("text message truncated in timestamp"))?;
        let packed = *plaintext
            .get(4)
            .ok_or_else(|| KissError::malformed("text message has no type byte"))?;
        let tail = plaintext
            .get(5..)
            .ok_or_else(|| KissError::malformed("text message truncated before text"))?;

        let text_len = tail
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(tail.len());
        let text = std::str::from_utf8(&tail[..text_len])
            .map_err(|err| KissError::malformed(format!("text message is not utf-8: {err}")))?;
        let extended_attempt = tail.get(text_len + 1).copied().unwrap_or(0);

        Ok(Self {
            timestamp: u32::from_le_bytes(timestamp),
            txt_type: packed >> 2,
            attempt: packed & 0x03,
            text: text.to_owned(),
            extended_attempt,
        })
    }

    /// The bytes the acknowledgement hash is taken over, before the public key.
    ///
    /// This is `timestamp`, the type byte, and the text, and stops there: the
    /// firmware hashes `5 + text_len` bytes and so excludes the terminator and
    /// any extended attempt byte (`BaseChatMesh.cpp:243`, `:431`).
    #[must_use]
    pub fn ack_input_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.text.len());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.push((self.txt_type << 2) | (self.attempt & 0x03));
        out.extend_from_slice(self.text.as_bytes());
        out
    }

    /// Serialise the plaintext for encryption.
    ///
    /// An attempt above three is appended after a NUL terminator, matching
    /// `composeMsgPacket` at `BaseChatMesh.cpp:433-437`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.ack_input_bytes();
        if self.extended_attempt > 3 {
            out.push(0);
            out.push(self.extended_attempt);
        }
        out
    }
}

fn trim_trailing_nuls(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

impl Packet {
    /// Assemble a packet from its parts, computing `path_length` from the path.
    ///
    /// `path_hash_size` must be 1, 2 or 3; anything else is clamped into range.
    /// The path is truncated to a whole number of hashes and to
    /// [`MAX_PATH_SIZE`].
    #[must_use]
    pub fn build(
        route: RouteType,
        payload_type: PayloadType,
        path_hash_size: u8,
        path: &[u8],
        payload: Vec<u8>,
    ) -> Self {
        let hash_size = path_hash_size.clamp(1, 3);
        let usable = path.len().min(MAX_PATH_SIZE);
        let hop_count = (usable / usize::from(hash_size)).min(0x3F);
        let path_bytes = hop_count * usize::from(hash_size);
        let header = ((payload_type as u8) << 2) | (route as u8);
        let transport_codes = if route.has_transport_codes() {
            Some([0, 0])
        } else {
            None
        };

        Self {
            header,
            transport_codes,
            path_length: ((hash_size - 1) << 6) | u8::try_from(hop_count).unwrap_or(0),
            path: path[..path_bytes].to_vec(),
            payload,
        }
    }
}

/// A returned-path payload, carried inside the encrypted envelope.
///
/// The sender learns the route back to us from `path`, and `extra` optionally
/// bundles another payload so an acknowledgement rides along instead of
/// costing a second transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBody {
    /// Path hashes, one hop per entry group.
    pub path: Vec<u8>,
    /// Payload type of the bundled extra, when present.
    pub extra_type: Option<u8>,
    /// The bundled extra payload.
    pub extra: Vec<u8>,
}

impl PathBody {
    /// Parse a returned-path plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Malformed`] when the declared path length runs past
    /// the end of the plaintext.
    pub fn parse(plaintext: &[u8]) -> Result<Self, KissError> {
        let path_len = usize::from(
            *plaintext
                .first()
                .ok_or_else(|| KissError::malformed("path payload has no length byte"))?,
        );
        let path = plaintext
            .get(1..1 + path_len)
            .ok_or_else(|| KissError::malformed("path payload truncated in path"))?
            .to_vec();

        let rest = &plaintext[1 + path_len..];
        let (extra_type, extra) = match rest.split_first() {
            Some((kind, tail)) => (Some(*kind), trim_trailing_nuls(tail).to_vec()),
            None => (None, Vec::new()),
        };

        Ok(Self {
            path,
            extra_type,
            extra,
        })
    }

    /// Serialise a returned-path plaintext.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.path.len() + self.extra.len());
        out.push(u8::try_from(self.path.len()).unwrap_or(0));
        out.extend_from_slice(&self.path);
        if let Some(kind) = self.extra_type {
            out.push(kind);
            out.extend_from_slice(&self.extra);
        }
        out
    }
}
