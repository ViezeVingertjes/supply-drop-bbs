//! SetHardware (0x06) request and response codec.
//!
//! Every SetHardware frame opens with a one-byte sub-command. Responses are
//! identified by `request | 0x80`, with generic and unsolicited codes in the
//! `0xF0`+ range. All multi-byte values are little-endian.
//!
//! # Body length rule
//!
//! [`HwResponse::decode`] rejects a body shorter than the fixed layout its
//! response code declares, and accepts whatever remains for the variable tails
//! ([`RESP_RANDOM`], [`RESP_DECRYPTED`], [`RESP_DEVICE_NAME`], and the
//! ciphertext following the MAC in [`RESP_ENCRYPTED`]) — including nothing at
//! all. A response code this crate does not model is returned as
//! [`HwResponse::Unknown`] rather than an error, so firmware newer than this
//! crate stays decodable.
//!
//! # Example
//!
//! ```
//! use meshcore_kiss::hw::frame::{HwRequest, HwResponse};
//!
//! assert_eq!(HwRequest::Ping.encode(), vec![0x17]);
//! assert_eq!(
//!     HwResponse::decode(&[0x97]).expect("a pong"),
//!     HwResponse::Pong
//! );
//! ```

use crate::error::{HwError, KissError};

/// KISS command number for a data frame carrying a raw LoRa packet.
pub const CMD_DATA: u8 = 0x00;
/// KISS command number for the MeshCore SetHardware extension.
pub const CMD_SET_HARDWARE: u8 = 0x06;

/// The bit the modem sets on a sub-command to form its response code.
const RESPONSE_BIT: u8 = 0x80;

/// SetHardware sub-command numbers, host to modem.
pub const SUB_GET_IDENTITY: u8 = 0x01;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_RANDOM: u8 = 0x02;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_VERIFY_SIGNATURE: u8 = 0x03;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_SIGN_DATA: u8 = 0x04;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_ENCRYPT_DATA: u8 = 0x05;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_DECRYPT_DATA: u8 = 0x06;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_KEY_EXCHANGE: u8 = 0x07;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_HASH: u8 = 0x08;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_SET_RADIO: u8 = 0x09;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_SET_TX_POWER: u8 = 0x0A;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_RADIO: u8 = 0x0B;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_TX_POWER: u8 = 0x0C;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_AIRTIME: u8 = 0x0F;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_VERSION: u8 = 0x11;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_STATS: u8 = 0x12;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_BATTERY: u8 = 0x13;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_GET_DEVICE_NAME: u8 = 0x16;
/// See [`SUB_GET_IDENTITY`].
pub const SUB_PING: u8 = 0x17;

/// Response to [`SUB_GET_IDENTITY`].
pub const RESP_IDENTITY: u8 = SUB_GET_IDENTITY | RESPONSE_BIT;
/// Response to [`SUB_GET_RANDOM`].
pub const RESP_RANDOM: u8 = SUB_GET_RANDOM | RESPONSE_BIT;
/// Response to [`SUB_VERIFY_SIGNATURE`].
pub const RESP_VERIFY: u8 = SUB_VERIFY_SIGNATURE | RESPONSE_BIT;
/// Response to [`SUB_SIGN_DATA`].
pub const RESP_SIGNATURE: u8 = SUB_SIGN_DATA | RESPONSE_BIT;
/// Response to [`SUB_ENCRYPT_DATA`].
pub const RESP_ENCRYPTED: u8 = SUB_ENCRYPT_DATA | RESPONSE_BIT;
/// Response to [`SUB_DECRYPT_DATA`].
pub const RESP_DECRYPTED: u8 = SUB_DECRYPT_DATA | RESPONSE_BIT;
/// Response to [`SUB_KEY_EXCHANGE`].
pub const RESP_SHARED_SECRET: u8 = SUB_KEY_EXCHANGE | RESPONSE_BIT;
/// Response to [`SUB_HASH`].
pub const RESP_HASH: u8 = SUB_HASH | RESPONSE_BIT;
/// Response to [`SUB_GET_RADIO`].
pub const RESP_RADIO: u8 = SUB_GET_RADIO | RESPONSE_BIT;
/// Response to [`SUB_GET_TX_POWER`].
pub const RESP_TX_POWER: u8 = SUB_GET_TX_POWER | RESPONSE_BIT;
/// Response to [`SUB_GET_AIRTIME`].
pub const RESP_AIRTIME: u8 = SUB_GET_AIRTIME | RESPONSE_BIT;
/// Response to [`SUB_GET_VERSION`].
pub const RESP_VERSION: u8 = SUB_GET_VERSION | RESPONSE_BIT;
/// Response to [`SUB_GET_STATS`].
pub const RESP_STATS: u8 = SUB_GET_STATS | RESPONSE_BIT;
/// Response to [`SUB_GET_BATTERY`].
pub const RESP_BATTERY: u8 = SUB_GET_BATTERY | RESPONSE_BIT;
/// Response to [`SUB_GET_DEVICE_NAME`].
pub const RESP_DEVICE_NAME: u8 = SUB_GET_DEVICE_NAME | RESPONSE_BIT;
/// Response to [`SUB_PING`].
pub const RESP_PONG: u8 = SUB_PING | RESPONSE_BIT;

/// Generic acknowledgement response code.
pub const RESP_OK: u8 = 0xF0;
/// Error response code; the body carries one [`HwError`] byte.
pub const RESP_ERROR: u8 = 0xF1;
/// Unsolicited transmit-complete notification.
pub const RESP_TX_DONE: u8 = 0xF8;
/// Unsolicited signal report accompanying a received data frame.
pub const RESP_RX_META: u8 = 0xF9;

/// Divisor applied to the [`RESP_RX_META`] SNR byte, which counts quarter-dB
/// steps.
const SNR_QUARTER_DB: f32 = 4.0;

/// LoRa radio parameters as carried by `SetRadio` and the `Radio` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadioParams {
    /// Carrier frequency in Hz.
    pub frequency_hz: u32,
    /// Channel bandwidth in Hz.
    pub bandwidth_hz: u32,
    /// LoRa spreading factor.
    pub spreading_factor: u8,
    /// LoRa coding rate denominator.
    pub coding_rate: u8,
}

/// Packet counters reported by `GetStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStats {
    /// Packets received.
    pub rx: u32,
    /// Packets transmitted.
    pub tx: u32,
    /// Receive errors.
    pub errors: u32,
}

/// A SetHardware request sent to the modem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwRequest {
    /// Liveness check.
    Ping,
    /// Fetch the modem's public key.
    GetIdentity,
    /// Fetch random bytes; `len` must be 1 to 64.
    GetRandom {
        /// Number of bytes requested.
        len: u8,
    },
    /// Verify an Ed25519 signature over `data`.
    VerifySignature {
        /// Signer's public key.
        pubkey: [u8; 32],
        /// Signature to check.
        signature: [u8; 64],
        /// Signed message.
        data: Vec<u8>,
    },
    /// Sign `data` with the modem's identity.
    SignData {
        /// Message to sign.
        data: Vec<u8>,
    },
    /// Encrypt `plaintext` under `key`.
    EncryptData {
        /// Shared secret.
        key: [u8; 32],
        /// Message to encrypt.
        plaintext: Vec<u8>,
    },
    /// Decrypt `ciphertext` under `key`, checking `mac`.
    DecryptData {
        /// Shared secret.
        key: [u8; 32],
        /// Two-byte truncated MAC.
        mac: [u8; 2],
        /// Ciphertext to decrypt.
        ciphertext: Vec<u8>,
    },
    /// Derive the shared secret with `peer_pubkey`.
    KeyExchange {
        /// Remote node's public key.
        peer_pubkey: [u8; 32],
    },
    /// SHA-256 over `data`.
    Hash {
        /// Message to hash.
        data: Vec<u8>,
    },
    /// Apply radio parameters.
    SetRadio(RadioParams),
    /// Set transmit power in dBm.
    SetTxPower {
        /// Power in dBm.
        dbm: u8,
    },
    /// Read the current radio parameters.
    GetRadio,
    /// Read the current transmit power.
    GetTxPower,
    /// Estimate airtime in milliseconds for a packet of `packet_len` bytes.
    GetAirtime {
        /// Packet length in bytes.
        packet_len: u8,
    },
    /// Read the firmware protocol version.
    GetVersion,
    /// Read packet counters.
    GetStats,
    /// Read battery voltage.
    GetBattery,
    /// Read the board's name.
    GetDeviceName,
}

impl HwRequest {
    /// The SetHardware sub-command byte for this request.
    #[must_use]
    pub fn sub(&self) -> u8 {
        match self {
            Self::Ping => SUB_PING,
            Self::GetIdentity => SUB_GET_IDENTITY,
            Self::GetRandom { .. } => SUB_GET_RANDOM,
            Self::VerifySignature { .. } => SUB_VERIFY_SIGNATURE,
            Self::SignData { .. } => SUB_SIGN_DATA,
            Self::EncryptData { .. } => SUB_ENCRYPT_DATA,
            Self::DecryptData { .. } => SUB_DECRYPT_DATA,
            Self::KeyExchange { .. } => SUB_KEY_EXCHANGE,
            Self::Hash { .. } => SUB_HASH,
            Self::SetRadio(_) => SUB_SET_RADIO,
            Self::SetTxPower { .. } => SUB_SET_TX_POWER,
            Self::GetRadio => SUB_GET_RADIO,
            Self::GetTxPower => SUB_GET_TX_POWER,
            Self::GetAirtime { .. } => SUB_GET_AIRTIME,
            Self::GetVersion => SUB_GET_VERSION,
            Self::GetStats => SUB_GET_STATS,
            Self::GetBattery => SUB_GET_BATTERY,
            Self::GetDeviceName => SUB_GET_DEVICE_NAME,
        }
    }

    /// The response code this request expects.
    ///
    /// Every query is answered with its own sub-command plus the response bit;
    /// the two setters are answered with the generic [`RESP_OK`]. Any request
    /// may instead be answered with [`RESP_ERROR`].
    #[must_use]
    pub fn expected_response(&self) -> u8 {
        match self {
            Self::SetRadio(_) | Self::SetTxPower { .. } => RESP_OK,
            other => other.sub() | RESPONSE_BIT,
        }
    }

    /// Serialise the request, sub-command byte first.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.sub()];
        match self {
            Self::Ping
            | Self::GetIdentity
            | Self::GetRadio
            | Self::GetTxPower
            | Self::GetVersion
            | Self::GetStats
            | Self::GetBattery
            | Self::GetDeviceName => {}
            Self::GetRandom { len } => out.push(*len),
            Self::VerifySignature {
                pubkey,
                signature,
                data,
            } => {
                out.extend_from_slice(pubkey);
                out.extend_from_slice(signature);
                out.extend_from_slice(data);
            }
            Self::SignData { data } | Self::Hash { data } => out.extend_from_slice(data),
            Self::EncryptData { key, plaintext } => {
                out.extend_from_slice(key);
                out.extend_from_slice(plaintext);
            }
            Self::DecryptData {
                key,
                mac,
                ciphertext,
            } => {
                out.extend_from_slice(key);
                out.extend_from_slice(mac);
                out.extend_from_slice(ciphertext);
            }
            Self::KeyExchange { peer_pubkey } => out.extend_from_slice(peer_pubkey),
            Self::SetRadio(params) => {
                out.extend_from_slice(&params.frequency_hz.to_le_bytes());
                out.extend_from_slice(&params.bandwidth_hz.to_le_bytes());
                out.push(params.spreading_factor);
                out.push(params.coding_rate);
            }
            Self::SetTxPower { dbm } => out.push(*dbm),
            Self::GetAirtime { packet_len } => out.push(*packet_len),
        }
        out
    }
}

/// A SetHardware response, or an unsolicited event, received from the modem.
#[derive(Debug, Clone, PartialEq)]
pub enum HwResponse {
    /// Generic acknowledgement, sent for the radio setters and `Reboot`.
    Ok,
    /// The request was rejected.
    Error(HwError),
    /// The modem's public key.
    Identity {
        /// Ed25519 public key.
        pubkey: [u8; 32],
    },
    /// Random bytes from the modem's generator.
    Random {
        /// The bytes requested.
        bytes: Vec<u8>,
    },
    /// The verdict on a signature.
    Verify {
        /// Whether the signature checked out.
        valid: bool,
    },
    /// A signature over the submitted message.
    Signature {
        /// Ed25519 signature.
        signature: [u8; 64],
    },
    /// Ciphertext and its truncated MAC.
    Encrypted {
        /// HMAC-SHA256 truncated to two bytes.
        mac: [u8; 2],
        /// AES-128 ciphertext with zero padding.
        ciphertext: Vec<u8>,
    },
    /// Recovered plaintext.
    Decrypted {
        /// The decrypted message.
        plaintext: Vec<u8>,
    },
    /// The X25519 shared secret with a peer.
    SharedSecret {
        /// The derived secret.
        secret: [u8; 32],
    },
    /// A SHA-256 digest.
    Hash {
        /// The digest.
        digest: [u8; 32],
    },
    /// The modem's current radio parameters.
    Radio(RadioParams),
    /// The modem's current transmit power.
    TxPower {
        /// Power in dBm.
        dbm: u8,
    },
    /// An airtime estimate.
    Airtime {
        /// Estimated airtime in milliseconds.
        millis: u32,
    },
    /// The firmware protocol version.
    Version {
        /// Version number; the trailing reserved byte is discarded.
        version: u8,
    },
    /// The modem's packet counters.
    Stats(DeviceStats),
    /// The battery reading.
    Battery {
        /// Battery voltage in millivolts.
        millivolts: u16,
    },
    /// The board's name.
    DeviceName {
        /// UTF-8 board name.
        name: String,
    },
    /// The answer to a [`HwRequest::Ping`].
    Pong,
    /// Unsolicited: a transmission finished.
    TxDone {
        /// Whether the packet made it onto the air.
        success: bool,
    },
    /// Unsolicited: the signal report for the data frame just delivered.
    RxMeta {
        /// Signal-to-noise ratio in dB, to a quarter of a dB.
        snr_db: f32,
        /// Received signal strength in dBm.
        rssi_dbm: i8,
    },
    /// A response code this crate does not model, kept verbatim.
    Unknown {
        /// The response code.
        code: u8,
        /// Everything after the response code.
        body: Vec<u8>,
    },
}

impl HwResponse {
    /// Parse a SetHardware frame body, response code first.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Malformed`] when `data` is empty, when the body is
    /// shorter than its response code's fixed layout, or when a device name is
    /// not valid UTF-8.
    pub fn decode(data: &[u8]) -> Result<Self, KissError> {
        let (&code, body) = data
            .split_first()
            .ok_or_else(|| KissError::malformed("empty SetHardware response"))?;
        let response = match code {
            RESP_OK => Self::Ok,
            RESP_ERROR => Self::Error(HwError::from(fixed::<1>(body, "Error")?[0])),
            RESP_IDENTITY => Self::Identity {
                pubkey: fixed::<32>(body, "Identity")?,
            },
            RESP_RANDOM => Self::Random {
                bytes: body.to_vec(),
            },
            RESP_VERIFY => Self::Verify {
                valid: fixed::<1>(body, "Verify")?[0] != 0,
            },
            RESP_SIGNATURE => Self::Signature {
                signature: fixed::<64>(body, "Signature")?,
            },
            RESP_ENCRYPTED => {
                let mac = fixed::<2>(body, "Encrypted")?;
                Self::Encrypted {
                    mac,
                    ciphertext: body[mac.len()..].to_vec(),
                }
            }
            RESP_DECRYPTED => Self::Decrypted {
                plaintext: body.to_vec(),
            },
            RESP_SHARED_SECRET => Self::SharedSecret {
                secret: fixed::<32>(body, "SharedSecret")?,
            },
            RESP_HASH => Self::Hash {
                digest: fixed::<32>(body, "Hash")?,
            },
            RESP_RADIO => {
                let raw = fixed::<10>(body, "Radio")?;
                Self::Radio(RadioParams {
                    frequency_hz: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                    bandwidth_hz: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
                    spreading_factor: raw[8],
                    coding_rate: raw[9],
                })
            }
            RESP_TX_POWER => Self::TxPower {
                dbm: fixed::<1>(body, "TxPower")?[0],
            },
            RESP_AIRTIME => Self::Airtime {
                millis: u32::from_le_bytes(fixed::<4>(body, "Airtime")?),
            },
            RESP_VERSION => Self::Version {
                version: fixed::<2>(body, "Version")?[0],
            },
            RESP_STATS => {
                let raw = fixed::<12>(body, "Stats")?;
                Self::Stats(DeviceStats {
                    rx: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
                    tx: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
                    errors: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
                })
            }
            RESP_BATTERY => Self::Battery {
                millivolts: u16::from_le_bytes(fixed::<2>(body, "Battery")?),
            },
            RESP_DEVICE_NAME => Self::DeviceName {
                name: std::str::from_utf8(body)
                    .map_err(|err| KissError::malformed(format!("DeviceName is not UTF-8: {err}")))?
                    .to_owned(),
            },
            RESP_PONG => Self::Pong,
            RESP_TX_DONE => Self::TxDone {
                success: fixed::<1>(body, "TxDone")?[0] != 0,
            },
            RESP_RX_META => {
                let raw = fixed::<2>(body, "RxMeta")?;
                Self::RxMeta {
                    snr_db: f32::from(raw[0] as i8) / SNR_QUARTER_DB,
                    rssi_dbm: raw[1] as i8,
                }
            }
            other => Self::Unknown {
                code: other,
                body: body.to_vec(),
            },
        };
        Ok(response)
    }
}

fn fixed<const N: usize>(body: &[u8], response: &str) -> Result<[u8; N], KissError> {
    body.get(..N)
        .and_then(|head| <[u8; N]>::try_from(head).ok())
        .ok_or_else(|| {
            KissError::malformed(format!(
                "{response} response needs {N} bytes, got {}",
                body.len()
            ))
        })
}
