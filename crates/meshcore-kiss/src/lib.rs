//! MeshCore node stack driven over the KISS Modem serial protocol.
//!
//! The MeshCore KISS Modem firmware is a raw-PHY TNC: it transmits and
//! receives whole LoRa packets and performs CSMA, but does no routing, no
//! contact management and no packet construction. This crate supplies those,
//! and delegates every cryptographic operation back to the device over the
//! firmware's SetHardware (0x06) extension.
//!
//! **No cryptography is implemented here.** Identity, signing, verification,
//! key exchange, encryption, decryption, hashing and randomness are all
//! sub-commands on the modem. The device is the reference implementation, so
//! there is nothing to reimplement byte-identically and nothing to drift.
//!
//! The public surface deliberately mirrors [`meshcore_companion`], so
//! `bbs-mesh` consumes either backend through the same event and command
//! types.
//!
//! # Layering
//!
//! ```text
//! client   KissClient — serial worker, reconnect, OutboundFrame handling
//! node     contacts, paths, dedup, ACK matching, message queues
//! packet   MeshCore v1 packet and payload bodies
//! hw       SetHardware requests, responses, and the response correlator
//! kiss     KISS framing
//! ```

pub mod client;
pub mod error;
pub mod hw;
pub mod kiss;
pub mod node;
pub mod packet;
pub mod radio;

pub use error::{HwError, KissError};
