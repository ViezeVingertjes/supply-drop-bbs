//! Error types for the KISS link and the MeshCore node stack.

use std::io;

/// A failure in the KISS link or the MeshCore node stack.
#[derive(Debug, thiserror::Error)]
pub enum KissError {
    /// The serial port could not be opened, read, or written.
    #[error("kiss io: {0}")]
    Io(#[from] io::Error),

    /// A frame arrived that does not match the expected structure.
    #[error("malformed frame: {0}")]
    Malformed(String),

    /// The device answered a SetHardware request with an error code.
    #[error("device error: {0}")]
    Device(#[from] HwError),

    /// A SetHardware request received no matching response in time.
    #[error("timed out awaiting response to sub-command {sub:#04x}")]
    Timeout {
        /// The SetHardware sub-command that went unanswered.
        sub: u8,
    },

    /// The background worker has exited.
    #[error("kiss worker has exited")]
    WorkerGone,
}

impl KissError {
    /// Build a [`KissError::Malformed`] from anything printable.
    pub fn malformed(reason: impl Into<String>) -> Self {
        Self::Malformed(reason.into())
    }
}

/// An error code returned by the modem in a SetHardware `Error` (0xF1) frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HwError {
    /// Request data was shorter than the sub-command requires.
    #[error("invalid length")]
    InvalidLength,
    /// A parameter was out of range.
    #[error("invalid parameter")]
    InvalidParam,
    /// The board does not implement this feature.
    #[error("feature not available")]
    NoCallback,
    /// MAC verification failed.
    ///
    /// For `DecryptData` this is not an error so much as an answer: the
    /// payload was not encrypted for this node under the key supplied.
    #[error("mac verification failed")]
    MacFailed,
    /// The sub-command is not recognised by this firmware.
    #[error("unknown sub-command")]
    UnknownCmd,
    /// Encryption failed.
    #[error("encryption failed")]
    EncryptFailed,
    /// The radio is transmitting, or the modem's outbound queue is full.
    #[error("transmitter busy")]
    TxBusy,
    /// An error code this crate does not model.
    #[error("unrecognised device error code {0:#04x}")]
    Other(u8),
}

impl From<u8> for HwError {
    fn from(code: u8) -> Self {
        match code {
            0x01 => Self::InvalidLength,
            0x02 => Self::InvalidParam,
            0x03 => Self::NoCallback,
            0x04 => Self::MacFailed,
            0x05 => Self::UnknownCmd,
            0x06 => Self::EncryptFailed,
            0x07 => Self::TxBusy,
            other => Self::Other(other),
        }
    }
}
