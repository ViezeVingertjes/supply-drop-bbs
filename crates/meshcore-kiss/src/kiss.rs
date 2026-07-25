//! KISS framing per the KA9Q/K3MC specification.
//!
//! Every frame on the wire is `FEND, type_byte, escaped_data..., FEND`. The
//! type byte packs a port number in bits 4-7 and a command in bits 0-3.
//!
//! # Example
//!
//! ```
//! use meshcore_kiss::kiss::{encode, Decoder, FEND};
//!
//! let bytes = encode(0x06, &[0x17]);
//! assert_eq!(bytes, vec![FEND, 0x06, 0x17, FEND]);
//!
//! let mut decoder = Decoder::new();
//! decoder.push(&bytes);
//! let frame = decoder.next_frame().expect("one complete frame");
//! assert_eq!(frame.type_byte, 0x06);
//! assert_eq!(frame.data, vec![0x17]);
//! ```

use std::collections::VecDeque;

/// Frame delimiter.
pub const FEND: u8 = 0xC0;
/// Escape character.
pub const FESC: u8 = 0xDB;
/// Escaped [`FEND`], following [`FESC`].
pub const TFEND: u8 = 0xDC;
/// Escaped [`FESC`], following [`FESC`].
pub const TFESC: u8 = 0xDD;

/// Maximum unescaped frame size the modem accepts, including the type byte.
pub const MAX_KISS_FRAME: usize = 512;

/// How many decoded frames the decoder will hold before the caller drains it.
const READY_QUEUE_LIMIT: usize = 64;

/// A decoded KISS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissFrame {
    /// The raw type byte: port in the high nibble, command in the low nibble.
    pub type_byte: u8,
    /// The unescaped frame body, excluding the type byte.
    pub data: Vec<u8>,
}

impl KissFrame {
    /// The port number from the type byte's high nibble.
    #[must_use]
    pub fn port(&self) -> u8 {
        self.type_byte >> 4
    }

    /// The command number from the type byte's low nibble.
    #[must_use]
    pub fn command(&self) -> u8 {
        self.type_byte & 0x0F
    }
}

/// Encode a type byte and body into a complete KISS frame.
#[must_use]
pub fn encode(type_byte: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(FEND);
    push_escaped(&mut out, type_byte);
    for &byte in data {
        push_escaped(&mut out, byte);
    }
    out.push(FEND);
    out
}

fn push_escaped(out: &mut Vec<u8>, byte: u8) {
    match byte {
        FEND => out.extend_from_slice(&[FESC, TFEND]),
        FESC => out.extend_from_slice(&[FESC, TFESC]),
        other => out.push(other),
    }
}

/// Incremental KISS frame decoder.
///
/// Feed arbitrary byte chunks with [`Decoder::push`] and drain complete frames
/// with [`Decoder::next_frame`]. A frame whose unescaped length would exceed
/// [`MAX_KISS_FRAME`] is discarded rather than buffered, so a corrupt stream
/// cannot grow the decoder without bound or stall the link.
#[derive(Debug, Default)]
pub struct Decoder {
    current: Vec<u8>,
    in_frame: bool,
    escaped: bool,
    overflowed: bool,
    ready: VecDeque<KissFrame>,
}

impl Decoder {
    /// Create an empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed received bytes into the decoder.
    pub fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.push_byte(byte);
        }
    }

    fn push_byte(&mut self, byte: u8) {
        if byte == FEND {
            self.finish_frame();
            self.in_frame = true;
            self.escaped = false;
            self.overflowed = false;
            self.current.clear();
            return;
        }
        if !self.in_frame {
            return;
        }
        let decoded = if self.escaped {
            self.escaped = false;
            match byte {
                TFEND => FEND,
                TFESC => FESC,
                other => other,
            }
        } else if byte == FESC {
            self.escaped = true;
            return;
        } else {
            byte
        };
        if self.current.len() >= MAX_KISS_FRAME {
            self.overflowed = true;
            self.current.clear();
            return;
        }
        self.current.push(decoded);
    }

    fn finish_frame(&mut self) {
        let complete = self.in_frame && !self.overflowed && !self.current.is_empty();
        if !complete {
            self.current.clear();
            return;
        }
        let type_byte = self.current[0];
        let data = self.current[1..].to_vec();
        self.current.clear();
        if self.ready.len() >= READY_QUEUE_LIMIT {
            self.ready.pop_front();
        }
        self.ready.push_back(KissFrame { type_byte, data });
    }

    /// Take the next complete frame, if one is available.
    pub fn next_frame(&mut self) -> Option<KissFrame> {
        self.ready.pop_front()
    }

    /// Whether any decoded frames are waiting to be drained.
    #[must_use]
    pub fn has_frames(&self) -> bool {
        !self.ready.is_empty()
    }
}
