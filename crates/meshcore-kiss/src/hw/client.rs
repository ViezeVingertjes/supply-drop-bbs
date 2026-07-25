//! A serialising SetHardware client over a byte stream.
//!
//! SetHardware carries no request identifier. A response is recognised only by
//! its code, so two in-flight requests of the same kind would be
//! indistinguishable. [`HwLink`] therefore allows exactly one outstanding
//! request: [`HwLink::request`] takes `&mut self`, writes the frame, and reads
//! until the expected code or an error code arrives.
//!
//! Traffic that is not a reply travels a separate path. Received packets,
//! signal reports and transmit completions are queued as [`Unsolicited`] and
//! drained with [`HwLink::next_unsolicited`], so they can never satisfy a
//! pending request.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tracing::debug;

use crate::error::{HwError, KissError};
use crate::hw::frame::{
    HwRequest, HwResponse, CMD_DATA, CMD_SET_HARDWARE, RESP_ERROR, RESP_RX_META, RESP_TX_DONE,
};
use crate::kiss::{encode, Decoder};

/// How many unsolicited events are retained before the oldest is dropped.
const UNSOLICITED_LIMIT: usize = 256;

/// Size of the read buffer used for each stream read.
const READ_BUFFER: usize = 1024;

/// How many extra attempts a request gets when the device does not answer.
///
/// The modem occasionally leaves a request unanswered under serial load, most
/// often the slower signing and key-exchange operations. Re-sending the same
/// request is safe: a late reply to the first attempt answers the second
/// identically, because the input has not changed.
const REQUEST_ATTEMPTS: usize = 3;

/// Traffic from the modem that is not a reply to a request.
#[derive(Debug, Clone, PartialEq)]
pub enum Unsolicited {
    /// A raw LoRa packet the radio received.
    Packet {
        /// The packet exactly as it came off the air.
        bytes: Vec<u8>,
    },
    /// The signal report for the packet that preceded it.
    RxMeta {
        /// Signal-to-noise ratio in dB.
        snr_db: f32,
        /// Received signal strength in dBm.
        rssi_dbm: i8,
    },
    /// A transmission finished.
    TxDone {
        /// Whether the radio reported success.
        success: bool,
    },
    /// The modem reported an error outside any request, such as a rejected
    /// transmission.
    Error(HwError),
}

/// A SetHardware client bound to one byte stream.
#[derive(Debug)]
pub struct HwLink<S> {
    stream: S,
    decoder: Decoder,
    unsolicited: VecDeque<Unsolicited>,
    request_timeout: Duration,
}

impl<S> HwLink<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Wrap a stream, giving each request `request_timeout` to be answered.
    pub fn new(stream: S, request_timeout: Duration) -> Self {
        Self {
            stream,
            decoder: Decoder::new(),
            unsolicited: VecDeque::new(),
            request_timeout,
        }
    }

    /// Send a request and wait for its response.
    ///
    /// Unsolicited traffic seen while waiting is queued rather than returned.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Timeout`] when no matching response arrives within
    /// the configured window, or [`KissError::Io`] when the stream fails. A
    /// device-side refusal is delivered as `Ok(HwResponse::Error(_))`, since
    /// the request completed.
    pub async fn request(&mut self, request: HwRequest) -> Result<HwResponse, KissError> {
        let expected = request.expected_response();
        let sub = request.sub();
        let encoded = request.encode();

        self.classify_ready(None);

        for attempt in 1..=REQUEST_ATTEMPTS {
            self.write_frame(CMD_SET_HARDWARE, &encoded).await?;
            match timeout(self.request_timeout, self.read_until(expected)).await {
                Ok(result) => return result,
                Err(_) => {
                    debug!(
                        sub,
                        attempt, "kiss: no response in time, resending the request"
                    );
                    self.classify_ready(None);
                }
            }
        }

        Err(KissError::Timeout { sub })
    }

    /// Queue a raw LoRa packet for transmission.
    ///
    /// Completion arrives later as [`Unsolicited::TxDone`], and a refusal as
    /// [`Unsolicited::Error`] carrying [`HwError::TxBusy`].
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Io`] when the stream fails.
    pub async fn send_data(&mut self, packet: &[u8]) -> Result<(), KissError> {
        self.write_frame(CMD_DATA, packet).await
    }

    /// Send a KISS frame that expects no response, such as a CSMA setting.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Io`] when the stream fails.
    pub async fn send_kiss(&mut self, type_byte: u8, body: &[u8]) -> Result<(), KissError> {
        self.write_frame(type_byte, body).await
    }

    /// Read whatever the modem has sent, up to `window`, queueing every event.
    ///
    /// Used to collect transmit completions and received packets between
    /// requests. Returns once the window elapses, not once the stream is idle.
    ///
    /// # Errors
    ///
    /// Returns [`KissError::Io`] when the stream fails.
    pub async fn pump(&mut self, window: Duration) -> Result<(), KissError> {
        match timeout(window, self.read_forever()).await {
            Ok(result) => result,
            Err(_) => Ok(()),
        }
    }

    /// Take the next queued unsolicited event.
    ///
    /// Frames that were decoded while a request was being satisfied but not
    /// yet classified are folded into the queue first, so nothing already read
    /// from the stream is withheld until the next read.
    pub fn next_unsolicited(&mut self) -> Option<Unsolicited> {
        if self.decoder.has_frames() {
            self.classify_ready(None);
        }
        self.unsolicited.pop_front()
    }

    /// How many unsolicited events are waiting.
    #[must_use]
    pub fn pending_unsolicited(&self) -> usize {
        self.unsolicited.len()
    }

    /// The stream this link owns, for callers that need to reconnect.
    pub fn into_inner(self) -> S {
        self.stream
    }

    async fn write_frame(&mut self, type_byte: u8, body: &[u8]) -> Result<(), KissError> {
        let bytes = encode(type_byte, body);
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_until(&mut self, expected: u8) -> Result<HwResponse, KissError> {
        loop {
            if let Some(response) = self.take_matching(expected) {
                return Ok(response);
            }
            self.read_once().await?;
        }
    }

    async fn read_forever(&mut self) -> Result<(), KissError> {
        loop {
            self.classify_ready(None);
            self.read_once().await?;
        }
    }

    async fn read_once(&mut self) -> Result<(), KissError> {
        let mut buffer = [0u8; READ_BUFFER];
        let read = self.stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(KissError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "kiss stream closed",
            )));
        }
        self.decoder.push(&buffer[..read]);
        Ok(())
    }

    fn take_matching(&mut self, expected: u8) -> Option<HwResponse> {
        self.classify_ready(Some(expected))
    }

    fn classify_ready(&mut self, expected: Option<u8>) -> Option<HwResponse> {
        while let Some(frame) = self.decoder.next_frame() {
            if frame.type_byte == CMD_DATA {
                self.queue(Unsolicited::Packet { bytes: frame.data });
                continue;
            }
            if frame.type_byte != CMD_SET_HARDWARE {
                debug!(
                    type_byte = frame.type_byte,
                    "kiss: ignoring frame with an unexpected type byte"
                );
                continue;
            }

            let code = match frame.data.first() {
                Some(code) => *code,
                None => continue,
            };
            let response = match HwResponse::decode(&frame.data) {
                Ok(response) => response,
                Err(error) => {
                    debug!(%error, code, "kiss: dropping undecodable response");
                    continue;
                }
            };

            match code {
                RESP_TX_DONE | RESP_RX_META => {
                    self.queue(unsolicited_from(response));
                    continue;
                }
                RESP_ERROR
                    if expected.is_none()
                        || matches!(response, HwResponse::Error(HwError::TxBusy)) =>
                {
                    self.queue(unsolicited_from(response));
                    continue;
                }
                _ => {}
            }

            match expected {
                Some(expected) if code == expected || code == RESP_ERROR => {
                    return Some(response);
                }
                _ => {
                    debug!(code, "kiss: dropping response with no pending request");
                }
            }
        }
        None
    }

    fn queue(&mut self, event: Unsolicited) {
        if self.unsolicited.len() >= UNSOLICITED_LIMIT {
            self.unsolicited.pop_front();
        }
        self.unsolicited.push_back(event);
    }
}

fn unsolicited_from(response: HwResponse) -> Unsolicited {
    match response {
        HwResponse::TxDone { success } => Unsolicited::TxDone { success },
        HwResponse::RxMeta { snr_db, rssi_dbm } => Unsolicited::RxMeta { snr_db, rssi_dbm },
        HwResponse::Error(error) => Unsolicited::Error(error),
        other => {
            debug!(
                ?other,
                "kiss: unexpected response classified as unsolicited"
            );
            Unsolicited::Error(HwError::Other(0))
        }
    }
}
