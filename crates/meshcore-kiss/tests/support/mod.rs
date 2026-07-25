#![allow(missing_docs)]
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use meshcore_kiss::hw::frame::{CMD_DATA, CMD_SET_HARDWARE};
use meshcore_kiss::kiss::{encode, Decoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

pub const RECORDED_IDENTITY: [u8; 32] = [
    0x37, 0x9a, 0xfe, 0xe0, 0xa2, 0xaa, 0x74, 0x8c, 0x29, 0xc7, 0xe6, 0x2b, 0x85, 0xe4, 0x86, 0x59,
    0xa8, 0xea, 0x8d, 0xf2, 0xd6, 0xa0, 0x1a, 0x6b, 0xc9, 0x48, 0x21, 0xf5, 0x11, 0xf1, 0x50, 0x02,
];

pub const RECORDED_SECRET: [u8; 32] = [
    0xf4, 0xd3, 0x34, 0x57, 0x82, 0x27, 0x1b, 0xd9, 0x0f, 0xa1, 0x8b, 0x5f, 0x1b, 0xf8, 0x67, 0xeb,
    0x3c, 0x2e, 0x77, 0x01, 0x91, 0xf0, 0x61, 0x7a, 0x32, 0x6b, 0xa8, 0xfd, 0xaa, 0x05, 0x34, 0x77,
];

pub const RECORDED_RADIO: [u8; 10] = [0x50, 0x51, 0xD5, 0x33, 0x24, 0xF4, 0x00, 0x00, 0x07, 0x05];

const SUB_GET_IDENTITY: u8 = 0x01;
const SUB_GET_RANDOM: u8 = 0x02;
const SUB_VERIFY_SIGNATURE: u8 = 0x03;
const SUB_SIGN_DATA: u8 = 0x04;
const SUB_ENCRYPT_DATA: u8 = 0x05;
const SUB_DECRYPT_DATA: u8 = 0x06;
const SUB_KEY_EXCHANGE: u8 = 0x07;
const SUB_HASH: u8 = 0x08;
const SUB_SET_RADIO: u8 = 0x09;
const SUB_SET_TX_POWER: u8 = 0x0A;
const SUB_GET_RADIO: u8 = 0x0B;
const SUB_GET_TX_POWER: u8 = 0x0C;
const SUB_GET_AIRTIME: u8 = 0x0F;
const SUB_GET_VERSION: u8 = 0x11;
const SUB_GET_STATS: u8 = 0x12;
const SUB_GET_BATTERY: u8 = 0x13;
const SUB_GET_DEVICE_NAME: u8 = 0x16;
const SUB_PING: u8 = 0x17;

const XOR_MASK: u8 = 0x5A;

#[derive(Debug, Clone)]
pub struct Behaviour {
    pub signature_valid: bool,
    pub decrypt_fails: bool,
    pub tx_busy_once: bool,
    pub auto_tx_done: bool,
    pub silent_subs: Vec<u8>,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            signature_valid: true,
            decrypt_fails: false,
            tx_busy_once: false,
            auto_tx_done: true,
            silent_subs: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Recorded {
    pub transmitted: Vec<Vec<u8>>,
    pub requests: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct FakeModem {
    behaviour: Arc<Mutex<Behaviour>>,
    recorded: Arc<Mutex<Recorded>>,
    inject: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl FakeModem {
    pub fn set_signature_valid(&self, valid: bool) {
        self.behaviour
            .lock()
            .expect("behaviour mutex")
            .signature_valid = valid;
    }

    pub fn set_decrypt_fails(&self, fails: bool) {
        self.behaviour
            .lock()
            .expect("behaviour mutex")
            .decrypt_fails = fails;
    }

    pub fn set_tx_busy_once(&self, busy: bool) {
        self.behaviour.lock().expect("behaviour mutex").tx_busy_once = busy;
    }

    pub fn set_auto_tx_done(&self, auto: bool) {
        self.behaviour.lock().expect("behaviour mutex").auto_tx_done = auto;
    }

    pub fn silence_sub(&self, sub: u8) {
        self.behaviour
            .lock()
            .expect("behaviour mutex")
            .silent_subs
            .push(sub);
    }

    pub fn transmitted(&self) -> Vec<Vec<u8>> {
        self.recorded
            .lock()
            .expect("recorded mutex")
            .transmitted
            .clone()
    }

    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.recorded
            .lock()
            .expect("recorded mutex")
            .requests
            .clone()
    }

    pub fn deliver(&self, packet: &[u8], snr_quarter_db: i8, rssi_dbm: i8) {
        self.inject
            .send(encode(CMD_DATA, packet))
            .expect("modem task alive");
        self.inject
            .send(encode(
                CMD_SET_HARDWARE,
                &[0xF9, snr_quarter_db as u8, rssi_dbm as u8],
            ))
            .expect("modem task alive");
    }

    pub fn send_tx_done(&self, success: bool) {
        self.inject
            .send(encode(CMD_SET_HARDWARE, &[0xF8, u8::from(success)]))
            .expect("modem task alive");
    }
}

pub fn fake_modem() -> (DuplexStream, FakeModem) {
    let (host_side, modem_side) = tokio::io::duplex(8192);
    let behaviour = Arc::new(Mutex::new(Behaviour::default()));
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let (inject, mut inject_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let handle = FakeModem {
        behaviour: Arc::clone(&behaviour),
        recorded: Arc::clone(&recorded),
        inject,
    };

    tokio::spawn(async move {
        let mut modem_side = modem_side;
        let mut decoder = Decoder::new();
        let mut buf = [0u8; 1024];
        loop {
            tokio::select! {
                injected = inject_rx.recv() => {
                    match injected {
                        Some(bytes) => {
                            if modem_side.write_all(&bytes).await.is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
                }
                read = modem_side.read(&mut buf) => {
                    let read = match read {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    decoder.push(&buf[..read]);
                    while let Some(frame) = decoder.next_frame() {
                        let replies = handle_frame(&behaviour, &recorded, &frame.type_byte, &frame.data);
                        for reply in replies {
                            if modem_side.write_all(&reply).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    });

    (host_side, handle)
}

fn handle_frame(
    behaviour: &Arc<Mutex<Behaviour>>,
    recorded: &Arc<Mutex<Recorded>>,
    type_byte: &u8,
    data: &[u8],
) -> Vec<Vec<u8>> {
    if *type_byte == CMD_DATA {
        let mut state = behaviour.lock().expect("behaviour mutex");
        if state.tx_busy_once {
            state.tx_busy_once = false;
            return vec![encode(CMD_SET_HARDWARE, &[0xF1, 0x07])];
        }
        let auto_tx_done = state.auto_tx_done;
        drop(state);
        recorded
            .lock()
            .expect("recorded mutex")
            .transmitted
            .push(data.to_vec());
        if auto_tx_done {
            return vec![encode(CMD_SET_HARDWARE, &[0xF8, 0x01])];
        }
        return Vec::new();
    }

    if *type_byte != CMD_SET_HARDWARE || data.is_empty() {
        return Vec::new();
    }

    recorded
        .lock()
        .expect("recorded mutex")
        .requests
        .push(data.to_vec());

    let state = behaviour.lock().expect("behaviour mutex").clone();
    if state.silent_subs.contains(&data[0]) {
        return Vec::new();
    }

    vec![encode(CMD_SET_HARDWARE, &respond(&state, data))]
}

fn respond(state: &Behaviour, data: &[u8]) -> Vec<u8> {
    let sub = data[0];
    let body = &data[1..];
    match sub {
        SUB_PING => vec![0x97],
        SUB_GET_IDENTITY => reply(0x81, &RECORDED_IDENTITY),
        SUB_GET_RANDOM => {
            let len = usize::from(body.first().copied().unwrap_or(1));
            reply(0x82, &vec![0x5A; len])
        }
        SUB_VERIFY_SIGNATURE => vec![0x83, u8::from(state.signature_valid)],
        SUB_SIGN_DATA => reply(0x84, &[0x11; 64]),
        SUB_ENCRYPT_DATA if body.len() > 32 => {
            let plaintext = &body[32..];
            let mut out = vec![0x85, 0x5B, 0x6A];
            out.extend(padded_xor(plaintext));
            out
        }
        SUB_DECRYPT_DATA => {
            if state.decrypt_fails || body.len() < 34 {
                return vec![0xF1, 0x04];
            }
            let ciphertext = &body[34..];
            reply(0x86, &xor(ciphertext))
        }
        SUB_KEY_EXCHANGE => reply(0x87, &RECORDED_SECRET),
        SUB_HASH => reply(0x88, &pseudo_digest(body)),
        SUB_GET_RADIO => reply(0x8B, &RECORDED_RADIO),
        SUB_GET_TX_POWER => vec![0x8C, 0x16],
        SUB_GET_AIRTIME => reply(0x8F, &300u32.to_le_bytes()),
        SUB_GET_VERSION => vec![0x91, 0x01, 0x00],
        SUB_GET_STATS => reply(0x92, &[0u8; 12]),
        SUB_GET_BATTERY => reply(0x93, &4100u16.to_le_bytes()),
        SUB_GET_DEVICE_NAME => reply(0x96, b"Fake Modem"),
        SUB_SET_RADIO | SUB_SET_TX_POWER => vec![0xF0],
        _ => vec![0xF1, 0x05],
    }
}

fn reply(code: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![code];
    out.extend_from_slice(body);
    out
}

fn xor(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ XOR_MASK).collect()
}

fn padded_xor(bytes: &[u8]) -> Vec<u8> {
    let mut padded = bytes.to_vec();
    while !padded.len().is_multiple_of(16) {
        padded.push(0x00);
    }
    xor(&padded)
}

fn pseudo_digest(input: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut accumulator: u32 = 0x811C_9DC5;
    for (index, byte) in input.iter().enumerate() {
        accumulator ^= u32::from(*byte).wrapping_add(index as u32);
        accumulator = accumulator.wrapping_mul(0x0100_0193);
        digest[index % 32] ^= (accumulator >> 8) as u8;
    }
    digest[0] ^= input.len() as u8;
    digest
}
