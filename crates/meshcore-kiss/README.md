# meshcore-kiss

A MeshCore node stack that speaks the **KISS Modem** serial protocol.

MeshCore's KISS Modem firmware turns a LoRa board into a raw-PHY TNC. It
transmits and receives whole packets and handles CSMA, but it does no routing,
no contact management and no packet construction. This crate supplies those, so
Supply Drop BBS can drive a KISS Modem device over USB with no `pymc_core`
process in between.

It is the KISS counterpart to [`meshcore-companion`](../meshcore-companion),
which speaks the companion-frame protocol. Both produce the same `ClientEvent`
stream and accept the same `OutboundFrame` commands, so `bbs-mesh` consumes
either backend through one code path.

## The crate implements no cryptography

Identity, signing, verification, key exchange, encryption, decryption, hashing
and randomness are all sub-commands on the modem, reached through the firmware's
SetHardware (0x06) extension. The device is the reference implementation, so
there is nothing here to reimplement byte-identically and nothing to drift out
of step with the firmware.

That has a cost. The identity lives in the device's flash and the KISS firmware
exposes no way to export it, so a KISS-mode node's mesh identity cannot be
backed up or moved to a replacement board. Replacing the board means the BBS
appears on the mesh as a new node.

Measured round-trip cost on an ESP32-S3 at 115 200 baud — the per-packet path is
sub-millisecond, which is negligible beside LoRa airtime:

| Operation | Median | Frequency |
|---|---|---|
| `Hash` | 0.31 ms | per message |
| `EncryptData` | 0.54 ms | per outbound message |
| `DecryptData` | 0.47 ms | per inbound packet |
| `SignData` | 6.65 ms | per self-advert |
| `KeyExchange` | 14.58 ms | once per contact, then cached |
| `VerifySignature` | 85.43 ms | per inbound advert |

## Modules

| Module | Responsibility |
|---|---|
| `kiss` | KISS framing — escape, unescape, incremental frame decoding |
| `hw` | SetHardware requests and responses, and the correlator that pairs them |
| `packet` | MeshCore v1 packet header, path encoding, and payload bodies |
| `node` | Contacts, shared-secret cache, paths, dedup, ACK matching, queues |
| `client` | `KissClient` handle, serial worker, reconnect |

`kiss` and `packet` are pure and I/O-free, so they test without hardware. `hw`
and `node` run against a fake modem over an in-memory duplex stream. Only
`client` opens a real port.

## Scope

Deliberately a leaf chat node, matching what `bbs-mesh` consumes from a
companion device: self-adverts, advert parsing, contacts, direct messages,
acknowledgements and path learning.

Not implemented: channels and group text, flood forwarding, transport codes and
region scoping, multipart packets, trace, and room-server login semantics.
Commands for those are answered with an explicit error rather than silence.

## Tests

```
cargo test -p meshcore-kiss
```

Tests that need real hardware are behind a feature flag and read the port from
an environment variable, so they never run by accident. They must run one at a
time, because only one process can hold the serial port:

```
SDBBS_KISS_PORT=/dev/ttyACM0 \
  cargo test -p meshcore-kiss --features hardware-tests -- --test-threads=1
```

## Configuration

Operators do not configure this crate directly. It is selected with
`connection_type = "kiss"` under `[plugins.mesh]`; see `docs/CONFIG.md` for the
full key reference and `docs/adr/0014-native-meshcore-stack-for-kiss-modems.md`
for why the stack lives on the host.
