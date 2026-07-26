# ADR-0014: Native MeshCore node stack for KISS Modem devices

- **Status:** Accepted
- **Date:** 2026-07-25
- **Deciders:** Mesh-America

## Context

[ADR-0007](0007-bridge-stays-pymc-core.md) deferred writing a Rust MeshCore
radio bridge, and [ADR-0013](0013-native-serial-transport-for-usb-devices.md)
added a USB serial mode on the grounds that it changed only the byte-stream
source and no protocol logic.

Both assume the device runs **companion** firmware, which owns MeshCore routing,
contacts, paths and cryptography and exposes them over the companion-frame
protocol. MeshCore also ships **KISS Modem** firmware, which is a different
thing: a raw-PHY TNC using standard KISS framing (`0xC0` FEND, `0xDB` FESC). It
transmits and receives whole LoRa packets and performs CSMA, but it does no
routing, keeps no contacts, and does not decide what to encrypt. A device
running it cannot talk to the BBS at all.

The only way to use one today is to put `pymc_core` in front of it
(`radio_type: "kiss"` → `KissModemWrapper`), which reintroduces the second
process ADR-0013 exists to eliminate.

The KISS firmware does expose MeshCore's cryptographic primitives to the host
through its SetHardware (0x06) extension: identity, signing, verification, key
exchange, encryption, decryption, hashing and randomness.

## Decision

Add a fourth `connection_type = "kiss"` to the mesh transport, in which the BBS
host implements the MeshCore node stack itself and drives the modem directly
over USB serial.

The split of responsibility is:

| Concern | Owner |
|---|---|
| Packet framing, routing, paths, contacts, dedup, acknowledgements | Host (`meshcore-kiss`) |
| Every cryptographic operation | Device (SetHardware) |
| Radio, CSMA, carrier sense, transmission | Device |

**No cryptography is implemented on the host.** No `ed25519-dalek`,
`x25519-dalek`, `aes`, `hmac`, `sha2` or `rand` dependency is added. The device
is MeshCore's own implementation, so there is nothing to reimplement
byte-identically and nothing to drift.

The one construction assembled host-side is HMAC-SHA256, needed for flood-scope
transport codes, which the firmware does not expose as a sub-command. It is
composed from two device hashes — `H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))` — so only
padding and exclusive-or happen on the host. It is checked against a known
vector in a hardware test.

The stack lives in a new `meshcore-kiss` crate, which carries no `bbs-` prefix
because it is not a plugin: it depends only on `meshcore-companion` for the
shared frame vocabulary and could be used by any application. `bbs-mesh` gains a
`RadioLink` enum selecting the backend, and the transport's event loop is
unchanged.

## Relationship to the earlier ADRs

**ADR-0007** deferred a Rust MeshCore protocol implementation. This does that
for a bounded subset. The justification is that KISS firmware leaves no
in-process alternative, that the subset is bounded to what `bbs-mesh` already
consumes from a companion device, and that the companion and HAT paths are
untouched.

**ADR-0013** argued its serial mode was safe *precisely because* it added a
byte-stream source and no protocol logic. That reasoning does not extend here.
This ADR **supersedes the ADR-0013 rationale for the KISS case**, while leaving
ADR-0013's companion-serial decision in force.

## Scope

Parity with what `bbs-mesh` consumes from a companion device: self-adverts,
advert parsing and verification, contacts, direct messages, acknowledgements,
path learning, and flood scopes.

Explicit non-goals: channels and group text (the transport discards
`ChannelMsgRecv` today), flood forwarding (companion firmware also defaults to
`client_repeat = 0`, so omitting it is parity), multipart packets, trace, and
room-server login semantics. Commands for those are answered with an explicit
error rather than silence, so the transport never waits on a reply that will
not come.

## Consequences

### Positive

- A KISS Modem device works with no Python and no second process.
- Crypto correctness is the firmware's, not ours.
- The companion-frame vocabulary becomes the internal backend seam, so
  `transport.rs` is backend-agnostic and both paths share session handling,
  command parsing, retry and metrics.
- Host-side packet construction makes flood scopes and path-hash width
  configurable without firmware support.

### Negative

- **The identity is not portable.** It lives in the device's flash and the KISS
  firmware exposes no private-key export, so a KISS-mode node's mesh identity
  cannot be backed up or moved to a replacement board. `node export-key` and
  `node import-key` refuse explicitly rather than operate on something else.
  Adding export would be a firmware change, not a host workaround.
- The host now owns protocol logic that the firmware owns for other modes, so a
  MeshCore protocol change can require a matching change here.
- Each cryptographic step is a serial round trip. Measured on an ESP32-S3, the
  per-packet path is sub-millisecond (`Hash` 0.31 ms, `EncryptData` 0.54 ms,
  `DecryptData` 0.47 ms) against LoRa airtime of hundreds of milliseconds.
  `KeyExchange` at 14.6 ms is cached per contact and `VerifySignature` at
  85.4 ms runs only for inbound adverts.

- **The contact table is a JSON file, not a database table.** Companion
  firmware keeps contacts in the radio's flash; a KISS modem does not, so
  without somewhere to put them the BBS forgets every node's route on restart.
  [ADR-0012](0012-persistence-layer.md) puts persistence in SQLite behind
  `bbs-core`, but `meshcore-kiss` carries no `bbs-` dependency by design and so
  cannot reach it. The table is written to `<data_dir>/meshcore-contacts.json`,
  atomically and coalesced to at most one write per thirty seconds. It is
  cache, not record: losing it costs a re-advert per node, not correctness, and
  cached shared secrets are deliberately never written. If a future backend
  needs durable per-contact state that actually matters, that is the point to
  revisit the split rather than grow this file.

### Neutral

- Companion and HAT operators see no change.
- `Plugin::name()` stays `"meshcore"`. This is a backend of the existing
  transport, not a new one, so it needs no identity-mapping table of its own
  under [ADR-0011](0011-transport-protocol-agnostic-core.md) Rule 2.

## Implementation notes

- Gated by the existing `transport-mesh` Cargo feature, which already covers
  both `bbs-mesh` and `meshcore-companion`.
- SetHardware carries no request identifier, so responses are matched by code
  with one request in flight at a time. The device intermittently leaves a
  request unanswered under serial load, most often the slower signing and key
  exchange; requests are retried up to three times, which is safe because
  re-sending the same request makes a late reply to the first attempt a correct
  answer to the second.
- Radio parameters are validated before they reach the device. A frequency
  outside the SX126x tuning range is refused, because writing one leaves the
  node deaf and silent until corrected by hand. The bounds live in
  `meshcore_kiss::radio` and `bbs-mesh` defers to them, so a companion node and
  a KISS node cannot come to disagree about what a usable frequency is.
- **`path_length` is a packed byte, not a byte count.** It holds the hop count
  in bits 0-5 and the hash width minus one in bits 6-7, in the packet header
  and in a returned-path payload alike. The two readings coincide on a mesh
  using one-byte hashes, which is the firmware default, and diverge on the two-
  and three-byte hashes this BBS configures — so the mistake is invisible until
  it is in the field. Everything that touches one goes through
  `packet::path_byte_len`, and `Contact::out_path_len` stores the packed byte,
  which is what both the firmware and `meshcore-companion` mean by that field.
- **A route is learned in one place: a returned-path payload.** The path
  accumulated on an inbound flooded packet runs sender-to-us — repeaters append
  at the tail, direct routing consumes from the head — so it is the sender's
  route to us, not ours to them. It is handed back to them unchanged and
  nothing is learned from it, matching the firmware, which assigns `out_path`
  only in `onContactPathRecv`. The BBS learns its own route from the reciprocal
  return the far node sends after receiving ours. Both halves are needed:
  without the reciprocal, neither side ever learns a route and every reply
  floods for the life of the link.
- Hardware tests sit behind a `hardware-tests` Cargo feature and read the port
  from `SDBBS_KISS_PORT`. They must run with `--test-threads=1`, since only one
  process can hold the serial port.
