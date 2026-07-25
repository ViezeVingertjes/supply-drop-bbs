#![allow(missing_docs)]

mod support;

use std::time::Duration;

use meshcore_companion::frame::InboundFrame;
use meshcore_kiss::hw::client::HwLink;
use meshcore_kiss::node::scope::FloodScope;
use meshcore_kiss::node::state::{NodeConfig, NodeOutput, NodeState};
use meshcore_kiss::packet::{
    AdvertBody, EncryptedBody, Packet, PathBody, PayloadType, RouteType, TxtMsgPlain,
};
use support::{fake_modem, FakeModem, RECORDED_IDENTITY};
use tokio::io::DuplexStream;

const TIMEOUT: Duration = Duration::from_secs(2);
const XOR_MASK: u8 = 0x5A;

const PEER: [u8; 32] = [0x5C; 32];

fn node() -> (HwLink<DuplexStream>, FakeModem, NodeState) {
    let (stream, modem) = fake_modem();
    let link = HwLink::new(stream, TIMEOUT);
    let config = NodeConfig {
        node_name: "Supply Drop".into(),
        latitude_1e6: 0,
        longitude_1e6: 0,
        path_hash_size: 3,
        flood_scope: None,
    };
    (link, modem, NodeState::new(RECORDED_IDENTITY, config))
}

fn fake_encrypt(plaintext: &[u8]) -> Vec<u8> {
    let mut padded = plaintext.to_vec();
    while !padded.len().is_multiple_of(16) {
        padded.push(0);
    }
    padded.iter().map(|byte| byte ^ XOR_MASK).collect()
}

fn advert_packet(pubkey: [u8; 32], timestamp: u32, name: &str, path: &[u8]) -> Vec<u8> {
    let advert = AdvertBody::unsigned(pubkey, timestamp, 0x01, None, Some(name));
    Packet::build(
        RouteType::Flood,
        PayloadType::Advert,
        3,
        path,
        advert.encode(),
    )
    .encode()
}

fn encrypted_packet(
    payload_type: PayloadType,
    route: RouteType,
    src: [u8; 32],
    dest: [u8; 32],
    plaintext: &[u8],
    path: &[u8],
) -> Vec<u8> {
    let body = EncryptedBody {
        dest_hash: dest[0],
        src_hash: src[0],
        mac: [0x5B, 0x6A],
        ciphertext: fake_encrypt(plaintext),
    };
    Packet::build(route, payload_type, 3, path, body.encode()).encode()
}

fn text_packet(route: RouteType, path: &[u8], text: &str, timestamp: u32) -> Vec<u8> {
    let plain = TxtMsgPlain {
        timestamp,
        txt_type: 0,
        attempt: 0,
        text: text.into(),
        extended_attempt: 0,
    };
    encrypted_packet(
        PayloadType::TxtMsg,
        route,
        PEER,
        RECORDED_IDENTITY,
        &plain.encode(),
        path,
    )
}

async fn register_peer(link: &mut HwLink<DuplexStream>, node: &mut NodeState) {
    let raw = advert_packet(PEER, 1_700_000_000, "Peer", &[]);
    node.handle_inbound_packet(link, &raw, None)
        .await
        .expect("advert accepted");
    assert!(node.contacts().by_pubkey(&PEER).is_some());
}

#[tokio::test]
async fn self_advert_is_a_signed_flooded_room_advert() {
    let (mut link, _modem, mut node) = node();

    let raw = node
        .build_self_advert(&mut link, true, 1_700_000_000)
        .await
        .expect("builds the advert");

    let packet = Packet::decode(&raw).expect("decodes");
    assert_eq!(packet.payload_type(), PayloadType::Advert);
    assert_eq!(packet.route_type(), RouteType::Flood);
    assert_eq!(packet.path_hash_count(), 0);

    let advert = AdvertBody::parse(&packet.payload).expect("parses");
    assert_eq!(advert.pubkey, RECORDED_IDENTITY);
    assert_eq!(advert.timestamp, 1_700_000_000);
    assert_eq!(advert.flags & 0x0F, 0x03);
    assert_eq!(advert.flags & 0x80, 0x80);
    assert_eq!(advert.name.as_deref(), Some("Supply Drop"));
    assert_eq!(advert.signature, [0x11; 64]);
}

#[tokio::test]
async fn inbound_advert_is_verified_and_becomes_a_contact() {
    let (mut link, _modem, mut node) = node();

    let output = node
        .handle_inbound_packet(
            &mut link,
            &advert_packet(PEER, 1_700_000_000, "Peer", &[]),
            None,
        )
        .await
        .expect("handles the packet");

    assert!(output
        .frames
        .iter()
        .any(|frame| matches!(frame, InboundFrame::NewAdvert(contact) if contact.pubkey == PEER)));
    let contact = node.contacts().by_pubkey(&PEER).expect("stored");
    assert_eq!(contact.name, "Peer");
    assert_eq!(contact.adv_type, 0x01);
}

#[tokio::test]
async fn advert_with_a_bad_signature_is_dropped() {
    let (mut link, modem, mut node) = node();
    modem.set_signature_valid(false);

    let output = node
        .handle_inbound_packet(&mut link, &advert_packet(PEER, 1, "Peer", &[]), None)
        .await
        .expect("handles the packet");

    assert_eq!(output, NodeOutput::default());
    assert!(node.contacts().by_pubkey(&PEER).is_none());
}

#[tokio::test]
async fn our_own_advert_echoed_back_is_ignored() {
    let (mut link, _modem, mut node) = node();

    let output = node
        .handle_inbound_packet(
            &mut link,
            &advert_packet(RECORDED_IDENTITY, 1, "self", &[]),
            None,
        )
        .await
        .expect("handles the packet");

    assert_eq!(output, NodeOutput::default());
    assert!(node.contacts().by_pubkey(&RECORDED_IDENTITY).is_none());
}

#[tokio::test]
async fn a_flooded_advert_stores_the_accumulated_path_verbatim() {
    let (mut link, _modem, mut node) = node();
    let path = [0x0A, 0x0B, 0x0C, 0x1A, 0x1B, 0x1C];

    let output = node
        .handle_inbound_packet(&mut link, &advert_packet(PEER, 1, "Peer", &path), None)
        .await
        .expect("handles the packet");

    assert!(output
        .frames
        .iter()
        .any(|frame| matches!(frame, InboundFrame::PathUpdated { pubkey } if *pubkey == PEER)));
    let contact = node.contacts().by_pubkey(&PEER).expect("stored");
    assert_eq!(contact.out_path_len, 6);
    assert_eq!(&contact.out_path[..6], &path);
}

#[tokio::test]
async fn a_duplicate_packet_is_handled_once() {
    let (mut link, _modem, mut node) = node();
    let raw = advert_packet(PEER, 1_700_000_000, "Peer", &[]);

    let first = node
        .handle_inbound_packet(&mut link, &raw, None)
        .await
        .expect("first");
    let second = node
        .handle_inbound_packet(&mut link, &raw, None)
        .await
        .expect("second");

    assert!(!first.frames.is_empty());
    assert_eq!(second, NodeOutput::default());
}

#[tokio::test]
async fn a_direct_message_is_queued_and_acknowledged() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let raw = text_packet(RouteType::Direct, &[], "hello bbs", 1_700_000_100);
    let output = node
        .handle_inbound_packet(&mut link, &raw, Some(5.5))
        .await
        .expect("handles the packet");

    assert!(output
        .frames
        .iter()
        .any(|frame| matches!(frame, InboundFrame::MsgWaiting)));
    assert_eq!(node.queued_messages(), 1);
    assert_eq!(output.transmit.len(), 1);

    let ack = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(ack.payload_type(), PayloadType::Ack);
    assert_eq!(ack.payload.len(), 6);

    match node.sync_next_message() {
        InboundFrame::ContactMsgRecv(message) => {
            assert_eq!(message.text, "hello bbs");
            assert_eq!(message.timestamp, 1_700_000_100);
            assert_eq!(&message.sender_key_prefix, &PEER[..6]);
            assert_eq!(message.snr, Some(5.5));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(matches!(
        node.sync_next_message(),
        InboundFrame::NoMoreMessages
    ));
}

#[tokio::test]
async fn a_flooded_message_is_answered_with_a_path_return_carrying_the_ack() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let raw = text_packet(RouteType::Flood, &[0x01, 0x02, 0x03], "hi", 42);
    let output = node
        .handle_inbound_packet(&mut link, &raw, None)
        .await
        .expect("handles the packet");

    assert_eq!(output.transmit.len(), 1);
    let reply = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(reply.payload_type(), PayloadType::Path);

    let body = EncryptedBody::parse(&reply.payload).expect("parses");
    let plaintext = fake_encrypt(&body.ciphertext);
    let path_body = PathBody::parse(&plaintext).expect("parses");
    assert_eq!(path_body.path, vec![0x01, 0x02, 0x03]);
    assert_eq!(path_body.extra_type, Some(PayloadType::Ack as u8));
    assert_eq!(path_body.extra.len(), 6);
}

#[tokio::test]
async fn a_message_we_cannot_decrypt_is_dropped() {
    let (mut link, modem, mut node) = node();
    register_peer(&mut link, &mut node).await;
    modem.set_decrypt_fails(true);

    let raw = text_packet(RouteType::Direct, &[], "not for us", 1);
    let output = node
        .handle_inbound_packet(&mut link, &raw, None)
        .await
        .expect("handles the packet");

    assert_eq!(output, NodeOutput::default());
    assert_eq!(node.queued_messages(), 0);
}

#[tokio::test]
async fn a_message_addressed_to_another_node_is_ignored() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let plain = TxtMsgPlain {
        timestamp: 1,
        txt_type: 0,
        attempt: 0,
        text: "elsewhere".into(),
        extended_attempt: 0,
    };
    let raw = encrypted_packet(
        PayloadType::TxtMsg,
        RouteType::Direct,
        PEER,
        [0xEE; 32],
        &plain.encode(),
        &[],
    );

    let output = node
        .handle_inbound_packet(&mut link, &raw, None)
        .await
        .expect("handles the packet");
    assert_eq!(output, NodeOutput::default());
}

#[tokio::test]
async fn sending_to_an_unknown_contact_reports_an_untracked_send() {
    let (mut link, _modem, mut node) = node();

    let output = node
        .send_text(&mut link, [0xAA; 6], 0, 0, 1, "nobody home".into())
        .await
        .expect("send completes");

    assert!(output.transmit.is_empty());
    match output.frames.as_slice() {
        [InboundFrame::Sent(result)] => assert_eq!(result.expected_ack, 0),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn sending_without_a_known_path_floods() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    let output = node
        .send_text(&mut link, prefix, 0, 0, 1_700_000_200, "reply".into())
        .await
        .expect("send completes");

    assert_eq!(output.transmit.len(), 1);
    let packet = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(packet.payload_type(), PayloadType::TxtMsg);
    assert_eq!(packet.route_type(), RouteType::Flood);

    match output.frames.as_slice() {
        [InboundFrame::Sent(result)] => {
            assert!(result.is_flood);
            assert_ne!(result.expected_ack, 0);
            assert!(result.timeout_ms >= 4_000);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn sending_with_a_known_path_uses_direct_routing() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;
    assert!(node.contacts_mut().set_path(&PEER, &[0x07, 0x08, 0x09]));

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    let output = node
        .send_text(&mut link, prefix, 0, 0, 1, "direct".into())
        .await
        .expect("send completes");

    let packet = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(packet.route_type(), RouteType::Direct);
    assert_eq!(packet.path, vec![0x07, 0x08, 0x09]);
    assert_eq!(packet.path_hash_count(), 1);
}

#[tokio::test]
async fn a_matching_acknowledgement_confirms_the_send() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    let sent = node
        .send_text(&mut link, prefix, 0, 0, 1, "confirm me".into())
        .await
        .expect("send completes");
    let expected_ack = match sent.frames.as_slice() {
        [InboundFrame::Sent(result)] => result.expected_ack,
        other => panic!("unexpected {other:?}"),
    };

    let ack = Packet::build(
        RouteType::Direct,
        PayloadType::Ack,
        3,
        &[],
        expected_ack.to_le_bytes().to_vec(),
    )
    .encode();
    let output = node
        .handle_inbound_packet(&mut link, &ack, None)
        .await
        .expect("handles the packet");

    match output.frames.as_slice() {
        [InboundFrame::SendConfirmed { crc }] => assert_eq!(*crc, expected_ack),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn an_acknowledgement_for_nothing_pending_is_ignored() {
    let (mut link, _modem, mut node) = node();

    let ack = Packet::build(
        RouteType::Direct,
        PayloadType::Ack,
        3,
        &[],
        0xDEAD_BEEFu32.to_le_bytes().to_vec(),
    )
    .encode();
    let output = node
        .handle_inbound_packet(&mut link, &ack, None)
        .await
        .expect("handles the packet");

    assert_eq!(output, NodeOutput::default());
}

#[tokio::test]
async fn reset_path_makes_the_next_send_flood_again() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;
    assert!(node.contacts_mut().set_path(&PEER, &[0x07, 0x08, 0x09]));
    assert!(node.reset_path(&PEER));

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    let output = node
        .send_text(&mut link, prefix, 0, 0, 1, "after reset".into())
        .await
        .expect("send completes");

    let packet = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(packet.route_type(), RouteType::Flood);
}

#[tokio::test]
async fn the_shared_secret_is_derived_once_per_contact() {
    let (mut link, modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    for round in 0..3u32 {
        node.send_text(&mut link, prefix, 0, 0, round, "spam".into())
            .await
            .expect("send completes");
    }

    let key_exchanges = modem
        .requests()
        .iter()
        .filter(|request| request.first() == Some(&0x07))
        .count();
    assert_eq!(key_exchanges, 1);
}

#[tokio::test]
async fn without_a_scope_outbound_packets_carry_no_transport_codes() {
    let (mut link, _modem, mut node) = node();

    let raw = node
        .build_self_advert(&mut link, true, 1)
        .await
        .expect("builds the advert");
    let packet = Packet::decode(&raw).expect("decodes");

    assert_eq!(packet.route_type(), RouteType::Flood);
    assert_eq!(packet.transport_codes, None);
    assert!(!node.has_scope());
}

#[tokio::test]
async fn a_scope_turns_flooded_packets_into_transport_flood() {
    let (mut link, _modem, mut node) = node();
    let scope = FloodScope::derive(&mut link, "nl")
        .await
        .expect("derives the key");
    node.set_scope(Some(scope));

    let raw = node
        .build_self_advert(&mut link, true, 1)
        .await
        .expect("builds the advert");
    let packet = Packet::decode(&raw).expect("decodes");

    assert_eq!(packet.route_type(), RouteType::TransportFlood);
    let codes = packet.transport_codes.expect("transport codes present");
    assert_ne!(codes[0], 0x0000);
    assert_ne!(codes[0], 0xFFFF);
    assert_eq!(codes[1], 0);
}

#[tokio::test]
async fn a_scope_turns_direct_packets_into_transport_direct() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;
    assert!(node.contacts_mut().set_path(&PEER, &[0x07, 0x08, 0x09]));
    let scope = FloodScope::derive(&mut link, "nl")
        .await
        .expect("derives the key");
    node.set_scope(Some(scope));

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    let output = node
        .send_text(&mut link, prefix, 0, 0, 1, "scoped".into())
        .await
        .expect("send completes");

    let packet = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(packet.route_type(), RouteType::TransportDirect);
    assert!(packet.transport_codes.is_some());
    assert_eq!(packet.path, vec![0x07, 0x08, 0x09]);
}

#[tokio::test]
async fn a_hashtag_prefix_is_added_only_when_missing() {
    let (mut link, _modem, _node) = node();

    let bare = FloodScope::derive(&mut link, "nl").await.expect("derives");
    let hashed = FloodScope::derive(&mut link, "#nl").await.expect("derives");
    let other = FloodScope::derive(&mut link, "be").await.expect("derives");

    assert_eq!(bare.key(), hashed.key());
    assert_ne!(bare.key(), other.key());
}

fn node_with_path_bytes(bytes: u8) -> (HwLink<DuplexStream>, FakeModem, NodeState) {
    let (stream, modem) = fake_modem();
    let link = HwLink::new(stream, TIMEOUT);
    let config = NodeConfig {
        node_name: "Supply Drop".into(),
        latitude_1e6: 0,
        longitude_1e6: 0,
        path_hash_size: bytes,
        flood_scope: None,
    };
    (link, modem, NodeState::new(RECORDED_IDENTITY, config))
}

#[tokio::test]
async fn path_hash_width_is_encoded_in_the_path_length_byte() {
    for (bytes, expected_code) in [(1u8, 0u8), (2, 1), (3, 2)] {
        let (mut link, _modem, mut node) = node_with_path_bytes(bytes);
        let raw = node
            .build_self_advert(&mut link, true, 1)
            .await
            .expect("builds the advert");
        let packet = Packet::decode(&raw).expect("decodes");

        assert_eq!(packet.path_hash_size(), bytes, "hash size for {bytes}");
        assert_eq!(
            packet.path_length >> 6,
            expected_code,
            "path_length high bits for {bytes}"
        );
    }
}

#[tokio::test]
async fn set_path_hash_size_changes_subsequent_packets() {
    let (mut link, _modem, mut node) = node_with_path_bytes(3);

    let before = Packet::decode(
        &node
            .build_self_advert(&mut link, true, 1)
            .await
            .expect("builds"),
    )
    .expect("decodes");
    assert_eq!(before.path_hash_size(), 3);

    node.set_path_hash_size(2);

    let after = Packet::decode(
        &node
            .build_self_advert(&mut link, true, 2)
            .await
            .expect("builds"),
    )
    .expect("decodes");
    assert_eq!(after.path_hash_size(), 2);
}

#[tokio::test]
async fn a_two_byte_path_is_split_into_two_byte_hops() {
    let (mut link, _modem, mut node) = node_with_path_bytes(2);
    register_peer(&mut link, &mut node).await;
    assert!(node
        .contacts_mut()
        .set_path(&PEER, &[0x11, 0x22, 0x33, 0x44]));

    let mut prefix = [0u8; 6];
    prefix.copy_from_slice(&PEER[..6]);
    let output = node
        .send_text(&mut link, prefix, 0, 0, 1, "two byte hops".into())
        .await
        .expect("send completes");

    let packet = Packet::decode(&output.transmit[0]).expect("decodes");
    assert_eq!(packet.path_hash_size(), 2);
    assert_eq!(packet.path_hash_count(), 2);
    assert_eq!(packet.path, vec![0x11, 0x22, 0x33, 0x44]);
}

#[tokio::test]
async fn the_advert_announces_the_bbs_as_a_room_server() {
    let (mut link, _modem, mut node) = node();

    let raw = node
        .build_self_advert(&mut link, true, 1)
        .await
        .expect("builds the advert");
    let packet = Packet::decode(&raw).expect("decodes");
    let advert = AdvertBody::parse(&packet.payload).expect("parses");

    assert_eq!(advert.flags & 0x0F, 0x03, "room server, not chat node");
}

#[tokio::test]
async fn a_send_to_an_unknown_contact_is_reported_as_failed_not_flooded() {
    let (mut link, _modem, mut node) = node();

    let output = node
        .send_text(&mut link, [0xAA; 6], 0, 0, 1, "nobody home".into())
        .await
        .expect("send completes");

    match output.frames.as_slice() {
        [InboundFrame::Sent(result)] => {
            assert_eq!(result.expected_ack, 0);
            assert!(
                !result.is_flood,
                "a failure must not look like an accepted flood send"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn the_same_message_arriving_over_two_routes_is_handled_once() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    let plain = TxtMsgPlain {
        timestamp: 1_700_000_500,
        txt_type: 0,
        attempt: 0,
        text: "one copy please".into(),
        extended_attempt: 0,
    };
    let via_a = encrypted_packet(
        PayloadType::TxtMsg,
        RouteType::Flood,
        PEER,
        RECORDED_IDENTITY,
        &plain.encode(),
        &[0xA0, 0xA1, 0xA2],
    );
    let via_ab = encrypted_packet(
        PayloadType::TxtMsg,
        RouteType::Flood,
        PEER,
        RECORDED_IDENTITY,
        &plain.encode(),
        &[0xA0, 0xA1, 0xA2, 0xB0, 0xB1, 0xB2],
    );

    node.handle_inbound_packet(&mut link, &via_a, None)
        .await
        .expect("first copy");
    node.handle_inbound_packet(&mut link, &via_ab, None)
        .await
        .expect("second copy");

    assert_eq!(
        node.queued_messages(),
        1,
        "the same message reached us twice"
    );
}

#[tokio::test]
async fn two_different_messages_over_the_same_route_are_both_kept() {
    let (mut link, _modem, mut node) = node();
    register_peer(&mut link, &mut node).await;

    for (index, text) in ["first", "second"].iter().enumerate() {
        let plain = TxtMsgPlain {
            timestamp: 1_700_000_600 + index as u32,
            txt_type: 0,
            attempt: 0,
            text: (*text).into(),
            extended_attempt: 0,
        };
        let raw = encrypted_packet(
            PayloadType::TxtMsg,
            RouteType::Flood,
            PEER,
            RECORDED_IDENTITY,
            &plain.encode(),
            &[0xA0, 0xA1, 0xA2, 0xB0, 0xB1, 0xB2],
        );
        node.handle_inbound_packet(&mut link, &raw, None)
            .await
            .expect("handles the packet");
    }

    assert_eq!(
        node.queued_messages(),
        2,
        "distinct messages were deduplicated"
    );
}

#[tokio::test]
async fn a_later_advert_from_the_same_node_is_not_treated_as_a_duplicate() {
    let (mut link, _modem, mut node) = node();

    node.handle_inbound_packet(
        &mut link,
        &advert_packet(PEER, 1_700_000_000, "Peer", &[]),
        None,
    )
    .await
    .expect("first advert");

    let output = node
        .handle_inbound_packet(
            &mut link,
            &advert_packet(PEER, 1_700_000_900, "Peer Renamed", &[]),
            None,
        )
        .await
        .expect("second advert");

    assert!(
        !output.frames.is_empty(),
        "a fresh advert from a known node must not be dropped as a duplicate"
    );
    let contact = node.contacts().by_pubkey(&PEER).expect("stored");
    assert_eq!(contact.name, "Peer Renamed");
    assert_eq!(contact.last_advert_timestamp, 1_700_000_900);
}

#[tokio::test]
async fn a_replayed_advert_is_still_rejected() {
    let (mut link, _modem, mut node) = node();

    node.handle_inbound_packet(
        &mut link,
        &advert_packet(PEER, 1_700_000_900, "Peer", &[]),
        None,
    )
    .await
    .expect("first advert");
    node.handle_inbound_packet(
        &mut link,
        &advert_packet(PEER, 1_700_000_100, "Rollback", &[]),
        None,
    )
    .await
    .expect("replayed advert");

    let contact = node.contacts().by_pubkey(&PEER).expect("stored");
    assert_eq!(contact.name, "Peer");
    assert_eq!(contact.last_advert_timestamp, 1_700_000_900);
}
