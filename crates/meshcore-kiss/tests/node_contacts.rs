//! Contact store tests: upsert, replay rejection, lookup, paths and secrets.

use meshcore_kiss::node::contacts::{ContactStore, DEFAULT_CONTACT_CAPACITY, OUT_PATH_UNKNOWN};
use meshcore_kiss::packet::{pack_path_length, AdvertBody};

fn advert(pubkey: [u8; 32], timestamp: u32, name: &str) -> AdvertBody {
    AdvertBody {
        pubkey,
        timestamp,
        signature: [0u8; 64],
        flags: 0x81,
        latitude_1e6: None,
        longitude_1e6: None,
        name: Some(name.into()),
        appdata: vec![0x81],
    }
}

#[test]
fn upsert_inserts_then_updates_by_pubkey() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    assert!(store.upsert_from_advert(&advert(key, 100, "one")));
    assert!(!store.upsert_from_advert(&advert(key, 200, "two")));
    let contact = store.by_pubkey(&key).expect("present");
    assert_eq!(contact.name, "two");
    assert_eq!(contact.last_advert_timestamp, 200);
    assert_eq!(store.iter().count(), 1);
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}

#[test]
fn replayed_advert_is_rejected() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 200, "one"));
    store.upsert_from_advert(&advert(key, 100, "replayed"));
    let contact = store.by_pubkey(&key).expect("present");
    assert_eq!(contact.name, "one");
    assert_eq!(contact.last_advert_timestamp, 200);
}

#[test]
fn advert_with_the_same_timestamp_is_rejected() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 200, "one"));
    assert!(!store.upsert_from_advert(&advert(key, 200, "again")));
    assert_eq!(store.by_pubkey(&key).expect("present").name, "one");
}

#[test]
fn lookup_by_six_byte_prefix_and_first_byte_hash() {
    let mut store = ContactStore::default();
    let mut key = [0x00; 32];
    key[..6].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
    store.upsert_from_advert(&advert(key, 1, "node"));

    assert!(store
        .by_prefix(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02])
        .is_some());
    assert!(store.by_prefix(&[0x00; 6]).is_none());
    assert_eq!(store.by_hash(0xDE).len(), 1);
    assert!(store.by_hash(0x00).is_empty());
}

#[test]
fn by_hash_returns_every_colliding_contact_in_insertion_order() {
    let mut store = ContactStore::default();
    let mut first = [0x11; 32];
    first[1] = 0x01;
    let mut second = [0x11; 32];
    second[1] = 0x02;
    let other = [0x22; 32];

    store.upsert_from_advert(&advert(first, 1, "first"));
    store.upsert_from_advert(&advert(second, 1, "second"));
    store.upsert_from_advert(&advert(other, 1, "other"));

    let candidates = store.by_hash(0x11);
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].name, "first");
    assert_eq!(candidates[1].name, "second");
    assert_eq!(store.by_hash(0x22).len(), 1);
}

#[test]
fn new_contact_starts_with_an_unknown_path_and_the_advert_node_type() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "node"));
    let contact = store.by_pubkey(&key).expect("present");
    assert_eq!(contact.out_path_len, OUT_PATH_UNKNOWN);
    assert!(store.route(&key).is_none());
    assert_eq!(contact.adv_type, 0x01);
    assert_eq!(contact.flags, 0);
    assert_eq!(contact.gps_lat, 0);
    assert_eq!(contact.gps_lon, 0);
}

#[test]
fn set_path_then_reset_path_clears_the_route() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "node"));

    let one_three_byte_hop = pack_path_length(3, 1);
    assert!(store.set_path(&key, one_three_byte_hop, &[0x11, 0x22, 0x33]));
    let contact = store.by_pubkey(&key).expect("present");
    assert_eq!(contact.out_path_len, one_three_byte_hop as i8);
    assert_eq!(&contact.out_path[..3], &[0x11, 0x22, 0x33]);
    assert_eq!(
        store.route(&key),
        Some((one_three_byte_hop, vec![0x11, 0x22, 0x33]))
    );

    assert!(store.reset_path(&key));
    let contact = store.by_pubkey(&key).expect("present");
    assert_eq!(contact.out_path_len, OUT_PATH_UNKNOWN);
    assert!(store.route(&key).is_none());
}

/// `out_path_len` is the packed `path_length`, so three-byte hashes push it
/// past `i8::MAX` and it lands negative. Only [`OUT_PATH_UNKNOWN`] may be read
/// as "no route"; a `< 0` test here would flood every reply on a mesh using
/// hashes wider than a byte.
#[test]
fn a_negative_out_path_len_that_is_not_the_sentinel_is_still_a_route() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "node"));

    let three_hops = pack_path_length(3, 3);
    assert!(
        three_hops as i8 <= 0,
        "expected the packed byte to go negative"
    );
    assert!(store.set_path(&key, three_hops, &[0x11; 9]));

    assert_eq!(store.route(&key), Some((three_hops, vec![0x11; 9])));
}

#[test]
fn set_path_rejects_encodings_that_do_not_match_the_path() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "node"));

    let two_one_byte_hops = pack_path_length(1, 2);
    assert!(store.set_path(&key, two_one_byte_hops, &[0x11, 0x22]));

    assert!(
        !store.set_path(&key, pack_path_length(3, 2), &[0x33, 0x44]),
        "two three-byte hops need six bytes, not two"
    );
    assert!(
        !store.set_path(&key, 0xFF, &[0x33; 63]),
        "the reserved four-byte hash size must be refused"
    );
    assert!(
        !store.set_path(&key, pack_path_length(3, 63), &[0x33; 189]),
        "a path over MAX_PATH_SIZE must be refused"
    );

    let contact = store.by_pubkey(&key).expect("present");
    assert_eq!(contact.out_path_len, two_one_byte_hops as i8);
    assert_eq!(&contact.out_path[..2], &[0x11, 0x22]);

    assert!(store.set_path(&key, pack_path_length(1, 64 - 1), &[0x44; 63]));
}

#[test]
fn set_path_on_unknown_contact_reports_false() {
    let mut store = ContactStore::default();
    assert!(!store.set_path(&[0xFF; 32], pack_path_length(1, 1), &[0x11]));
    assert!(store.route(&[0xFF; 32]).is_none());
}

#[test]
fn reset_path_on_unknown_contact_reports_false() {
    let mut store = ContactStore::default();
    assert!(!store.reset_path(&[0xFF; 32]));
}

#[test]
fn secret_cache_survives_contact_updates() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "one"));
    store.store_secret(&key, [0x7F; 32]);
    store.upsert_from_advert(&advert(key, 2, "two"));
    assert_eq!(store.cached_secret(&key), Some(&[0x7F; 32]));
}

#[test]
fn remove_drops_contact_and_secret() {
    let mut store = ContactStore::default();
    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "one"));
    store.store_secret(&key, [0x7F; 32]);
    assert!(store.remove(&key));
    assert!(store.by_pubkey(&key).is_none());
    assert_eq!(store.cached_secret(&key), None);
    assert!(store.is_empty());
    assert!(!store.remove(&key));
}

#[test]
fn modified_since_and_most_recent_lastmod_track_changes() {
    let mut store = ContactStore::default();
    assert_eq!(store.most_recent_lastmod(), 0);
    assert!(store.modified_since(0).is_empty());

    let key = [0xA1; 32];
    store.upsert_from_advert(&advert(key, 1, "one"));
    let lastmod = store.by_pubkey(&key).expect("present").lastmod;
    assert!(lastmod > 0);
    assert_eq!(store.most_recent_lastmod(), lastmod);
    assert_eq!(store.modified_since(0).len(), 1);
    assert_eq!(store.modified_since(lastmod).len(), 1);
    assert!(store.modified_since(lastmod + 1).is_empty());

    store.set_path(&key, pack_path_length(1, 1), &[0x11]);
    assert!(store.by_pubkey(&key).expect("present").lastmod >= lastmod);
    assert!(store.most_recent_lastmod() >= lastmod);
}

fn advert_named(pubkey: [u8; 32], timestamp: u32, name: &str) -> AdvertBody {
    AdvertBody::unsigned(pubkey, timestamp, 0x03, None, Some(name))
}

fn key(seed: u8) -> [u8; 32] {
    let mut out = [seed; 32];
    out[0] = seed;
    out[1] = seed.wrapping_mul(7);
    out
}

#[test]
fn contacts_survive_a_save_and_load_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    store.upsert_from_advert(&advert_named(key(1), 1_700_000_000, "Alice"));
    store.upsert_from_advert(&advert_named(key(2), 1_700_000_100, "Bob"));
    let one_three_byte_hop = pack_path_length(3, 1);
    assert!(store.set_path(&key(1), one_three_byte_hop, &[0x11, 0x22, 0x33]));
    store.save(&path).expect("saves");

    let loaded = ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY);
    assert_eq!(loaded.len(), 2);

    let alice = loaded.by_pubkey(&key(1)).expect("alice present");
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.adv_type, 0x03);
    assert_eq!(alice.last_advert_timestamp, 1_700_000_000);
    assert_eq!(alice.out_path_len, one_three_byte_hop as i8);
    assert_eq!(&alice.out_path[..3], &[0x11, 0x22, 0x33]);
    assert_eq!(
        loaded.route(&key(1)),
        Some((one_three_byte_hop, vec![0x11, 0x22, 0x33])),
        "the hash width a route was learned at must survive a restart"
    );
    assert_eq!(loaded.by_pubkey(&key(2)).expect("bob present").name, "Bob");
}

#[test]
fn a_contact_file_from_an_older_format_is_discarded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");
    std::fs::write(
        &path,
        br#"{"version":1,"contacts":[{"pubkey":"a1","adv_type":1,"flags":0,
            "out_path":"112233","name":"Alice","last_advert_timestamp":1,
            "gps_lat":0,"gps_lon":0,"lastmod":1}]}"#,
    )
    .expect("writes");

    assert!(ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY).is_empty());
}

#[test]
fn a_contact_whose_stored_path_contradicts_its_length_is_dropped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    store.upsert_from_advert(&advert_named(key(1), 1, "Alice"));
    store.save(&path).expect("saves");

    let raw = std::fs::read_to_string(&path).expect("reads");
    let corrupted = raw.replace(
        "\"out_path_len\": -1",
        &format!("\"out_path_len\": {}", pack_path_length(3, 2) as i8),
    );
    assert_ne!(raw, corrupted, "the fixture must actually change");
    std::fs::write(&path, corrupted).expect("writes");

    assert!(ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY).is_empty());
}

#[test]
fn an_unknown_path_round_trips_as_unknown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    store.upsert_from_advert(&advert_named(key(1), 1, "Alice"));
    store.save(&path).expect("saves");

    let loaded = ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY);
    assert_eq!(
        loaded.by_pubkey(&key(1)).expect("present").out_path_len,
        OUT_PATH_UNKNOWN
    );
    assert!(loaded.route(&key(1)).is_none());
}

#[test]
fn a_missing_file_loads_as_an_empty_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ContactStore::load(&dir.path().join("absent.json"), DEFAULT_CONTACT_CAPACITY);
    assert!(store.is_empty());
}

#[test]
fn a_corrupt_file_loads_as_an_empty_store_without_panicking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");
    std::fs::write(&path, b"{ this is not json").expect("writes");

    let store = ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY);
    assert!(store.is_empty());
}

#[test]
fn cached_secrets_are_never_written_to_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    store.upsert_from_advert(&advert_named(key(1), 1, "Alice"));
    store.store_secret(&key(1), [0xAB; 32]);
    store.save(&path).expect("saves");

    let raw = std::fs::read_to_string(&path).expect("reads");
    assert!(
        !raw.to_lowercase().contains("abababab"),
        "shared secrets must not be persisted"
    );
    assert_eq!(
        ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY).cached_secret(&key(1)),
        None
    );
}

#[test]
fn reaching_capacity_evicts_the_stalest_contact_first() {
    let mut store = ContactStore::with_capacity(3);
    store.upsert_from_advert(&advert_named(key(1), 1_000, "oldest"));
    store.upsert_from_advert(&advert_named(key(2), 3_000, "newer"));
    store.upsert_from_advert(&advert_named(key(3), 2_000, "middle"));
    assert_eq!(store.len(), 3);

    store.upsert_from_advert(&advert_named(key(4), 4_000, "newest"));

    assert_eq!(store.len(), 3);
    assert!(
        store.by_pubkey(&key(1)).is_none(),
        "stalest must be evicted"
    );
    assert!(store.by_pubkey(&key(2)).is_some());
    assert!(store.by_pubkey(&key(3)).is_some());
    assert!(store.by_pubkey(&key(4)).is_some());
}

#[test]
fn eviction_never_drops_the_contact_being_added() {
    let mut store = ContactStore::with_capacity(1);
    store.upsert_from_advert(&advert_named(key(1), 9_000, "incumbent"));
    store.upsert_from_advert(&advert_named(key(2), 1_000, "newcomer"));

    assert_eq!(store.len(), 1);
    assert!(
        store.by_pubkey(&key(2)).is_some(),
        "the contact just added must survive its own insertion"
    );
}

#[test]
fn eviction_discards_the_evicted_contacts_cached_secret() {
    let mut store = ContactStore::with_capacity(1);
    store.upsert_from_advert(&advert_named(key(1), 1_000, "first"));
    store.store_secret(&key(1), [0x7F; 32]);
    store.upsert_from_advert(&advert_named(key(2), 2_000, "second"));

    assert_eq!(store.cached_secret(&key(1)), None);
}

#[test]
fn updating_an_existing_contact_at_capacity_evicts_nothing() {
    let mut store = ContactStore::with_capacity(2);
    store.upsert_from_advert(&advert_named(key(1), 1_000, "one"));
    store.upsert_from_advert(&advert_named(key(2), 2_000, "two"));

    store.upsert_from_advert(&advert_named(key(1), 3_000, "one renamed"));

    assert_eq!(store.len(), 2);
    assert_eq!(
        store.by_pubkey(&key(1)).expect("present").name,
        "one renamed"
    );
    assert!(store.by_pubkey(&key(2)).is_some());
}

#[test]
fn loading_more_contacts_than_capacity_keeps_the_freshest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    for seed in 1..=5u8 {
        store.upsert_from_advert(&advert_named(key(seed), 1_000 * u32::from(seed), "n"));
    }
    store.save(&path).expect("saves");

    let loaded = ContactStore::load(&path, 2);
    assert_eq!(loaded.len(), 2);
    assert!(loaded.by_pubkey(&key(5)).is_some());
    assert!(loaded.by_pubkey(&key(4)).is_some());
    assert!(loaded.by_pubkey(&key(1)).is_none());
}

#[test]
fn the_store_reports_when_it_needs_saving() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    assert!(!store.is_dirty());

    store.upsert_from_advert(&advert_named(key(1), 1, "Alice"));
    assert!(store.is_dirty(), "an advert must mark the store dirty");

    store.save(&path).expect("saves");
    assert!(!store.is_dirty(), "saving must clear the dirty flag");

    store.set_path(&key(1), pack_path_length(3, 1), &[0x01, 0x02, 0x03]);
    assert!(store.is_dirty(), "a path change must mark the store dirty");
}

#[test]
fn saving_replaces_the_file_atomically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("contacts.json");

    let mut store = ContactStore::default();
    store.upsert_from_advert(&advert_named(key(1), 1, "Alice"));
    store.save(&path).expect("first save");
    store.upsert_from_advert(&advert_named(key(2), 2, "Bob"));
    store.save(&path).expect("second save");

    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("reads dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "contacts.json")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
    assert_eq!(ContactStore::load(&path, DEFAULT_CONTACT_CAPACITY).len(), 2);
}
