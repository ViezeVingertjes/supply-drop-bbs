//! Contact store, shared-secret cache and path management.
//!
//! The store holds one [`Contact`] per known node, keyed by its Ed25519 public
//! key, alongside the shared secret the device derived for that key. The
//! contact type comes from `meshcore-companion`, so an entry is emitted as a
//! companion-protocol frame without conversion.
//!
//! Lookups follow the way MeshCore addresses packets. A direct message carries
//! a six-byte key prefix, while a path or an acknowledgement carries a single
//! byte. A one-byte hash collides often enough that [`ContactStore::by_hash`]
//! returns every candidate for the caller to try in turn.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use meshcore_companion::constants::MAX_PATH_SIZE;
use meshcore_companion::types::Contact;

use crate::packet::AdvertBody;

/// How many contacts a store keeps before evicting the stalest.
///
/// A contact is roughly two hundred bytes, so ten thousand costs a couple of
/// megabytes: comfortable on a Raspberry Pi and far above any realistic mesh.
pub const DEFAULT_CONTACT_CAPACITY: usize = 10_000;

/// Format version written into the contact file.
const PERSIST_VERSION: u32 = 1;

/// The on-disk form of the contact table.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedContacts {
    version: u32,
    contacts: Vec<PersistedContact>,
}

/// One contact as written to disk.
///
/// Shared secrets are absent by design; they are re-derived on demand.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedContact {
    pubkey: String,
    adv_type: u8,
    flags: u8,
    out_path: String,
    name: String,
    last_advert_timestamp: u32,
    gps_lat: i32,
    gps_lon: i32,
    lastmod: u32,
}

impl From<&Contact> for PersistedContact {
    fn from(contact: &Contact) -> Self {
        let path_len = usize::try_from(contact.out_path_len.max(0)).unwrap_or(0);
        Self {
            pubkey: to_hex(&contact.pubkey),
            adv_type: contact.adv_type,
            flags: contact.flags,
            out_path: if contact.out_path_len < 0 {
                String::new()
            } else {
                to_hex(&contact.out_path[..path_len])
            },
            name: contact.name.clone(),
            last_advert_timestamp: contact.last_advert_timestamp,
            gps_lat: contact.gps_lat,
            gps_lon: contact.gps_lon,
            lastmod: contact.lastmod,
        }
    }
}

impl PersistedContact {
    fn into_contact(self) -> Option<Contact> {
        let pubkey: [u8; 32] = from_hex(&self.pubkey)?.try_into().ok()?;
        let path = from_hex(&self.out_path)?;
        if path.len() > MAX_PATH_SIZE {
            return None;
        }

        let mut out_path = [0u8; MAX_PATH_SIZE];
        out_path[..path.len()].copy_from_slice(&path);
        let out_path_len = if self.out_path.is_empty() {
            -1
        } else {
            i8::try_from(path.len()).ok()?
        };

        Some(Contact {
            pubkey,
            adv_type: self.adv_type,
            flags: self.flags,
            out_path_len,
            out_path,
            name: self.name,
            last_advert_timestamp: self.last_advert_timestamp,
            gps_lat: self.gps_lat,
            gps_lon: self.gps_lon,
            lastmod: self.lastmod,
        })
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

/// The node type occupies the low nibble of the advert flags byte.
const ADV_TYPE_MASK: u8 = 0x0F;

/// Known contacts and the shared secrets derived for them.
///
/// The secret cache is keyed by public key and is independent of the contact
/// entries, because a shared secret depends only on the two keys involved. An
/// advert that updates a contact leaves the cached secret in place, and only
/// [`ContactStore::remove`] discards it.
#[derive(Debug, Clone)]
pub struct ContactStore {
    contacts: Vec<Contact>,
    secrets: HashMap<[u8; 32], [u8; 32]>,
    capacity: usize,
    dirty: bool,
}

impl Default for ContactStore {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CONTACT_CAPACITY)
    }
}

impl ContactStore {
    /// An empty store holding at most `capacity` contacts.
    ///
    /// A capacity of zero is treated as one, so a store always holds the
    /// contact it was last told about.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            contacts: Vec::new(),
            secrets: HashMap::new(),
            capacity: capacity.max(1),
            dirty: false,
        }
    }

    /// Read a store back from disk.
    ///
    /// A missing or unreadable file yields an empty store, because losing the
    /// contact table costs a re-advert rather than correctness. When the file
    /// holds more contacts than `capacity`, the freshest are kept.
    #[must_use]
    pub fn load(path: &Path, capacity: usize) -> Self {
        let mut store = Self::with_capacity(capacity);

        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return store,
            Err(error) => {
                warn!(%error, path = %path.display(), "kiss: could not read the contact store");
                return store;
            }
        };

        let persisted: PersistedContacts = match serde_json::from_str(&raw) {
            Ok(persisted) => persisted,
            Err(error) => {
                warn!(
                    %error,
                    path = %path.display(),
                    "kiss: contact store is unreadable, starting empty"
                );
                return store;
            }
        };

        let mut contacts: Vec<Contact> = persisted
            .contacts
            .into_iter()
            .filter_map(PersistedContact::into_contact)
            .collect();
        contacts.sort_by_key(|contact| std::cmp::Reverse(contact.last_advert_timestamp));
        contacts.truncate(store.capacity);
        store.contacts = contacts;
        store
    }

    /// Write the store to disk, replacing any previous file atomically.
    ///
    /// Cached shared secrets are deliberately not written: they are derived
    /// from the two public keys on demand, so persisting them would put key
    /// material on disk for no gain.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the file cannot be written.
    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        let persisted = PersistedContacts {
            version: PERSIST_VERSION,
            contacts: self.contacts.iter().map(PersistedContact::from).collect(),
        };
        let encoded = serde_json::to_vec_pretty(&persisted)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, &encoded)?;
        std::fs::rename(&temporary, path)?;

        self.dirty = false;
        Ok(())
    }

    /// Whether the store has changed since it was last saved.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// How many contacts the store will hold before evicting.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn evict_stalest(&mut self, protected: &[u8; 32]) {
        while self.contacts.len() > self.capacity {
            let victim = self
                .contacts
                .iter()
                .enumerate()
                .filter(|(_, contact)| &contact.pubkey != protected)
                .min_by_key(|(_, contact)| contact.last_advert_timestamp)
                .map(|(index, contact)| (index, contact.pubkey));

            let Some((index, pubkey)) = victim else {
                return;
            };
            debug!(
                contact = ?&pubkey[..6],
                "kiss: contact store full, evicting the stalest contact"
            );
            self.contacts.remove(index);
            self.secrets.remove(&pubkey);
        }
    }

    /// Insert or update the contact an advert describes.
    ///
    /// Returns `true` only when the advert added a contact that was not
    /// already stored. An update returns `false`, and so does a rejected
    /// advert, so a caller that announces new nodes never announces a replay.
    ///
    /// An advert whose timestamp is at or below the stored
    /// `last_advert_timestamp` is a replay and is discarded without touching
    /// the entry, matching the check in `BaseChatMesh::onAdvertRecv`.
    ///
    /// A new contact starts with `out_path_len` at `-1`, meaning the path is
    /// unknown and the first message sent to it floods, and with `flags` at
    /// zero.
    pub fn upsert_from_advert(&mut self, advert: &AdvertBody) -> bool {
        let now = Self::now();
        let name = advert.name.clone().unwrap_or_default();
        let adv_type = advert.flags & ADV_TYPE_MASK;

        if let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|contact| contact.pubkey == advert.pubkey)
        {
            if advert.timestamp <= contact.last_advert_timestamp {
                return false;
            }
            contact.adv_type = adv_type;
            contact.name = name;
            contact.last_advert_timestamp = advert.timestamp;
            if let Some(latitude) = advert.latitude_1e6 {
                contact.gps_lat = latitude;
            }
            if let Some(longitude) = advert.longitude_1e6 {
                contact.gps_lon = longitude;
            }
            contact.lastmod = now;
            self.dirty = true;
            return false;
        }

        self.contacts.push(Contact {
            pubkey: advert.pubkey,
            adv_type,
            flags: 0,
            out_path_len: -1,
            out_path: [0u8; MAX_PATH_SIZE],
            name,
            last_advert_timestamp: advert.timestamp,
            gps_lat: advert.latitude_1e6.unwrap_or(0),
            gps_lon: advert.longitude_1e6.unwrap_or(0),
            lastmod: now,
        });
        self.dirty = true;
        self.evict_stalest(&advert.pubkey);
        true
    }

    /// Look up a contact by its full public key.
    #[must_use]
    pub fn by_pubkey(&self, pubkey: &[u8; 32]) -> Option<&Contact> {
        self.contacts
            .iter()
            .find(|contact| contact.pubkey == *pubkey)
    }

    /// Look up a contact by the six-byte key prefix a direct message carries.
    ///
    /// Returns the first contact whose public key starts with the prefix.
    #[must_use]
    pub fn by_prefix(&self, prefix: &[u8; 6]) -> Option<&Contact> {
        self.contacts
            .iter()
            .find(|contact| contact.pubkey[..6] == prefix[..])
    }

    /// Collect every contact whose public key starts with the given byte.
    ///
    /// MeshCore addresses a packet by a one-byte hash of the destination key,
    /// so two contacts can share a hash. The caller resolves the ambiguity by
    /// trying each candidate's shared secret against the payload. Candidates
    /// come back in insertion order.
    #[must_use]
    pub fn by_hash(&self, hash: u8) -> Vec<&Contact> {
        self.contacts
            .iter()
            .filter(|contact| contact.pubkey[0] == hash)
            .collect()
    }

    /// Drop a contact and the shared secret cached for it.
    ///
    /// Returns whether the contact was stored.
    pub fn remove(&mut self, pubkey: &[u8; 32]) -> bool {
        self.secrets.remove(pubkey);
        let before = self.contacts.len();
        self.contacts.retain(|contact| contact.pubkey != *pubkey);
        let removed = self.contacts.len() != before;
        self.dirty |= removed;
        removed
    }

    /// Record the outbound path to a contact.
    ///
    /// Returns `false`, leaving the contact untouched, when the contact is
    /// unknown or the path is longer than the `MAX_PATH_SIZE` bytes a MeshCore
    /// packet header holds.
    pub fn set_path(&mut self, pubkey: &[u8; 32], path: &[u8]) -> bool {
        if path.len() > MAX_PATH_SIZE {
            return false;
        }
        let Ok(path_len) = i8::try_from(path.len()) else {
            return false;
        };
        let now = Self::now();
        let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|contact| contact.pubkey == *pubkey)
        else {
            return false;
        };
        contact.out_path = [0u8; MAX_PATH_SIZE];
        contact.out_path[..path.len()].copy_from_slice(path);
        contact.out_path_len = path_len;
        contact.lastmod = now;
        self.dirty = true;
        true
    }

    /// Forget the outbound path to a contact so the next message floods.
    ///
    /// Returns whether the contact was stored.
    pub fn reset_path(&mut self, pubkey: &[u8; 32]) -> bool {
        let now = Self::now();
        let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|contact| contact.pubkey == *pubkey)
        else {
            return false;
        };
        contact.out_path = [0u8; MAX_PATH_SIZE];
        contact.out_path_len = -1;
        contact.lastmod = now;
        self.dirty = true;
        true
    }

    /// Read the shared secret cached for a public key.
    #[must_use]
    pub fn cached_secret(&self, pubkey: &[u8; 32]) -> Option<&[u8; 32]> {
        self.secrets.get(pubkey)
    }

    /// Cache the shared secret the device derived for a public key.
    ///
    /// The key does not need a stored contact, so a secret can be cached
    /// before the advert that names the node arrives.
    pub fn store_secret(&mut self, pubkey: &[u8; 32], secret: [u8; 32]) {
        self.secrets.insert(*pubkey, secret);
    }

    /// Iterate the stored contacts in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.iter()
    }

    /// Count the stored contacts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Report whether the store holds no contacts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Collect the contacts modified at or after the given timestamp.
    ///
    /// This answers a companion-protocol `GetContacts { since }`. The bound is
    /// inclusive, so a client that echoes back the `most_recent_lastmod` it
    /// was given receives the contact carrying that timestamp again.
    #[must_use]
    pub fn modified_since(&self, since: u32) -> Vec<&Contact> {
        self.contacts
            .iter()
            .filter(|contact| contact.lastmod >= since)
            .collect()
    }

    /// Report the highest `lastmod` in the store, or zero when it is empty.
    ///
    /// An `EndOfContacts` reply carries this value, and a client sends it back
    /// as the `since` of its next `GetContacts`.
    #[must_use]
    pub fn most_recent_lastmod(&self) -> u32 {
        self.contacts
            .iter()
            .map(|contact| contact.lastmod)
            .max()
            .unwrap_or(0)
    }

    /// Read the wall clock in whole seconds since the Unix epoch, as the
    /// MeshCore firmware stamps `lastmod` from its RTC.
    fn now() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
            })
    }
}
