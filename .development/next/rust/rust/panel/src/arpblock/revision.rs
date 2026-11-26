use super::parse::{Interface, Topology};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{fmt::Write, io};

// Go hashes its parsed topology in struct field order. Use the same shape so
// a page opened before an upgrade can submit its revision after the switch.
struct Snapshot<'a>(&'a Topology);
struct Bridge<'a>(&'a Interface);
struct AccessPoint<'a>(&'a Interface);

impl Serialize for Snapshot<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let cfg = self.0;
        let mut state = serializer.serialize_struct("NativeConfig", 4)?;
        state.serialize_field(
            "Bridges",
            &cfg.bridges.iter().map(Bridge).collect::<Vec<_>>(),
        )?;
        state.serialize_field(
            "AccessPoints",
            &cfg.aps.iter().map(AccessPoint).collect::<Vec<_>>(),
        )?;
        state.serialize_field("IsolatePrivate", &cfg.isolate_private.unwrap_or(true))?;
        state.serialize_field("IsolatePrivateExplicit", &cfg.isolate_private.is_some())?;
        state.end()
    }
}

impl Serialize for Bridge<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bridge = self.0;
        let mut state = serializer.serialize_struct("NativeBridgeConfig", 12)?;
        state.serialize_field("ID", &bridge.id)?;
        state.serialize_field("Rename", &bridge.alias)?;
        state.serialize_field("Description", &bridge.description)?;
        state.serialize_field("SecurityLevel", &bridge.level)?;
        state.serialize_field("Address", &bridge.address)?;
        state.serialize_field("Mask", &bridge.mask)?;
        state.serialize_field("Members", &bridge.members)?;
        state.serialize_field("Up", &bridge.up)?;
        state.serialize_field("Global", &bridge.global)?;
        state.serialize_field("PeerIsolation", &bridge.isolation.unwrap_or(false))?;
        state.serialize_field("PeerIsolationExplicit", &bridge.isolation.is_some())?;
        state.serialize_field("ExplicitSecurity", &!bridge.level.is_empty())?;
        state.end()
    }
}

impl Serialize for AccessPoint<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ap = self.0;
        let mut state = serializer.serialize_struct("NativeAccessPointConfig", 5)?;
        state.serialize_field("ID", &ap.id)?;
        state.serialize_field("Rename", &ap.alias)?;
        state.serialize_field("Description", &ap.description)?;
        state.serialize_field("SSID", &ap.ssid)?;
        state.serialize_field("Up", &ap.up)?;
        state.end()
    }
}

pub(super) fn token(cfg: &Topology) -> io::Result<String> {
    let encoded = serde_json::to_string(&Snapshot(cfg))?;
    let mut digest = Sha256::new();
    let mut start = 0;
    // encoding/json.Marshal escapes these characters even inside JSON strings.
    for (index, c) in encoded.char_indices() {
        let escaped = match c {
            '<' => br"\u003c",
            '>' => br"\u003e",
            '&' => br"\u0026",
            '\u{2028}' => br"\u2028",
            '\u{2029}' => br"\u2029",
            _ => continue,
        };
        digest.update(&encoded.as_bytes()[start..index]);
        digest.update(escaped);
        start = index + c.len_utf8();
    }
    digest.update(&encoded.as_bytes()[start..]);
    let mut token = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut token, "{byte:02x}").unwrap();
    }
    Ok(token)
}
