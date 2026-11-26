use super::{bad, ApiError, Config, Store, Value, FILE};
use nfqws2_store::{ConfigFile, Transaction};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Map};
use std::{fmt, io};

#[derive(Clone, Copy)]
enum GoValue {
    Bool,
    Int,
    Text,
    Collection,
}

const GO_FIELDS: &[(&str, GoValue)] = &[
    ("enabled", GoValue::Bool),
    ("port", GoValue::Int),
    ("secret", GoValue::Text),
    ("dc_redirects", GoValue::Collection),
    ("buffer_size", GoValue::Int),
    ("pool_size", GoValue::Int),
    ("proxy_protocol", GoValue::Bool),
    ("force_test_dc", GoValue::Bool),
    ("sni_fronting", GoValue::Bool),
    ("disable_secure", GoValue::Bool),
    ("cfproxy", GoValue::Bool),
    ("cfproxy_h2_media", GoValue::Bool),
    ("cfproxy_user_domain", GoValue::Text),
    ("cfproxy_worker_domain", GoValue::Text),
    ("cfproxy_user_domains", GoValue::Collection),
    ("cfproxy_worker_domains", GoValue::Collection),
    ("fake_tls_domain", GoValue::Text),
    ("link_host", GoValue::Text),
];

fn go_field(key: &str) -> Option<(&'static str, GoValue)> {
    // Go SimpleFold has two non-ASCII equivalents for ASCII field names.
    let folded = key.chars().map(|ch| match ch {
        'ſ' => 's',
        'K' => 'k',
        _ => ch.to_ascii_lowercase(),
    });
    GO_FIELDS
        .iter()
        .copied()
        .find(|(field, _)| folded.clone().eq(field.chars()))
}

impl GoValue {
    fn accepts_scalar(self, value: &Value) -> bool {
        match self {
            Self::Bool => value.is_boolean(),
            Self::Int => value.as_i64().is_some_and(|n| isize::try_from(n).is_ok()),
            Self::Text => value.is_string(),
            Self::Collection => true,
        }
    }
}

const TYPE_ERROR: &str = "Некорректные типы полей настроек TG WS";

/// Keep occurrence order for Go's case-insensitive matching of configuration keys.
pub(super) struct Fields(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Fields;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("объект настроек TG WS")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Fields, A::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    fields.push(entry);
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(Object)
    }
}

impl Fields {
    fn canonical(self, startup: bool) -> io::Result<Map<String, Value>> {
        // `transport` belongs to Rust and keeps its exact spelling and normal
        // JSON replacement semantics.
        let transport = self
            .0
            .iter()
            .rev()
            .find(|(key, _)| key == "transport")
            .map(|(_, value)| value);
        let mut fields = Map::new();
        if startup && transport.and_then(Value::as_str).unwrap_or("").is_empty() {
            fields.insert("dc_redirects".into(), json!(Config::default().dc_redirects));
        }
        if let Some(value) = transport.filter(|value| !value.is_null()) {
            fields.insert("transport".into(), value.clone());
        }

        for (key, value) in self.0 {
            let Some((field, kind)) = go_field(&key) else {
                continue;
            };
            if value.is_null() && !matches!(kind, GoValue::Collection) {
                continue;
            }
            if !kind.accepts_scalar(&value) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, TYPE_ERROR));
            }
            if field == "dc_redirects" {
                // Go overlays non-null maps and clears them on explicit null.
                match (fields.entry(field).or_insert(Value::Null), value) {
                    (Value::Object(existing), Value::Object(routes)) => existing.extend(routes),
                    (slot, value) => *slot = value,
                }
            } else {
                fields.insert(field.into(), value);
            }
        }
        Ok(fields)
    }
}
// A Go file is decoded over startup defaults, while the HTTP replace handler
// decodes into a zero-valued Config. Its custom unmarshaler defaults H2 to true.
pub(super) fn request(wire: Fields) -> Result<Config, ApiError> {
    let mut fields = wire.canonical(false).map_err(bad)?;
    fields.entry("pool_size").or_insert(json!(0));
    fields.entry("cfproxy").or_insert(json!(false));
    fields.entry("dc_redirects").or_insert(json!({}));
    serde_json::from_value(Value::Object(fields)).map_err(|_| bad(TYPE_ERROR))
}

pub(super) fn load(db: &Store) -> io::Result<Config> {
    let fields: Fields = db.read_limited(FILE, 1 << 20)?;
    Ok(serde_json::from_value(Value::Object(
        fields.canonical(true)?,
    ))?)
}

pub(super) fn save(tx: &Transaction<'_>, db: &Store, config: &Config) -> io::Result<()> {
    let mut fields: Map<String, Value> = match db.read_limited(FILE, 1 << 20) {
        Ok(fields) => fields,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Map::new(),
        Err(e) => return Err(e),
    };
    // Store one canonical spelling for recognized controls and keep extensions.
    fields.retain(|key, _| key != "transport" && go_field(key).is_none());
    let Value::Object(known) = serde_json::to_value(config)? else {
        unreachable!()
    };
    fields.extend(known);
    tx.save(FILE, &fields)
}

pub(super) fn persist(db: &Store, config: &Config, explicit_config: bool) -> io::Result<()> {
    let malformed = |e: &io::Error| {
        matches!(
            e.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
        )
    };
    match db.transaction(|tx| save(tx, db, config)) {
        Err(e) if explicit_config && malformed(&e) => {
            // An explicit, validated replacement can recover the UI. Keep the
            // damaged primary in the store's private .corrupt copy first.
            let repair: ConfigFile<Map<String, Value>> =
                ConfigFile::new(FILE, Map::new, |_| Ok(()));
            let fields = serde_json::from_value(serde_json::to_value(config)?)?;
            repair.replace_checked(db, fields, || {
                match db.read_limited::<Map<String, Value>>(FILE, 1 << 20) {
                    Err(e) if malformed(&e) => Ok(()),
                    Err(e) => Err(e),
                    Ok(_) => Err(io::Error::other(
                        "Настройки TG WS уже изменились, повторите сохранение",
                    )),
                }
            })?;
            Ok(())
        }
        result => result,
    }
}
