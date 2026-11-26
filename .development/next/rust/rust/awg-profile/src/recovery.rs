use super::{edit_document, invalid};
use nfqws2_store::Store;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io;
const FIELDS: [(&str, &str, u64, u64, u64); 5] = [
    ("fast_retry_seconds", "первая фаза повторов", 1, 600, 60),
    ("retry_delay_seconds", "обычная пауза повторов", 1, 30, 5),
    (
        "slow_retry_after_seconds",
        "начало длительных пауз",
        1800,
        3600,
        3600,
    ),
    (
        "slow_retry_delay_seconds",
        "длительная пауза повторов",
        90,
        900,
        90,
    ),
    ("handshake_timeout_seconds", "проверка handshake", 5, 60, 20),
];

pub struct RecoveryUpdate(Value);

impl<'de> Deserialize<'de> for RecoveryUpdate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReadRecoveryUpdate;
        impl<'de> serde::de::Visitor<'de> for ReadRecoveryUpdate {
            type Value = RecoveryUpdate;

            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("an AWG recovery settings object")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<RecoveryUpdate, E> {
                Ok(RecoveryUpdate(json!({})))
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<RecoveryUpdate, M::Error> {
                let mut settings = json!({});
                while let Some(field) = fields.next_key::<String>()? {
                    let folded = field.replace('ſ', "s").replace('K', "k");
                    if let Some((key, ..)) = FIELDS
                        .iter()
                        .find(|(key, ..)| folded.eq_ignore_ascii_case(key))
                    {
                        if let Some(seconds) = fields.next_value::<Option<i64>>()? {
                            settings[*key] = json!(seconds);
                        }
                    } else {
                        let _: serde::de::IgnoredAny = fields.next_value()?;
                    }
                }
                Ok(RecoveryUpdate(settings))
            }
        }
        deserializer.deserialize_any(ReadRecoveryUpdate)
    }
}

pub fn recovery_settings(raw: &Value) -> Value {
    let mut out = json!({});
    for (k, _, min, max, default) in FIELDS {
        out[k] = json!(raw[k]
            .as_u64()
            .filter(|v| (min..=max).contains(v))
            .unwrap_or(default));
    }
    out
}
pub fn save_recovery(db: &Store, RecoveryUpdate(raw): RecoveryUpdate) -> io::Result<()> {
    for (k, name, min, max, _) in FIELDS {
        if !raw[k].as_u64().is_some_and(|v| (min..=max).contains(&v)) {
            return Err(invalid(&format!(
                "{name}: допустимо от {min} до {max} секунд"
            )));
        }
    }
    edit_document(db, |d| {
        if !d["recovery_settings"].is_object() {
            d["recovery_settings"] = json!({});
        }
        for (k, ..) in FIELDS {
            d["recovery_settings"][k] = raw[k].clone();
        }
        Ok(())
    })
}
