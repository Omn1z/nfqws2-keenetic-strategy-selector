use serde_json::Value;
use std::io;

/// The Go manager owns counters for its lifetime. Rust replaces the helper
/// when changing settings, so attach each helper to the last stopped snapshot.
pub(super) fn cumulative(previous: &Value, mut sample: Value) -> io::Result<Value> {
    // Helpers predating HTTP/2 cannot contribute media counters.
    if sample.is_object() && sample.get("h2").is_none() {
        sample["h2"] = serde_json::json!({});
    }
    for group in ["connections", "ws", "h2", "traffic"] {
        let fields = sample
            .get_mut(group)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| io::Error::other("Некорректная статистика TG WS"))?;
        for (name, value) in fields.iter_mut() {
            if name == "active" || name.starts_with("human_") {
                continue;
            }
            let count = value
                .as_u64()
                .ok_or_else(|| io::Error::other("Некорректный счётчик TG WS"))?;
            let prior = previous[group][name.as_str()].as_u64().unwrap_or(0);
            *value = Value::from(prior.saturating_add(count));
        }
        if let Some(prior) = previous[group].as_object() {
            for (name, value) in prior {
                if name != "active" && value.is_u64() {
                    fields.entry(name).or_insert_with(|| value.clone());
                }
            }
        }
    }
    for (bytes, human) in [("bytes_up", "human_up"), ("bytes_down", "human_down")] {
        sample["traffic"][human] =
            nfqws2_tgws_config::human_bytes(sample["traffic"][bytes].as_u64().unwrap_or(0)).into();
    }
    Ok(sample)
}

#[cfg(test)]
mod tests {
    use super::super::empty_stats;
    use super::*;
    use serde_json::json;
    #[test]
    fn restart_carries_totals_once_and_resets_only_live_gauges() {
        let mut previous = empty_stats();
        previous["connections"]["total"] = json!(9);
        previous["connections"]["active"] = json!(6);
        previous["h2"]["requests"] = json!(12);
        previous["traffic"]["bytes_up"] = json!(1000);
        previous["started_at"] = json!(7);
        let mut sample = empty_stats();
        sample["connections"]["total"] = json!(2);
        sample["connections"]["active"] = json!(1);
        sample["h2"]["requests"] = json!(5);
        sample["traffic"]["bytes_up"] = json!(24);
        sample["started_at"] = json!(19);
        let totals = cumulative(&previous, sample.clone()).unwrap();
        assert_eq!(totals["connections"]["total"], 11);
        assert_eq!(totals["connections"]["active"], 1);
        assert_eq!(totals["h2"]["requests"], 17);
        assert_eq!(totals["traffic"]["human_up"], "1.0KB");
        assert_eq!(totals["started_at"], 19);
        assert_eq!(cumulative(&previous, sample).unwrap(), totals);
        let mut older = empty_stats();
        older.as_object_mut().unwrap().remove("h2");
        let totals = cumulative(&previous, older).unwrap();
        assert_eq!(totals["h2"]["requests"], 12);
    }
}
