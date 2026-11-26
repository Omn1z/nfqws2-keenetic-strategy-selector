use crate::model::err;
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor,
};
use std::{collections::HashSet, fmt, io};
struct Check(usize);
impl<'de> DeserializeSeed<'de> for Check {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        if self.0 > 64 {
            return Err(de::Error::custom("слишком глубокий JSON"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Check {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Check(self.0 + 1))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("повторяющееся поле JSON"));
            }
            map.next_value_seed(Check(self.0 + 1))?;
        }
        Ok(())
    }
}
pub fn decode<T: DeserializeOwned>(raw: &[u8], max: usize) -> io::Result<T> {
    if raw.is_empty() || raw.len() > max {
        return Err(err("размер JSON вне допустимого диапазона"));
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    Check(0)
        .deserialize(&mut d)
        .map_err(|e| err(e.to_string()))?;
    d.end().map_err(|e| err(e.to_string()))?;
    serde_json::from_slice(raw).map_err(|e| err(e.to_string()))
}
