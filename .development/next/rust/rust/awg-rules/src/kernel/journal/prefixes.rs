//! A sorted prefix run shares its interface string; IPv4 hosts use one u32.
//! Every entry describes exactly one network. There are no ranges to expand.
use super::super::{packed, plan::iface_ok, Prefix};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr},
};

pub(in crate::kernel) fn serialize<S: Serializer>(
    prefixes: &BTreeMap<Prefix, String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut rows = serializer.serialize_seq(None)?;
    let mut previous = None;
    for (prefix, iface) in prefixes {
        if previous != Some(iface) {
            rows.serialize_element(iface)?;
            previous = Some(iface);
        }
        if let IpAddr::V4(ip) = prefix.sample() {
            if prefix.is_host() {
                rows.serialize_element(&u32::from(ip))?;
                continue;
            }
        }
        rows.serialize_element(prefix)?;
    }
    rows.end()
}

enum Token {
    Interface(String),
    Network(Prefix),
}
impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Read;
        impl Visitor<'_> for Read {
            type Value = Token;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an AWG interface, a network or an unsigned IPv4 host")
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Token, E> {
                let ip = u32::try_from(n).map_err(E::custom)?;
                Ok(Token::Network(Prefix::host(Ipv4Addr::from(ip))))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Token, E> {
                if iface_ok(s) {
                    Ok(Token::Interface(s.to_owned()))
                } else {
                    s.parse().map(Token::Network).map_err(E::custom)
                }
            }
        }
        deserializer.deserialize_any(Read)
    }
}

pub(in crate::kernel) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<Prefix, String>, D::Error> {
    struct Read;
    impl<'de> Visitor<'de> for Read {
        type Value = BTreeMap<Prefix, String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a prefix stream or legacy route map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut routes = BTreeMap::new();
            while let Some((prefix, iface)) = map.next_entry::<Prefix, String>()? {
                if routes.len() == packed::LIMIT
                    || !iface_ok(&iface)
                    || routes.insert(prefix, iface).is_some()
                {
                    return Err(de::Error::custom("invalid or repeated route prefix"));
                }
            }
            Ok(routes)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut routes = BTreeMap::new();
            let mut iface = None;
            let mut needs_network = false;
            while let Some(token) = seq.next_element()? {
                match token {
                    Token::Interface(name) => {
                        if needs_network || iface.as_ref() == Some(&name) {
                            return Err(de::Error::custom("empty or repeated route run"));
                        }
                        iface = Some(name);
                        needs_network = true;
                    }
                    Token::Network(prefix) => {
                        let name = iface
                            .as_ref()
                            .ok_or_else(|| de::Error::custom("missing route interface"))?;
                        if routes.len() == packed::LIMIT
                            || routes
                                .last_key_value()
                                .is_some_and(|(last, _)| *last >= prefix)
                        {
                            return Err(de::Error::custom(
                                "excessive, unordered or repeated route prefixes",
                            ));
                        }
                        routes.insert(prefix, name.clone());
                        needs_network = false;
                    }
                }
            }
            if needs_network {
                return Err(de::Error::custom("unfinished route run"));
            }
            Ok(routes)
        }
    }
    deserializer.deserialize_any(Read)
}
