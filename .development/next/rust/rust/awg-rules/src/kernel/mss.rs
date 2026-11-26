use super::{
    err,
    inventory::{Kernel, Object, TAG},
    plan::{iface_ok, Family, MAX_TARGETS},
};
use serde::de::{self, MapAccess, Visitor};
use serde::Deserializer;
use std::collections::{BTreeMap, BTreeSet};
use std::{fmt, io};

pub(super) fn read_map<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, u16>, D::Error> {
    struct Links;
    impl<'de> Visitor<'de> for Links {
        type Value = BTreeMap<String, u16>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("one effective MSS per AWG interface")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            let mut links = BTreeMap::new();
            while let Some(iface) = m.next_key::<String>()? {
                if links.len() >= MAX_TARGETS || !iface_ok(&iface) || links.contains_key(&iface) {
                    return Err(de::Error::custom("invalid MSS interface"));
                }
                links.insert(iface, m.next_value()?);
            }
            Ok(links)
        }
    }
    d.deserialize_map(Links)
}

/// An xtables backend can exit successfully even when another writer has
/// already replaced the mangle table. Read back both sides of the handshake
/// before withdrawing the old generation, in one listing per changed family.
pub(super) fn verify_additions(
    k: &Kernel<'_>,
    before: &BTreeSet<Object>,
    after: &BTreeSet<Object>,
) -> io::Result<()> {
    let mut expected = BTreeMap::<Family, BTreeSet<String>>::new();
    for obj in after.difference(before).filter(|o| o.fixed_mss()) {
        let (_, chain, spec) = obj.xtables().expect("physical MSS rule");
        expected
            .entry(obj.family())
            .or_default()
            .insert(format!("-A {chain} {}", spec.join(" ")));
    }
    for (family, mut missing) in expected {
        for line in k
            .call(family.firewall(), &["-w", "-t", "mangle", "-S"])?
            .lines()
        {
            if line.contains(TAG) && line.contains("--set-mss") {
                missing.remove(&line.replace(&format!("\"{TAG}\""), TAG));
            }
        }
        if !missing.is_empty() {
            return Err(err("ядро не подтвердило новые правила MSS туннеля"));
        }
    }
    Ok(())
}
