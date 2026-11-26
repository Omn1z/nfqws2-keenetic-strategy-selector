use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Vendor {
    pub id: &'static str,
    pub name: &'static str,
    pub prefixes: &'static [&'static str],
}
const fn group(id: &'static str, name: &'static str, prefixes: &'static [&'static str]) -> Vendor {
    Vendor { id, name, prefixes }
}
pub(super) const CATALOG: &[Vendor] = &[
    group("iskratel", "Iskratel", &["64:6E:EA"]),
    group(
        "rostelecom",
        "Rostelecom CPE",
        &["F8:8C:21", "D8:D7:75", "E8:65:D4"],
    ),
    group("zyxel", "Zyxel", &["00:13:49", "00:19:CB", "FC:F5:28"]),
    group(
        "huawei",
        "Huawei",
        &["00:18:82", "00:1E:10", "28:6E:D4", "A4:C6:4F"],
    ),
    group(
        "asus",
        "ASUS",
        &["00:1B:FC", "04:92:26", "2C:56:DC", "AC:22:0B"],
    ),
    group(
        "xiaomi",
        "Xiaomi",
        &["50:8F:4C", "64:09:80", "74:23:44", "D4:97:0B"],
    ),
    group(
        "tp-link",
        "TP-Link",
        &["14:CC:20", "50:C7:BF", "98:DA:C4", "C0:25:E9"],
    ),
    group(
        "d-link",
        "D-Link",
        &["00:05:5D", "1C:7E:E5", "84:C9:B2", "C4:A8:1D"],
    ),
    group("zte", "ZTE", &["00:19:C6", "34:4B:50", "E8:BD:D1"]),
    group(
        "sagemcom",
        "Sagemcom",
        &["00:1D:19", "60:35:C0", "A0:1B:29"],
    ),
    group("sercomm", "Sercomm", &["00:1D:AA", "20:0C:C8", "7C:03:D8"]),
    group("netgear", "NETGEAR", &["00:14:6C", "20:4E:7F", "A0:40:A0"]),
    group("custom", "Custom", &[]),
];
pub(super) fn first(id: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|v| v.id == id)?
        .prefixes
        .first()
        .copied()
}
pub(super) fn matches(id: &str, prefix: &str) -> bool {
    CATALOG
        .iter()
        .any(|v| v.id == id && v.prefixes.contains(&prefix))
}
