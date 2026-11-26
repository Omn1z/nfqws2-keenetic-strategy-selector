use super::{arguments, process, Kind, Query};
use std::io::{self, Cursor};

fn varint(mut n: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while n >= 128 {
        bytes.push(n as u8 | 128);
        n >>= 7;
    }
    bytes.push(n as u8);
    bytes
}

fn field(key: u8, bytes: &[u8]) -> Vec<u8> {
    [&[key], varint(bytes.len() as u64).as_slice(), bytes].concat()
}

fn domain(kind: u8, name: &str) -> Vec<u8> {
    field(18, &[&[8, kind][..], &field(18, name.as_bytes())].concat())
}

fn run(bytes: &[u8], kind: Kind, query: Query) -> io::Result<Option<String>> {
    let mut out = Vec::new();
    let found = process(
        Cursor::new(bytes),
        bytes.len() as u64,
        kind,
        query,
        &mut out,
    )?;
    Ok(found.then(|| String::from_utf8(out).unwrap()))
}

fn extract(category: &str, limit: u64) -> Query {
    Query::Extract {
        category: category.into(),
        limit,
    }
}

#[test]
fn geosite_preserves_order_and_merges_case_insensitive_categories() {
    let records = [
        field(
            10,
            &[domain(0, "literal"), domain(1, "regex"), field(10, b"B")].concat(),
        ),
        field(
            10,
            &[field(10, b"A"), domain(3, ""), domain(1, "excluded")].concat(),
        ),
        field(
            10,
            &[field(10, b"b"), domain(2, "literal"), domain(3, "full")].concat(),
        ),
        field(10, &domain(0, "nameless")),
    ]
    .concat();
    assert_eq!(
        run(&records, Kind::Site, Query::List).unwrap().unwrap(),
        "[{\"name\":\"a\",\"count\":0},{\"name\":\"b\",\"count\":3}]\n"
    );
    assert_eq!(
        run(&records, Kind::Site, extract("B", 0)).unwrap().unwrap(),
        "[\"literal\",\"literal\",\"full\"]\n"
    );
    assert_eq!(
        run(&records, Kind::Site, extract("b", 2)).unwrap().unwrap(),
        "[\"literal\",\"literal\"]\n"
    );
    assert_eq!(
        run(&records, Kind::Site, extract("a", 0)).unwrap().unwrap(),
        "[]\n"
    );
    assert_eq!(
        run(&records, Kind::Site, extract("absent", 0)).unwrap(),
        None
    );
}

#[test]
fn geoip_matches_go_host_prefix_and_ipnet_formatting() {
    let cidr = |addr: &[u8], prefix: u8| field(18, &[field(10, addr), vec![16, prefix]].concat());
    let mut mapped = [0u8; 16];
    mapped[10..].copy_from_slice(&[255, 255, 192, 0, 2, 3]);
    let mut v6 = [0u8; 16];
    v6[15] = 1;
    let records = field(
        10,
        &[
            field(10, b"NET"),
            cidr(&[192, 0, 2, 15], 24),
            cidr(&[1, 2, 3, 4], 0),
            cidr(&[1, 2], 8),
            cidr(&[1, 2, 3, 4], 33),
            cidr(&v6, 64),
            cidr(&mapped, 120),
            cidr(&mapped, 64),
        ]
        .concat(),
    );
    assert_eq!(run(&records, Kind::Ip, extract("net",0)).unwrap().unwrap(),
        "[\"192.0.2.15/24\",\"1.2.3.4/32\",\"1.2.3.4/32\",\"::1/64\",\"192.0.2.3/24\",\"192.0.2.3/0\"]\n");
    assert_eq!(
        run(&records, Kind::Ip, Query::List).unwrap().unwrap(),
        "[{\"name\":\"net\",\"count\":6}]\n"
    );
}

#[test]
fn text_handles_empty_files_comments_whitespace_and_json_escaping() {
    let data = " \n # skipped\r\nbücher.example \n \"x\\y\tz\"\n";
    assert_eq!(
        run(data.as_bytes(), Kind::Text, extract("ALL", 0))
            .unwrap()
            .unwrap(),
        "[\"bücher.example\",\"\\\"x\\\\y\\u0009z\\\"\"]\n"
    );
    assert_eq!(
        run(b"", Kind::Text, Query::List).unwrap().unwrap(),
        "[{\"name\":\"all\",\"count\":0}]\n"
    );
    assert_eq!(
        run(b"foo", Kind::Text, extract("all", 1)).unwrap().unwrap(),
        "[\"foo\"]\n"
    );
    assert_eq!(
        run(b"foo", Kind::Text, extract("missing", 0)).unwrap(),
        None
    );
}

#[test]
fn unknown_fields_are_skipped_and_escaped_category_names_are_valid_json() {
    let mut records = vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0];
    records.extend(field(26, b"ignored"));
    records.extend(field(
        10,
        &[field(10, b"a\nb"), vec![40, 20], domain(0, "test")].concat(),
    ));
    assert_eq!(
        run(&records, Kind::Site, Query::List).unwrap().unwrap(),
        "[{\"name\":\"a\\u000ab\",\"count\":1}]\n"
    );
}

#[test]
fn rejects_overflow_truncation_invalid_wire_and_oversized_fields() {
    for input in [
        vec![128; 11],
        vec![0],
        vec![10, 128],
        vec![10, 3, 8, 0],
        vec![10, 2, 10, 2],
        vec![29, 1, 2],
        vec![15],
        vec![10, 1, 128],
    ] {
        assert!(run(&input, Kind::Site, Query::List).is_err(), "{input:?}");
    }
    let large = vec![b'x'; 1024 * 1024 + 1];
    let data = field(10, &field(10, &large));
    assert!(run(&data, Kind::Site, Query::List).is_err());
    assert!(run(&large, Kind::Text, Query::List).is_err());
}

#[test]
fn validates_cli_arguments() {
    for args in [
        vec!["list", "text"],
        vec!["list", "geoip", "file", "extra"],
        vec!["extract", "unknown", "f", "cat"],
        vec!["extract", "geoip", "f", "cat", "-1"],
        vec!["extract", "geoip", "f", "cat", "1", "extra"],
    ] {
        let args: Vec<_> = args.into_iter().map(Into::into).collect();
        assert!(arguments(&args).is_none());
    }
}

#[test]
fn checked_extract_distinguishes_missing_empty_and_truncated_snapshots() {
    let sample = field(
        10,
        &[
            field(10, b"G"),
            domain(3, "a.example"),
            domain(3, "b.example"),
        ]
        .concat(),
    );
    let checked = |key: &str, limit| Query::ExtractChecked {
        category: key.into(),
        limit,
    };
    assert!(run(&sample, Kind::Site, checked("g", 1)).is_err());
    assert_eq!(
        run(&sample, Kind::Site, checked("g", 2)).unwrap().unwrap(),
        "[\"a.example\",\"b.example\"]\n"
    );
    assert_eq!(
        run(&sample, Kind::Site, checked("missing", 1)).unwrap(),
        None
    );
    assert!(run(&[], Kind::Site, checked("missing", 1)).is_err());
    assert!(run(&[10, 128], Kind::Site, checked("missing", 1)).is_err());
    let args = ["extract-checked", "geosite", "file", "g", "1"].map(Into::into);
    assert!(matches!(
        arguments(&args),
        Some((Kind::Site, _, Query::ExtractChecked { limit: 1, .. }))
    ));
}
