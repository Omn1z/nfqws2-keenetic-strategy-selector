use crate::wire::{invalid, Reader, Value, MAX_STRING};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Site,
    Ip,
    Text,
}

pub enum Query {
    List,
    Extract {
        category: String,
        limit: u64,
    },
    /// For complete portable snapshots, reject empty databases and oversized categories.
    ExtractChecked {
        category: String,
        limit: u64,
    },
}

pub enum Entry<'a> {
    Text(&'a str),
    Network(IpAddr, u64),
}

fn utf8(bytes: &[u8]) -> io::Result<&str> {
    str::from_utf8(bytes).map_err(|_| invalid("invalid UTF-8 in geo file"))
}

fn json_string(out: &mut impl Write, value: &str) -> io::Result<()> {
    out.write_all(b"\"")?;
    let bytes = value.as_bytes();
    let mut start = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if matches!(byte, b'"' | b'\\' | 0..=31) {
            out.write_all(&bytes[start..i])?;
            match byte {
                b'"' | b'\\' => out.write_all(&[b'\\', byte])?,
                _ => write!(out, "\\u{byte:04x}")?,
            }
            start = i + 1;
        }
    }
    out.write_all(&bytes[start..])?;
    out.write_all(b"\"")
}

fn read_entry<'a, R: Read + Seek>(
    wire: &mut Reader<R>,
    end: u64,
    kind: Kind,
    scratch: &'a mut Vec<u8>,
) -> io::Result<Option<Entry<'a>>> {
    let mut number = 0;
    scratch.clear();
    wire.walk(end, |wire, field, value| {
        match (kind, field, value) {
            (Kind::Site, 1, Value::Number(n)) | (Kind::Ip, 2, Value::Number(n)) => number = n,
            (Kind::Site, 2, Value::Bytes { end }) => wire.bytes(end, scratch)?,
            (Kind::Ip, 1, Value::Bytes { end }) => {
                if matches!(end - wire.pos, 4 | 16) {
                    wire.bytes(end, scratch)?;
                } else {
                    scratch.clear();
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    if kind == Kind::Site {
        return if scratch.is_empty() || number == 1 {
            Ok(None)
        } else {
            Ok(Some(Entry::Text(utf8(scratch)?)))
        };
    }
    let (ip, bits) = match scratch.as_slice() {
        [a, b, c, d] => (IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)), 32),
        bytes if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().expect("length checked");
            (IpAddr::V6(Ipv6Addr::from(octets)), 128)
        }
        _ => return Ok(None),
    };
    // The Go importer treats an absent/zero or invalid prefix as a host.
    let prefix = if number == 0 || number > bits {
        bits
    } else {
        number
    };
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return Ok(Some(Entry::Network(
                IpAddr::V4(v4),
                prefix.saturating_sub(96),
            )));
        }
    }
    Ok(Some(Entry::Network(ip, prefix)))
}

fn category<R: Read + Seek>(
    wire: &mut Reader<R>,
    end: u64,
    mut visit: impl FnMut(&mut Reader<R>, u64) -> io::Result<()>,
) -> io::Result<String> {
    let mut name = Vec::new();
    wire.walk(end, |wire, field, value| {
        match (field, value) {
            (1, Value::Bytes { end }) => wire.bytes(end, &mut name)?,
            (2, Value::Bytes { end }) => visit(wire, end)?,
            _ => {}
        }
        Ok(())
    })?;
    Ok(utf8(&name)?.to_lowercase())
}

pub enum Scan {
    Categories(BTreeMap<String, u64>),
    Extracted(bool),
}

fn list(out: &mut impl Write, counts: BTreeMap<String, u64>) -> io::Result<()> {
    out.write_all(b"[")?;
    for (index, (name, count)) in counts.into_iter().enumerate() {
        if index != 0 {
            out.write_all(b",")?;
        }
        out.write_all(b"{\"name\":")?;
        json_string(out, &name)?;
        write!(out, ",\"count\":{count}}}")?;
    }
    out.write_all(b"]\n")
}

pub fn scan<R: Read + Seek>(
    input: R,
    length: u64,
    kind: Kind,
    query: Query,
    mut visit: impl FnMut(Entry<'_>) -> io::Result<()>,
) -> io::Result<Scan> {
    let mut counts = BTreeMap::new();
    let (target, limit, checked) = match query {
        Query::List => (None, 0, false),
        Query::Extract { category, limit } => (Some(category.to_lowercase()), limit, false),
        Query::ExtractChecked { category, limit } => (Some(category.to_lowercase()), limit, true),
    };
    let mut emitted = 0;
    let full = |emitted| limit != 0 && emitted >= limit;
    let mut deliver = |entry: Entry<'_>, emitted: &mut u64| -> io::Result<()> {
        if full(*emitted) {
            return Err(invalid("Geo category exceeds entry limit"));
        }
        visit(entry)?;
        *emitted += 1;
        Ok(())
    };
    let mut found = false;
    let mut scratch = Vec::new();
    if kind == Kind::Text {
        if target.as_deref().is_some_and(|name| name != "all") {
            return Ok(Scan::Extracted(false));
        }
        found = true;
        let mut reader = BufReader::new(input);
        let mut count = 0;
        while checked || !full(emitted) {
            scratch.clear();
            let n = (&mut reader)
                .take(MAX_STRING as u64 + 1)
                .read_until(b'\n', &mut scratch)?;
            if n == 0 {
                break;
            }
            if n > MAX_STRING {
                return Err(invalid("text list line exceeds 1 MiB"));
            }
            let line = utf8(&scratch)?.trim();
            if !line.is_empty() && !line.starts_with('#') {
                count += 1;
                if target.is_some() {
                    deliver(Entry::Text(line), &mut emitted)?;
                }
            }
        }
        if target.is_none() {
            counts.insert("all".into(), count);
        }
    } else {
        if length > i64::MAX as u64 {
            return Err(invalid("geo file too large to seek"));
        }
        let mut wire = Reader::new(input);
        let mut has_category = false;
        wire.walk(length, |wire, field, value| {
            let (1, Value::Bytes { end }) = (field, value) else {
                return Ok(());
            };
            if let Some(target) = target.as_ref() {
                if !checked && full(emitted) {
                    return Ok(());
                }
                // Protobuf permits the category name to appear after its entries.
                // Read names first, then revisit only a selected category's fields.
                let start = wire.pos;
                let name = category(wire, end, |_, _| Ok(()))?;
                has_category |= !name.is_empty();
                if !name.is_empty() && name == *target {
                    found = true;
                    wire.seek(start)?;
                    category(wire, end, |wire, end| {
                        if checked || !full(emitted) {
                            if let Some(value) = read_entry(wire, end, kind, &mut scratch)? {
                                deliver(value, &mut emitted)?;
                            }
                        }
                        Ok(())
                    })?;
                }
            } else {
                let mut count = 0;
                let name = category(wire, end, |wire, end| {
                    if read_entry(wire, end, kind, &mut scratch)?.is_some() {
                        count += 1;
                    }
                    Ok(())
                })?;
                if !name.is_empty() {
                    *counts.entry(name).or_default() += count;
                }
            }
            Ok(())
        })?;
        if checked && !has_category {
            return Err(invalid("Geo database contains no named categories"));
        }
    }
    Ok(if target.is_none() {
        Scan::Categories(counts)
    } else {
        Scan::Extracted(found)
    })
}

pub fn process<R: Read + Seek>(
    input: R,
    length: u64,
    kind: Kind,
    query: Query,
    out: &mut impl Write,
) -> io::Result<bool> {
    let mut started = false;
    let result = scan(input, length, kind, query, |entry| {
        out.write_all(if started { b"," } else { b"[" })?;
        started = true;
        match entry {
            Entry::Text(text) => json_string(out, text),
            Entry::Network(ip, prefix) => write!(out, "\"{ip}/{prefix}\""),
        }
    })?;
    match result {
        Scan::Categories(counts) => list(out, counts)?,
        Scan::Extracted(true) => out.write_all(if started { b"]\n" } else { b"[]\n" })?,
        Scan::Extracted(false) => return Ok(false),
    }
    Ok(true)
}
