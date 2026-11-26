fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (value, rest) = data.split_at_checked(n)?;
    *data = rest;
    Some(value)
}
fn vector_len(data: &mut &[u8], length_bytes: usize) -> Option<usize> {
    Some(
        take(data, length_bytes)?
            .iter()
            .fold(0usize, |n, &b| n * 256 + usize::from(b)),
    )
}
fn vector<'a>(data: &mut &'a [u8], length_bytes: usize) -> Option<&'a [u8]> {
    let n = vector_len(data, length_bytes)?;
    take(data, n)
}
pub fn server_name(record: &[u8]) -> Option<&str> {
    hello_server_name(record.get(9..)?, false)
}

/// Extract a complete server_name extension from the observed prefix of a
/// ClientHello. No bytes beyond either the first record or handshake count
/// toward the extension, even if they are present in the capture buffer.
pub fn server_name_prefix(record: &[u8]) -> Option<&str> {
    let header = record.get(..9)?;
    if header[..2] != [22, 3] || header[2] > 3 || header[5] != 1 {
        return None;
    }
    let record_end = 5 + usize::from(u16::from_be_bytes([header[3], header[4]]));
    let body_end = 9 + u32::from_be_bytes([0, header[6], header[7], header[8]]) as usize;
    let end = record.len().min(record_end).min(body_end);
    hello_server_name(record.get(9..end)?, true)
}

fn hello_server_name(mut hello: &[u8], prefix: bool) -> Option<&str> {
    take(&mut hello, 2 + 32)?;
    vector(&mut hello, 1)?;
    vector(&mut hello, 2)?;
    vector(&mut hello, 1)?;
    let n = vector_len(&mut hello, 2)?;
    let mut extensions = hello.get(..if prefix { n.min(hello.len()) } else { n })?;
    while !extensions.is_empty() {
        let kind = take(&mut extensions, 2)?;
        let mut ext = vector(&mut extensions, 2)?;
        if kind == [0, 0] {
            let mut names = vector(&mut ext, 2)?;
            while !names.is_empty() {
                let kind = take(&mut names, 1)?;
                let name = vector(&mut names, 2)?;
                if kind == [0] {
                    return std::str::from_utf8(name).ok();
                }
            }
        }
    }
    None
}
pub fn validate(data: &[u8]) -> (bool, String) {
    validate_record(data, data.len() as u64)
}
pub fn validate_record(data: &[u8], size: u64) -> (bool, String) {
    if data.len() < 9 {
        return (false, "слишком короткий для ClientHello".into());
    }
    if data[..2] != [0x16, 0x03] {
        return (false, "не TLS-запись (нет 16 03)".into());
    }
    let record = u64::from(u16::from_be_bytes([data[3], data[4]])) + 5;
    if record != size {
        return (false, format!("длина TLS-записи {record} ≠ размеру {size}"));
    }
    if data[5] != 1 {
        return (false, "не ClientHello (handshake-тип не 0x01)".into());
    }
    let handshake = u32::from_be_bytes([0, data[6], data[7], data[8]]);
    if u64::from(handshake) + 9 != size {
        return (false, "длина handshake не сходится с записью".into());
    }
    let detail = match server_name(data).filter(|s| !s.is_empty()) {
        None => "валидный ClientHello, но без SNI".to_owned(),
        Some(name) if size > 1500 => format!(
            "валидный ClientHello (SNI {name}), но крупный — фейк может не уместиться в пакет"
        ),
        Some(name) => format!("валидный ClientHello, SNI {name}"),
    };
    (true, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn declared_lengths_and_short_prefixes_are_checked_before_extensions() {
        let mut record = vec![22, 3, 1, 0, 45, 1, 0, 0, 41, 3, 3];
        record.resize(50, 0);
        assert!(validate(&record).0);
        assert_eq!(server_name(&record), None);
        for end in 0..record.len() {
            assert!(!validate(&record[..end]).0);
            assert_eq!(server_name(&record[..end]), None);
        }
        assert!(!validate_record(&record[..9], 100_000).0);
        record[8] += 1;
        assert!(!validate(&record).0);
    }

    #[test]
    fn prefix_requires_a_contained_sni_extension_but_not_a_trailing_extension() {
        let name = b"router.example";
        let mut extensions = vec![
            0,
            0,
            0,
            (5 + name.len()) as u8,
            0,
            (3 + name.len()) as u8,
            0,
            0,
            name.len() as u8,
        ];
        extensions.extend(name);
        let sni_start = 9 + 43;
        let sni_end = sni_start + extensions.len();
        extensions.extend([0, 21, 0, 6, 0, 0, 0, 0, 0, 0]);
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0, 0, extensions.len() as u8]);
        body.extend(extensions);
        let mut record = vec![
            22,
            3,
            1,
            0,
            (body.len() + 4) as u8,
            1,
            0,
            0,
            body.len() as u8,
        ];
        record.extend(body);
        let captured = &record[..sni_end];
        assert_eq!(server_name_prefix(captured), Some("router.example"));
        assert_eq!(server_name(captured), None);
        assert_eq!(server_name(&record), Some("router.example"));
        for truncated in 0..sni_end {
            assert_eq!(server_name_prefix(&record[..truncated]), None);
        }
        for (index, len) in [
            (4, sni_end - 6),
            (8, sni_end - 10),
            (sni_start + 3, 1),
            (sni_start + 8, name.len() + 1),
        ] {
            let mut malformed = record.clone();
            malformed[index] = len as u8;
            assert_eq!(server_name_prefix(&malformed), None);
        }
    }
}
