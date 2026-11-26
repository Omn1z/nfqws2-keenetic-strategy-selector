use std::borrow::Cow;
use std::io;
use std::ops::Range;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

const BEGIN: &str = "# BEGIN N2S SERVICE STRATEGIES";
const END: &str = "# END N2S SERVICE STRATEGIES";
const SERVICE_TAIL: &str = "${NFQWS_ARGS_CUSTOM:+ --new }${NFQWS_ARGS_CUSTOM}\"";

fn space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r')
}
fn name_char(b: u8, first: bool) -> bool {
    b == b'_' || b.is_ascii_alphabetic() || (!first && b.is_ascii_digit())
}

// During marker detection, quoted and multiline statements are opaque. During
// literal parsing, only simple variable references are allowed outside single quotes.
fn statement_end(source: &[u8], start: usize, strict: bool) -> Option<usize> {
    let mut pos = start;
    let mut quote = 0;
    while pos < source.len() {
        let b = source[pos];
        if b == b'\\' && quote != b'\'' {
            if strict && pos + 1 == source.len() {
                return None;
            }
            pos += 2;
            continue;
        }
        if strict && quote != b'\'' {
            if b == b'`' || (b == b'$' && matches!(source.get(pos + 1), Some(b'(' | b'\''))) {
                return None;
            }
            if b == b'$' && source.get(pos + 1) == Some(&b'{') {
                let first = pos + 2;
                pos = first;
                while pos < source.len() && name_char(source[pos], pos == first) {
                    pos += 1;
                }
                if pos == first || source.get(pos) != Some(&b'}') {
                    return None;
                }
                pos += 1;
                continue;
            }
        }
        if quote != 0 {
            if b == quote {
                quote = 0;
            }
        } else if matches!(b, b'\'' | b'"' | b'`') {
            quote = b;
        } else if b == b'#' && (pos == start || space(source[pos - 1])) {
            return Some(
                source[pos..]
                    .iter()
                    .position(|&ch| ch == b'\n')
                    .map_or(source.len(), |i| pos + i),
            );
        } else if b == b'\n' {
            return Some(pos);
        }
        pos += 1;
    }
    (!strict || quote == 0).then_some(source.len())
}

fn service_key(line: &str) -> Option<usize> {
    if let Some(value) = line
        .strip_prefix("NFQWS_ARGS_CUSTOM=\"")?
        .strip_suffix(SERVICE_TAIL)
    {
        let mut bytes = value.bytes();
        while let Some(b) = bytes.next() {
            match b {
                b'\\' if matches!(bytes.next(), Some(b'\\' | b'"' | b'$' | b'`')) => (),
                b'\\' | b'$' | b'`' | b'"' | b'\r' | b'\n' => return None,
                _ => (),
            }
        }
        return Some(0);
    }
    None
}

fn port_key(line: &str) -> Option<usize> {
    let (key, value) = line.split_once('=')?;
    let index = match key {
        "TCP_PORTS" => 1,
        "UDP_PORTS" => 2,
        _ => return None,
    };
    let value = match value.as_bytes().first() {
        Some(&q @ (b'\'' | b'"')) => value[1..].strip_suffix(q as char)?,
        _ => value,
    };
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b',' | b':'))
        .then_some(index)
}

pub fn managed_service_config_range(source: &str) -> io::Result<Option<Range<usize>>> {
    let malformed = || {
        invalid("некорректный управляемый блок сервисных стратегий: используйте полный редактор конфига")
    };
    let mut start = 0;
    let mut begin = None;
    let mut range = None;
    let mut seen = [false; 3];
    while start < source.len() {
        let end = statement_end(source.as_bytes(), start, false).unwrap_or(source.len());
        let line = source[start..end]
            .strip_suffix('\r')
            .unwrap_or(&source[start..end]);
        let next = if end == source.len() { end } else { end + 1 };
        match line.trim() {
            BEGIN => {
                if line != BEGIN || begin.is_some() || range.is_some() {
                    return Err(malformed());
                }
                begin = Some(start);
            }
            END => {
                if line != END || !seen[0] {
                    return Err(malformed());
                }
                range = Some(begin.take().ok_or_else(malformed)?..next);
            }
            "" => (),
            text if text.starts_with('#') => (),
            _ if begin.is_some() => {
                let idx = port_key(line)
                    .or_else(|| service_key(line))
                    .ok_or_else(malformed)?;
                if seen[idx] {
                    return Err(malformed());
                }
                seen[idx] = true;
            }
            _ if range.is_some() => return Err(malformed()),
            _ => (),
        }
        start = next;
    }
    if begin.is_some() {
        return Err(malformed());
    }
    Ok(range)
}

struct Assignment {
    range: Range<usize>,
    value: String,
    quote: Option<char>,
    literal: bool,
}

fn assignment_value(
    source: &[u8],
    from: usize,
    end: usize,
    keep: bool,
) -> Result<Option<Assignment>, ()> {
    let mut pos = from;
    let mut quote = 0;
    let mut value = Vec::new();
    let mut literal = true;
    while pos < end {
        let b = source[pos];
        if quote == 0 && (space(b) || b";|&<>()".contains(&b)) {
            break;
        }
        if b == b'\\' && quote != b'\'' {
            let &next = source.get(pos + 1).filter(|_| pos + 1 < end).ok_or(())?;
            if quote == b'"' && !b"$`\"\\\n".contains(&next) {
                if keep {
                    value.push(b);
                }
                pos += 1;
                continue;
            }
            if keep && next != b'\n' {
                value.push(next);
            }
            pos += 2;
            continue;
        }
        if quote == 0 && matches!(b, b'\'' | b'"') {
            quote = b;
        } else if quote != 0 && b == quote {
            quote = 0;
        } else {
            if (quote != b'\'' && b == b'$')
                || (quote == 0 && b == b'~' && (pos == from || source[pos - 1] == b':'))
            {
                literal = false;
            }
            if keep {
                value.push(b);
            }
        }
        pos += 1;
    }
    let to = pos;
    while pos < end && space(source[pos]) {
        pos += 1;
    }
    if quote != 0 || (pos != end && source[pos] != b'#') {
        return Err(());
    }
    let item = keep.then(|| Assignment {
        range: from..to,
        value: String::from_utf8(value).expect("removing ASCII quote characters preserves UTF-8"),
        quote: (to >= from + 2
            && matches!(source[from], b'\'' | b'"')
            && source[to - 1] == source[from])
            .then(|| source[from] as char),
        literal,
    });
    Ok(item)
}

fn assignments(source: &str, key: &str) -> io::Result<Option<Vec<Assignment>>> {
    let managed = managed_service_config_range(source)?;
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    while start < source.len() {
        if let Some(range) = managed.as_ref().filter(|r| r.start == start) {
            start = range.end;
            continue;
        }
        let Some(end) = statement_end(bytes, start, true) else {
            return Ok(None);
        };
        let mut pos = start;
        start = end + 1;
        while pos < end && space(bytes[pos]) {
            pos += 1;
        }
        if pos == end || bytes[pos] == b'#' {
            continue;
        }
        if source[pos..end].starts_with("export") && pos + 6 < end && space(bytes[pos + 6]) {
            pos += 6;
            while pos < end && space(bytes[pos]) {
                pos += 1;
            }
        }
        let key_start = pos;
        while pos < end && name_char(bytes[pos], pos == key_start) {
            pos += 1;
        }
        if key_start == pos || pos == end || bytes[pos] != b'=' {
            return Ok(None);
        }
        let keep = &source[key_start..pos] == key;
        let Ok(item) = assignment_value(bytes, pos + 1, end, keep) else {
            return Ok(None);
        };
        if let Some(item) = item {
            out.push(item);
        }
    }
    Ok(Some(out))
}

pub fn literal_shell_config_value(source: &str, key: &str) -> io::Result<Option<String>> {
    let mut items = assignments(source, key)?.ok_or_else(|| {
        invalid(format!(
            "{key}: конфиг содержит shell-команды или сложные выражения"
        ))
    })?;
    match items.pop() {
        None => Ok(None),
        Some(item) if item.literal => Ok(Some(item.value)),
        Some(_) => Err(invalid(format!(
            "{key}: для автоматического объединения портов укажите буквальное значение"
        ))),
    }
}

pub fn replace_nfqws_args(source: &str, args: &str) -> io::Result<String> {
    if args.len() > 1 << 20
        || args
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err(invalid("некорректные аргументы NFQWS2"));
    }
    let entries = assignments(source, "NFQWS_ARGS")?
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid("не найдено отдельное присваивание NFQWS_ARGS"))?;
    let mut quoted = String::from("\"");
    for c in args.chars() {
        if matches!(c, '\\' | '"' | '$' | '\x60') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    let mut text = String::new();
    let mut end = 0;
    for entry in entries {
        text.push_str(&source[end..entry.range.start]);
        text.push_str(&quoted);
        end = entry.range.end;
    }
    text.push_str(&source[end..]);
    Ok(normalize_wan_interfaces(&text)?.into_owned())
}

fn split_wan(value: &str) -> io::Result<Vec<String>> {
    let mut items = Vec::new();
    for token in value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        if token.len() > 15 {
            return Err(invalid(format!("ISP_INTERFACE: имя интерфейса {token:?} длиннее 15 байт; разделяйте интерфейсы пробелом или запятой")));
        }
        let name = token.strip_suffix('+').unwrap_or(token);
        if matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(invalid(format!(
                "ISP_INTERFACE: недопустимое имя интерфейса {token:?}"
            )));
        }
        if !items.iter().any(|s| s == token) {
            items.push(token.to_owned());
        }
    }
    Ok(items)
}

pub fn wan_interfaces_from_conf(source: &str) -> io::Result<Option<Vec<String>>> {
    let mut selected = None;
    if let Some(items) = assignments(source, "ISP_INTERFACE")? {
        for item in items {
            selected = if item.literal {
                Some(split_wan(&item.value)?)
            } else {
                None
            };
        }
    }
    Ok(selected)
}

pub fn normalize_wan_interfaces(source: &str) -> io::Result<Cow<'_, str>> {
    let Some(items) = assignments(source, "ISP_INTERFACE")? else {
        return Ok(Cow::Borrowed(source));
    };
    let mut out = String::new();
    let mut pos = 0;
    for item in items.into_iter().filter(|s| s.literal) {
        let value = split_wan(&item.value)?.join(" ");
        if value == item.value {
            continue;
        }
        out.push_str(&source[pos..item.range.start]);
        let quote = item.quote.or_else(|| value.contains(' ').then_some('"'));
        if let Some(q) = quote {
            out.push(q);
        }
        out.push_str(&value);
        if let Some(q) = quote {
            out.push(q);
        }
        pos = item.range.end;
    }
    if pos == 0 {
        return Ok(Cow::Borrowed(source));
    }
    out.push_str(&source[pos..]);
    Ok(Cow::Owned(out))
}
