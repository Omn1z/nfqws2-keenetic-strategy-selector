//! Domain names share an arena; a common domain costs one eight-byte index row.
mod types;
use std::{
    collections::HashMap,
    io::{self, BufRead, Read},
};

pub(super) const LIMIT: usize = 8 << 20;
const LINE_LIMIT: usize = 16 * 1024;
const RULE_LIMIT: usize = 350_000;
const ALLOW: u8 = 1;
const IMPORTANT: u8 = 2;
const EXACT: u8 = 4;
const DISABLED: u8 = 8;
const HAS_TEXT: u8 = 16;
const WILDCARD: u8 = 32;
const ORIGINAL_CASE: u8 = 64;

#[derive(Clone, Copy)]
struct Entry {
    offset: u32,
    len: u8,
    flags: u8,
    types: u16,
}
const _: () = assert!(std::mem::size_of::<Entry>() == 8);

impl Entry {
    fn name(self, arena: &str) -> &str {
        let start = self.offset as usize;
        &arena[start..start + self.len as usize]
    }
    fn key(self, arena: &str) -> &str {
        let name = self.name(arena);
        if self.flags & WILDCARD != 0 {
            name.split_once('.').unwrap().1
        } else {
            name
        }
    }
    fn text(self, arena: &str) -> Option<&str> {
        if self.flags & HAS_TEXT == 0 {
            return None;
        }
        let end = self.offset as usize + self.len as usize;
        Some(arena[end..].split_once('\0').unwrap().0)
    }
    fn display(self, arena: &str) -> String {
        if let Some(original) = self.text(arena) {
            return original.to_owned();
        }
        format!("||{}^", self.name(arena))
    }
    fn identity(self, arena: &str) -> (u8, &str) {
        // urlfilter compares the original, case-sensitive pattern, whitelist
        // bit, and enabled options. Both rules already matched the query type.
        let pattern = if self.flags & (ORIGINAL_CASE | EXACT) == ORIGINAL_CASE {
            let prefix = if self.flags & ALLOW == 0 { 2 } else { 4 };
            let pos = self.offset as usize + self.len as usize + prefix;
            &arena[pos..pos + self.len as usize]
        } else {
            self.name(arena)
        };
        (self.flags & (ALLOW | IMPORTANT | EXACT), pattern)
    }
    fn matches_name(self, arena: &str, name: &str, key: &str) -> bool {
        if self.flags & WILDCARD == 0 {
            return self.flags & EXACT == 0 || key == name;
        }
        let Some(left) = name.strip_suffix(key).and_then(|s| s.strip_suffix('.')) else {
            return false;
        };
        let pattern = self.name(arena).split_once('.').unwrap().0;
        suffixes(left).any(|v| glob(pattern.as_bytes(), v.as_bytes()))
    }
    fn priority(self) -> u8 {
        if self.flags & EXACT != 0 {
            // The Go DNS engine consults hosts files only after all network rules.
            return 0;
        }
        1 + (self.flags & (IMPORTANT | ALLOW)) * 2 + u8::from(self.types != 0)
    }
}
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |n| n.split_once('.').map(|(_, s)| s))
}

struct Rule<'a> {
    name: &'a str,
    flags: u8,
    mask: Option<u128>,
}
impl<'a> Rule<'a> {
    fn parse(text: &'a str) -> Option<Self> {
        if text.contains('\0') {
            return None;
        }
        let mut flags = 0;
        let mut mask = None;
        let body = text
            .strip_prefix("@@")
            .inspect(|_| flags |= ALLOW)
            .unwrap_or(text);
        let name = if let Some(pattern) = body.strip_prefix("||") {
            let (domain, rest) = pattern.split_once('^')?;
            if !rest.is_empty() {
                flags |= HAS_TEXT;
                for opt in rest.strip_prefix('$')?.split(',') {
                    match opt {
                        "important" => flags |= IMPORTANT,
                        "badfilter" => flags |= DISABLED,
                        _ => mask = Some(types::parse(opt.strip_prefix("dnstype=")?)?),
                    }
                }
            }
            domain
        } else {
            let mut words = body.split('#').next()?.split_ascii_whitespace();
            if flags != 0 || !matches!(words.next(), Some("0.0.0.0" | "127.0.0.1" | "::" | "::1")) {
                return None;
            }
            let host = words.next()?;
            if words.next().is_some() {
                return None;
            }
            flags |= EXACT | HAS_TEXT;
            host
        };
        if name.is_empty() || name.len() > 253 {
            return None;
        }
        for (i, label) in name.split('.').enumerate() {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
            {
                return None;
            }
            for ch in label.bytes() {
                if ch == b'*' && i == 0 && flags & EXACT == 0 && name.contains('.') {
                    flags |= WILDCARD;
                } else if ch.is_ascii_uppercase() {
                    flags |= HAS_TEXT | ORIGINAL_CASE;
                } else if !ch.is_ascii_alphanumeric() && !matches!(ch, b'-' | b'_') {
                    return None;
                }
            }
        }
        Some(Self { name, flags, mask })
    }
}

#[derive(Default)]
pub(in crate::dnsserver) struct Index {
    names: String,
    rows: Vec<Entry>,
    wild: Vec<Entry>,
    badfilters: Vec<Entry>,
    masks: Vec<u128>,
    usable: usize,
    pub ignored: usize,
}
pub(in crate::dnsserver) enum Verdict {
    Allow,
    Block(String),
}
impl Index {
    pub fn read(mut reader: impl BufRead) -> io::Result<Self> {
        let mut out = Self::default();
        let mut line = Vec::new();
        let mut total = 0;
        let mut first = true;
        let mut by_mask = HashMap::new();
        loop {
            line.clear();
            let size = reader
                .by_ref()
                .take((LINE_LIMIT + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if size == 0 {
                break;
            }
            total += size;
            if total > LIMIT || size > LINE_LIMIT {
                return Err(io::Error::other("превышен размер списка или строки DNS"));
            }
            let text = std::str::from_utf8(&line)
                .map_err(io::Error::other)?
                .trim()
                .trim_start_matches('\u{feff}')
                .trim();
            if text.is_empty() {
                continue;
            }
            if first && text.starts_with('<') {
                return Err(io::Error::other("сервер вернул HTML вместо списка DNS"));
            }
            first = false;
            if text.starts_with(['!', '#', '[']) {
                continue;
            }
            let Some(rule) = Rule::parse(text) else {
                out.ignored += 1;
                continue;
            };
            if out.rows.len() + out.wild.len() + out.badfilters.len() == RULE_LIMIT {
                return Err(io::Error::other("слишком много правил в списке DNS"));
            }
            let types = if let Some(mask) = rule.mask {
                use std::collections::hash_map::Entry;
                match by_mask.entry(mask) {
                    Entry::Occupied(v) => *v.get(),
                    Entry::Vacant(v) => {
                        let id = u16::try_from(out.masks.len() + 1).map_err(|_| {
                            io::Error::other("слишком много различных условий dnstype")
                        })?;
                        out.masks.push(mask);
                        *v.insert(id)
                    }
                }
            } else {
                0
            };
            let row = Entry {
                offset: out.names.len() as u32,
                len: rule.name.len() as u8,
                flags: rule.flags,
                types,
            };
            if rule.flags & HAS_TEXT != 0 {
                out.names
                    .extend(rule.name.bytes().map(|ch| ch.to_ascii_lowercase() as char));
                out.names.push_str(text);
                out.names.push('\0');
            } else {
                out.names.push_str(rule.name);
            }
            if rule.flags & DISABLED != 0 {
                out.badfilters.push(row);
            } else if rule.flags & WILDCARD != 0 {
                out.wild.push(row);
            } else {
                out.rows.push(row);
            }
        }
        if first {
            return Err(io::Error::other("пустой список DNS"));
        }
        for table in [&mut out.rows, &mut out.wild, &mut out.badfilters] {
            let compare = |a: &Entry, b: &Entry| {
                a.key(&out.names)
                    .cmp(b.key(&out.names))
                    .then_with(|| a.identity(&out.names).cmp(&b.identity(&out.names)))
                    .then_with(|| a.types.cmp(&b.types))
            };
            table.sort_unstable_by(|a, b| compare(a, b).then_with(|| a.offset.cmp(&b.offset)));
            table.dedup_by(|a, b| compare(a, b).is_eq());
            if table
                .chunk_by(|a, b| a.key(&out.names) == b.key(&out.names))
                .any(|g| g.len() > 256)
            {
                return Err(io::Error::other("слишком много правил DNS у одного домена"));
            }
            table.shrink_to_fit();
        }
        out.names.shrink_to_fit();
        out.masks.shrink_to_fit();
        // Counts guard replacement of a last-known-good list. Duplicate rows,
        // standalone badfilters and fully disabled rules must not inflate it.
        let mask = |r: &Entry| {
            if r.types == 0 {
                u128::MAX
            } else {
                out.masks[usize::from(r.types) - 1]
            }
        };
        let mut disabled = HashMap::new();
        for r in &out.badfilters {
            *disabled.entry(r.identity(&out.names)).or_insert(0) |= mask(r);
        }
        out.usable = out
            .rows
            .iter()
            .chain(&out.wild)
            .filter(|r| mask(r) & !disabled.get(&r.identity(&out.names)).copied().unwrap_or(0) != 0)
            .count();
        Ok(out)
    }
    pub fn len(&self) -> usize {
        self.usable
    }
    fn matches(&self, table: &[Entry], name: &str, bit: u128, mut visit: impl FnMut(Entry)) {
        if table.is_empty() {
            return;
        }
        for key in suffixes(name) {
            let start = table.partition_point(|r| r.key(&self.names) < key);
            for &r in table[start..]
                .iter()
                .take_while(|r| r.key(&self.names) == key)
            {
                if (r.types == 0 || self.masks[usize::from(r.types) - 1] & bit != 0)
                    && r.matches_name(&self.names, name, key)
                {
                    visit(r);
                }
            }
        }
    }
    pub fn lookup(&self, name: &str, kind: u16) -> Option<Verdict> {
        let bit = if self.masks.is_empty() {
            0
        } else {
            types::query_bit(kind)
        };
        let mut disabled = None;
        let mut distinct = false;
        self.matches(&self.badfilters, name, bit, |r| {
            let key = r.identity(&self.names);
            distinct |= disabled.is_some_and(|prev| prev != key);
            disabled = Some(key);
        });
        // v0.23.4 forms a union of the rules surviving each matching badfilter.
        // Different badfilter identities therefore cannot jointly remove a rule.
        let mut best: Option<Entry> = None;
        let mut consider = |r: Entry| {
            if !distinct && disabled.is_some_and(|id| id == r.identity(&self.names)) {
                return;
            }
            if best.is_none_or(|prior| r.priority() > prior.priority()) {
                best = Some(r);
            }
        };
        self.matches(&self.rows, name, bit, &mut consider);
        self.matches(&self.wild, name, bit, consider);
        best.map(|r| {
            if r.flags & ALLOW != 0 {
                Verdict::Allow
            } else {
                Verdict::Block(r.display(&self.names))
            }
        })
    }
}
fn glob(p: &[u8], s: &[u8]) -> bool {
    let (mut i, mut j, mut last, mut next) = (0, 0, None, 0);
    while j < s.len() {
        if p.get(i) == Some(&b'*') {
            last = Some(i);
            i += 1;
            next = j;
        } else if p.get(i) == s.get(j) {
            i += 1;
            j += 1;
        } else if let Some(star) = last {
            next += 1;
            j = next;
            i = star + 1;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == b'*')
}
