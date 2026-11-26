use super::err;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
};

#[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct OptionValue {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}
pub(crate) type Options = BTreeMap<String, OptionValue>;
impl OptionValue {
    pub fn scalar(v: &str) -> Self {
        Self {
            kind: "option".into(),
            values: vec![v.into()],
        }
    }
    pub fn list(v: Vec<String>) -> Self {
        Self {
            kind: "list".into(),
            values: v,
        }
    }
    pub fn valid(&self) -> bool {
        (match self.kind.as_str() {
            "" => self.values.is_empty(),
            "option" => self.values.len() == 1,
            "list" => !self.values.is_empty(),
            _ => false,
        }) && self.values.len() <= 256
            && self
                .values
                .iter()
                .all(|v| v.len() <= 4096 && !v.contains(['\0', '\n', '\r']))
    }
    pub fn prefix_of(&self, want: &Self) -> bool {
        self.kind == "list" && want.kind == "list" && want.values.starts_with(&self.values)
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Section {
    pub id: String,
    pub kind: String,
    pub options: Options,
}
impl Section {
    pub fn scalar(&self, k: &str) -> &str {
        self.options
            .get(k)
            .and_then(|v| v.values.first())
            .map_or("", |v| v.as_str())
    }
    pub fn enabled(&self) -> bool {
        !matches!(
            self.scalar("disabled"),
            "1" | "on" | "true" | "yes" | "enabled"
        ) && self.scalar("port") != "0"
    }
    pub fn values(&self, k: &str) -> Vec<String> {
        self.options
            .get(k)
            .map(|v| v.values.clone())
            .unwrap_or_default()
    }
}
pub(crate) fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub(crate) fn valid_instance(s: &str) -> bool {
    if valid_id(s) {
        return true;
    }
    s.strip_prefix("@dnsmasq[")
        .and_then(|v| v.strip_suffix(']'))
        .is_some_and(|v| {
            v.parse::<u16>()
                .is_ok_and(|i| i < 1024 && i.to_string() == v)
        })
}
pub(crate) fn conditional(s: &str) -> bool {
    s.strip_prefix('/')
        .and_then(|tail| tail.rsplit_once('/'))
        .is_some_and(|(domains, _)| !domains.split('/').any(|v| v == "#"))
}
pub(crate) struct Configuration {
    pub sections: Vec<Section>,
    pub digest: [u8; 32],
}
impl Configuration {
    pub fn find(&self, id: &str, kind: &str) -> io::Result<&Section> {
        self.sections
            .iter()
            .find(|s| s.kind == kind && s.id == id)
            .ok_or_else(|| err(format!("UCI section {id} ({kind}) not found")))
    }
    pub fn parse(raw: &str, pkg: &str) -> io::Result<Self> {
        if raw.len() > 4 << 20 {
            return Err(err("UCI export exceeds 4 MiB"));
        }
        let mut sections: Vec<Section> = Vec::new();
        let mut seen = HashSet::new();
        let mut ordinals = HashMap::new();
        for line in raw.split('\n') {
            let words = words(line)?;
            let get = |i: usize| words.get(i).map_or("", String::as_str);
            match (get(0), words.len()) {
                (_, 0) => (),
                ("package", 2) if get(1) == pkg => (),
                ("config", 2 | 3) if valid_id(get(1)) => {
                    let kind = get(1);
                    let ordinal = ordinals.entry(kind.to_owned()).or_insert(0usize);
                    let id = if words.len() == 2 {
                        format!("@{kind}[{ordinal}]")
                    } else if valid_id(get(2)) {
                        get(2).into()
                    } else {
                        return Err(err("invalid UCI section name"));
                    };
                    *ordinal += 1;
                    if !seen.insert(id.clone()) {
                        return Err(err("duplicate UCI section"));
                    }
                    sections.push(Section {
                        id,
                        kind: kind.into(),
                        options: Options::new(),
                    });
                }
                ("option" | "list", 3) if valid_id(get(1)) => {
                    let section = sections
                        .last_mut()
                        .ok_or_else(|| err("UCI option outside section"))?;
                    let option = section.options.entry(get(1).to_owned()).or_default();
                    if !option.kind.is_empty() && !(get(0) == "list" && option.kind == "list") {
                        return Err(err("duplicate or mixed UCI option"));
                    }
                    option.kind = get(0).into();
                    option.values.push(get(2).into());
                }
                _ => return Err(err("invalid UCI export")),
            }
        }
        Ok(Self {
            sections,
            digest: Sha256::digest(raw.as_bytes()).into(),
        })
    }
}
fn words(line: &str) -> io::Result<Vec<String>> {
    let (mut quote, mut escaped, mut started) = (None, false, false);
    let mut word = String::new();
    let mut words = Vec::new();
    for c in line.chars() {
        if matches!(c, '\0' | '\r') {
            return Err(err("invalid UCI text"));
        }
        if escaped {
            word.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
            continue;
        }
        if let Some(q) = quote {
            if q == c {
                quote = None;
            } else {
                word.push(c);
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if c == '#' && !started {
            break;
        } else if c.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(c);
            started = true;
        }
    }
    if escaped || quote.is_some() {
        return Err(err("unterminated UCI quote or escape"));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}
