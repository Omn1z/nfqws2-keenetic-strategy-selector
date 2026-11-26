use crate::{
    client::linux::{check_ip_names, lock_marker, nested_ip as ip},
    invalid,
};
use std::{fs, io, path::Path};

const TABLE: &str = "997";
const PREFIX: &str = "1.1.1.1/32";
const MARK: &str = "0x60000000";
const MASKED_MARK: &str = "0x60000000/0xe0000000";
const PROTO: &str = "99";

#[derive(Clone, Copy)]
enum Entry {
    Blackhole,
    Host,
    Rule,
}
const ENTRIES: [Entry; 3] = [Entry::Blackhole, Entry::Host, Entry::Rule];

fn after<'a>(words: &'a [&str], label: &str) -> Option<&'a str> {
    words.windows(2).find(|w| w[0] == label).map(|w| w[1])
}

fn conflict() -> io::Error {
    invalid("таблица или селектор HTTPS-проверки AWG уже заняты")
}

#[derive(Default)]
struct Scope {
    exact: [bool; 3],
    ambiguous: [bool; 3],
    foreign: bool,
}
impl Scope {
    fn add(&mut self, entry: Entry, exact: bool) {
        let i = entry as usize;
        if exact {
            self.ambiguous[i] |= std::mem::replace(&mut self.exact[i], true);
        } else {
            self.foreign = true;
            self.ambiguous[i] = true;
        }
    }

    fn matches(&self, expected: [bool; 3]) -> bool {
        !self.foreign && self.ambiguous == [false; 3] && self.exact == expected
    }
}

fn observe(iface: &str) -> io::Result<Scope> {
    let mut found = Scope::default();
    for line in ip(&["-o", "-4", "rule", "show"])?.lines() {
        let w: Vec<_> = line.split_ascii_whitespace().collect();
        let table = after(&w, "lookup").or_else(|| after(&w, "table"));
        let mark = after(&w, "fwmark");
        let marked = mark.is_some_and(|mark| mark.split('/').next() == Some(MARK));
        if w.first() == Some(&"65:") && table == Some(TABLE) && mark == Some(MASKED_MARK) {
            found.add(
                Entry::Rule,
                matches!(
                    &w[..],
                    [
                        "65:",
                        "from",
                        "all",
                        "fwmark",
                        MASKED_MARK,
                        "lookup" | "table",
                        TABLE
                    ]
                ),
            );
        } else if w.first() == Some(&"65:") || table == Some(TABLE) || marked {
            found.foreign = true;
        }
    }
    for line in ip(&["-o", "-4", "route", "show", "table", "all"])?.lines() {
        let w: Vec<_> = line.split_ascii_whitespace().collect();
        if after(&w, "table") != Some(TABLE) {
            continue;
        }
        let candidate = match &w[..] {
            ["blackhole" | "6", "default", fields @ ..]
                if after(fields, "metric") == Some("1000") =>
            {
                Some((Entry::Blackhole, fields))
            }
            ["1.1.1.1" | PREFIX, fields @ ..]
                if after(fields, "dev") == Some(iface) && after(fields, "metric") == Some("1") =>
            {
                Some((Entry::Host, fields))
            }
            _ => None,
        };
        let Some((kind, fields)) =
            candidate.filter(|(_, fields)| after(fields, "proto") == Some(PROTO))
        else {
            found.foreign = true;
            continue;
        };
        let mut fields = fields.iter().copied().filter(|v| *v != "linkdown");
        let mut exact = true;
        while let Some(key) = fields.next() {
            let Some(next) = fields.next() else {
                exact = false;
                break;
            };
            let valid = match (kind, key) {
                (_, "table") => next == TABLE,
                (_, "proto") => next == PROTO,
                (Entry::Blackhole, "metric") => next == "1000",
                (Entry::Blackhole, "dev") => next == "lo",
                (Entry::Host, "dev") => next == iface,
                (Entry::Host, "metric") => next == "1",
                (Entry::Host, "scope") => matches!(next, "link" | "253"),
                _ => false,
            };
            if !valid {
                exact = false;
                break;
            }
        }
        found.add(kind, exact);
    }
    Ok(found)
}

fn update(entry: Entry, verb: &str, iface: &str) -> io::Result<()> {
    match entry {
        Entry::Blackhole => ip(&[
            "-4",
            "route",
            verb,
            "blackhole",
            "default",
            "table",
            TABLE,
            "proto",
            PROTO,
            "metric",
            "1000",
        ]),
        Entry::Host => ip(&[
            "-4", "route", verb, PREFIX, "dev", iface, "table", TABLE, "proto", PROTO, "metric",
            "1",
        ]),
        Entry::Rule => ip(&[
            "-4",
            "rule",
            verb,
            "pref",
            "65",
            "fwmark",
            MASKED_MARK,
            "table",
            TABLE,
        ]),
    }?;
    Ok(())
}

pub(super) struct Lease<'a> {
    iface: &'a str,
    _lock: fs::File,
    installed: [bool; 3],
}

impl<'a> Lease<'a> {
    pub(super) fn install(iface: &'a str) -> io::Result<Self> {
        if iface.len() > 15
            || !iface
                .strip_prefix("awg")
                .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(invalid("некорректный интерфейс проверки AWG"));
        }
        let run = Path::new("/var/run/amneziawg");
        fs::create_dir_all(run)?;
        let _lock = lock_marker(&run.join("n2s-connection-probe.lock"))?;
        check_ip_names(997, 99)?;
        if !observe(iface)?.matches([false; 3]) {
            return Err(conflict());
        }
        let mut lease = Self {
            iface,
            _lock,
            installed: [false; 3],
        };
        for entry in ENTRIES {
            update(entry, "add", iface)?;
            lease.installed[entry as usize] = true;
        }
        if !observe(iface)?.matches(lease.installed) {
            return Err(conflict());
        }
        let route = ip(&["-o", "-4", "route", "get", "1.1.1.1", "mark", MARK])?;
        let words: Vec<_> = route.split_ascii_whitespace().collect();
        if after(&words, "dev") != Some(iface) || after(&words, "table") != Some(TABLE) {
            return Err(invalid(
                "ядро не подтвердило маршрут HTTPS-проверки через AWG",
            ));
        }
        Ok(lease)
    }

    pub(super) fn release(&mut self) -> io::Result<()> {
        if self.installed == [false; 3] {
            return Ok(());
        }
        let observed = observe(self.iface)?;
        let mut failure = None;
        for entry in ENTRIES.into_iter().rev() {
            let slot = &mut self.installed[entry as usize];
            if !*slot {
                continue;
            }
            if observed.ambiguous[entry as usize] {
                failure.get_or_insert_with(conflict);
                continue;
            }
            if observed.exact[entry as usize] {
                if let Err(error) = update(entry, "del", self.iface) {
                    failure.get_or_insert(error);
                    continue;
                }
            }
            *slot = false;
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
