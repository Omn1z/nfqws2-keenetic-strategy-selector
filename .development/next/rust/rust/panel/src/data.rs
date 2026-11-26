use nfqws2_store::{new_id, valid_name, Store};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    io,
    time::{SystemTime, UNIX_EPOCH},
};

fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
pub fn clean_lines(lines: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    lines
        .into_iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect()
}
pub fn or_default<T: DeserializeOwned + Default>(db: &Store, file: &str) -> io::Result<T> {
    match db.read(file) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        other => other,
    }
}
fn document(folder: &str, id: &str) -> io::Result<String> {
    if !valid_name(id) {
        return Err(bad("invalid ID"));
    }
    Ok(format!("{folder}/{id}.json"))
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct List {
    pub id: String,
    pub name: String,
    pub domains: Option<Vec<String>>,
    pub ips: Option<Vec<String>>,
    pub base_strategy_ids: Option<Vec<String>>,
    pub successful_strategies: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub test_url: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub fn lists(db: &Store) -> io::Result<Vec<List>> {
    let mut items: Vec<List> = records(db, "lists")?;
    items.sort_by_key(|item| item.created_at);
    Ok(items)
}

fn records<T: DeserializeOwned>(db: &Store, dir: &str) -> io::Result<Vec<T>> {
    Ok(db
        .files(dir)?
        .iter()
        .filter(|file| file.ends_with(".json"))
        .filter_map(|file| db.read(&format!("{dir}/{file}")).ok())
        .collect())
}

pub fn save_list(db: &Store, list: List) -> io::Result<List> {
    db.transaction(|tx| write_list(db, tx, list))
}
pub fn append_geo(
    db: &Store,
    id: &str,
    name: &str,
    domains: Vec<String>,
    ips: Vec<String>,
) -> io::Result<List> {
    db.transaction(|tx| {
        let mut list = if id.is_empty() {
            List {
                name: name.into(),
                ..List::default()
            }
        } else {
            list(db, id)?
        };
        list.domains.get_or_insert_with(Vec::new).extend(domains);
        list.ips.get_or_insert_with(Vec::new).extend(ips);
        write_list(db, tx, list)
    })
}
fn write_list(
    db: &Store,
    transaction: &nfqws2_store::Transaction<'_>,
    mut list: List,
) -> io::Result<List> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if list.id.is_empty() {
        list.id = new_id()?;
        list.created_at = now;
    }
    let file = document("lists", &list.id)?;
    match db.read::<List>(&file) {
        Ok(old) => {
            list.created_at = old.created_at;
            if list.successful_strategies.is_none() {
                list.successful_strategies = old.successful_strategies;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    list.domains = Some(clean_lines(list.domains.unwrap_or_default()));
    list.ips = Some(clean_lines(list.ips.unwrap_or_default()));
    list.updated_at = now;
    transaction.save(&file, &list)?;
    Ok(list)
}

pub fn delete_list(db: &Store, id: &str) -> io::Result<()> {
    let file = document("lists", id)?;
    db.transaction(|transaction| transaction.delete(&file))
}

pub fn list(db: &Store, id: &str) -> io::Result<List> {
    db.read(&document("lists", id)?)
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Strategy {
    id: String,
    name: String,
    l7: String,
    args: String,
    source: String,
}

fn validate_args(line: &str) -> io::Result<()> {
    const LUA: &[&str] = &[
        "circular",
        "fake",
        "multisplit",
        "multidisorder",
        "split",
        "disorder",
        "fakedsplit",
        "fakeddisorder",
        "hostfakesplit",
        "http_methodeol",
        "syndata",
        "send",
        "pktmod",
        "tamper",
    ];
    const DPI: &[&str] = &[
        "fake",
        "split",
        "split2",
        "disorder",
        "disorder2",
        "fakedsplit",
        "fakeddisorder",
        "multisplit",
        "multidisorder",
        "syndata",
        "ipfrag2",
        "udplen",
        "tamper",
    ];
    if line.trim().is_empty() {
        return Err(bad("пустые аргументы стратегии"));
    }
    for token in line.split_whitespace() {
        if token == "--new" || token.starts_with("--new=") || !token.starts_with('-') {
            return Err(bad("недопустимый аргумент стратегии"));
        }
        if let Some(method) = token
            .strip_prefix("--lua-desync=")
            .and_then(|v| v.split(':').next())
        {
            if !method.is_empty() && !LUA.contains(&method) {
                return Err(bad("неизвестный метод --lua-desync"));
            }
        }
        if let Some(modes) = token.strip_prefix("--dpi-desync=") {
            if modes.split(',').any(|m| !m.is_empty() && !DPI.contains(&m)) {
                return Err(bad("неизвестный режим --dpi-desync"));
            }
        }
    }
    Ok(())
}

const CUSTOM: &str = "strategies_custom.json";
pub fn strategies(db: &Store) -> io::Result<Vec<Strategy>> {
    #[cfg(not(feature = "compact"))]
    let mut builtin: Vec<Strategy> = serde_json::from_slice(include_bytes!(
        "../../../internal/services/strategy/core/catalog/builtin.json"
    ))?;
    #[cfg(feature = "compact")]
    let mut builtin: Vec<Strategy> = {
        use std::{fs::File, io::Read};
        match File::open(super::assets::module_dir().join("strategies/catalog.json")) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            f => {
                let mut data = Vec::new();
                f?.take(65537).read_to_end(&mut data)?;
                if data.len() > 65536 {
                    return Err(bad("strategy catalog too large"));
                }
                serde_json::from_slice(&data)?
            }
        }
    };
    builtin.extend(or_default::<Option<Vec<Strategy>>>(db, CUSTOM)?.unwrap_or_default());
    Ok(builtin)
}

pub fn save_strategy(db: &Store, strategy: Strategy) -> io::Result<Strategy> {
    db.transaction(|tx| write_strategy(db, tx, strategy))
}
pub fn write_imported_strategy(
    db: &Store,
    tx: &nfqws2_store::Transaction<'_>,
    name: String,
    l7: String,
    args: String,
) -> io::Result<Strategy> {
    write_strategy(
        db,
        tx,
        Strategy {
            name,
            l7,
            args,
            ..Strategy::default()
        },
    )
}
fn write_strategy(
    db: &Store,
    tx: &nfqws2_store::Transaction<'_>,
    mut strategy: Strategy,
) -> io::Result<Strategy> {
    validate_args(&strategy.args)?;
    if strategy.id.is_empty() {
        strategy.id = format!("custom-{}", new_id()?);
    }
    strategy.source = "custom".into();
    let items = or_default::<Option<Vec<Strategy>>>(db, CUSTOM)?.unwrap_or_default();
    let mut updated: Vec<_> = items.iter().collect();
    if let Some(item) = updated.iter_mut().find(|v| v.id == strategy.id) {
        *item = &strategy;
    } else {
        updated.push(&strategy);
    }
    tx.save(CUSTOM, &updated)?;
    Ok(strategy)
}

pub fn delete_strategy(db: &Store, id: &str) -> io::Result<()> {
    db.transaction(|tx| {
        let mut items = or_default::<Option<Vec<Strategy>>>(db, CUSTOM)?.unwrap_or_default();
        items.retain(|s| s.id != id);
        tx.save(CUSTOM, &items)
    })
}
