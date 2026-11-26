use super::{bad, read_at, ApiError, Json, Path, Record, Shared, State, Value};
use crate::http::{blocking, ApiJson};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{self, Write},
    net::IpAddr,
};

const MAX_ARCHIVE: u64 = 256 * 1024;

pub(super) fn check(rows: &Value, record: &Record) -> io::Result<()> {
    let invalid = || io::Error::other("invalid TLS capture metadata");
    let rows = rows
        .as_array()
        .filter(|a| a.len() <= 50)
        .ok_or_else(invalid)?;
    let mut total = 0;
    for row in rows {
        if !row.as_object().is_some_and(|o| o.len() == 7)
            || row["src_ip"] != record.doc["ip"]
            || !row["dst_ip"]
                .as_str()
                .is_some_and(|s| s.parse::<IpAddr>().is_ok())
            || row["dst_port"] != 443
            || row["valid"] != true
            || !row["sni"]
                .as_str()
                .is_some_and(|s| s.len() <= 253 && s.bytes().all(|b| b.is_ascii_graphic()))
            || !row["detail"]
                .as_str()
                .is_some_and(|s| s.len() <= 512 && !s.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        total += row["size"]
            .as_u64()
            .filter(|n| (50..=16389).contains(n))
            .ok_or_else(invalid)?;
    }
    if total > MAX_ARCHIVE || total != record.file.as_ref().ok_or_else(invalid)?.metadata()?.len() {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct Selection {
    #[serde(default)]
    index: i64,
    #[serde(default)]
    name: String,
}
pub(super) async fn save(
    State(s): State<Shared>,
    Path(id): Path<String>,
    ApiJson(v): ApiJson<Selection>,
) -> Result<Json<Value>, ApiError> {
    let missing = || bad("ClientHello не найден");
    let index = usize::try_from(v.index).map_err(|_| missing())?;
    let (file, offset, size) = {
        let jobs = s.trace.jobs.lock().unwrap();
        let r = jobs
            .find("hello", &id)
            .filter(|r| r.doc["status"] == "done")
            .ok_or_else(missing)?;
        let rows = r.doc["candidates"].as_array().ok_or_else(missing)?;
        let size = rows
            .get(index)
            .and_then(|r| r["size"].as_u64())
            .ok_or_else(missing)?;
        let offset: u64 = rows[..index]
            .iter()
            .filter_map(|r| r["size"].as_u64())
            .sum();
        (r.file.clone().ok_or_else(missing)?, offset, size)
    };
    blocking(move || {
        nfqws2_blobs::blob_name(&v.name)?;
        let mut bytes = vec![0; size as usize];
        let mut done = 0;
        while done < bytes.len() {
            let n = read_at(&file, &mut bytes[done..], offset + done as u64)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        let (valid, detail) = nfqws2_blobs::validate(&bytes);
        if !valid {
            return Err(io::Error::new(io::ErrorKind::InvalidData, detail));
        }
        let blobs = crate::blobs::service(&s);
        let mut output = blobs.temporary()?;
        output.write_all(&bytes)?;
        let path = blobs.commit(&v.name, output)?;
        Ok(Json(json!({"name":v.name, "path":path})))
    })
    .await
    .map_err(|e| bad(e.1))
}
