use super::*;
use serde::Serialize;
use std::path::Path;

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct Portable {
    name: String,
    l7: String,
    args: String,
}

fn rewrite(args: &str, mut blob: impl FnMut(&str) -> io::Result<String>) -> io::Result<String> {
    let mut result = String::with_capacity(args.len());
    for chunk in args.split_inclusive(char::is_whitespace) {
        let token = chunk.trim_end();
        if let Some((id, path)) = token
            .strip_prefix("--blob=")
            .and_then(|s| s.split_once(":@"))
            .filter(|(id, path)| !id.is_empty() && !id.contains(':') && !path.is_empty())
        {
            result.push_str("--blob=");
            result.push_str(id);
            result.push_str(":@");
            result.push_str(&blob(path)?);
            result.push_str(&chunk[token.len()..]);
        } else {
            result.push_str(chunk);
        }
    }
    Ok(result)
}
fn base(path: &str) -> io::Result<&str> {
    blob_name(path.rsplit(['/', '\\']).next().unwrap_or_default())
}
async fn export(
    State(s): State<Shared>,
    ApiJson(mut v): ApiJson<Portable>,
) -> Result<Response, ApiError> {
    if v.args.trim().is_empty() {
        return Err(bad("empty strategy args"));
    }
    let mut selected = Vec::new();
    let mut filename: String = v
        .name
        .chars()
        .take(60)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if filename.is_empty() {
        filename.push_str("strategy");
    }
    filename.push_str(".zip");
    v.args = rewrite(&v.args, |path| {
        let name = base(path)?;
        if name == "strategy.json" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reserved blob name",
            ));
        }
        // Portable archives refer to a filename. Resolve those names only in
        // the panel's configured custom/system blob libraries.
        selected.push(path.to_owned());
        Ok(name.into())
    })
    .map_err(bad)?;
    let meta = serde_json::to_vec(&v).map_err(bad)?;
    Ok(stream_zip(&filename, move |out| {
        service(&s).export(&selected, Some(&meta), out)
    }))
}
async fn import(
    State(s): State<Shared>,
    form: Multipart,
) -> Result<Json<crate::data::Strategy>, ApiError> {
    let (_, zip) = uploaded(&s, form, MAX_ZIP, false).await?;
    blocking(move || {
        service(&s).import_strategy(zip.as_file(), |tx, meta| {
            let v: Portable = serde_json::from_slice(meta)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let args = rewrite(&v.args, |name| {
                let name = base(name)?;
                Ok(Path::new(&s.config.data_dir)
                    .join("blobs")
                    .join(name)
                    .to_string_lossy()
                    .into_owned())
            })?;
            crate::data::write_imported_strategy(&s.store, tx, v.name, v.l7, args).map(Json)
        })
    })
    .await
}
pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/strategies/export", post(export))
        .route(
            "/api/strategies/import",
            post(import).layer(DefaultBodyLimit::max(MAX_ZIP as usize + 64 * 1024)),
        )
}
