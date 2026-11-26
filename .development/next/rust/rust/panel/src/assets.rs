use axum::{
    body::{Body, Bytes},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use flate2::read::GzDecoder;
use nfqws2_config::{Key, Resolver};
use std::io::Read;
use std::{env, path::PathBuf};

pub enum Asset {
    Embedded(&'static [u8]),
    #[cfg(feature = "compact")]
    Module(&'static str),
}
include!(concat!(env!("OUT_DIR"), "/assets.rs"));

pub fn module_dir() -> PathBuf {
    env::var_os("N2S_MODULE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Resolver::current().path(Key::ModuleDir).into())
}

fn gzip_ok(headers: &HeaderMap) -> bool {
    let mut wildcard = false;
    for value in headers.get_all(header::ACCEPT_ENCODING) {
        for item in value.to_str().unwrap_or_default().split(',') {
            let mut fields = item.trim().split(';');
            let encoding = fields.next().unwrap_or_default().trim();
            let q = fields
                .filter_map(|p| p.trim().split_once('='))
                .find(|(k, _)| k.trim().eq_ignore_ascii_case("q"))
                .map_or(1.0, |(_, v)| v.trim().parse::<f32>().unwrap_or(0.0));
            if encoding.eq_ignore_ascii_case("gzip") {
                return q > 0.0;
            }
            if encoding == "*" {
                wildcard = q > 0.0;
            }
        }
    }
    wildcard
}

pub async fn serve(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let name = uri.path().trim_start_matches('/');
    if name == "api" || name.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let name = if name.starts_with("ui/") || name.starts_with("modules/") {
        name
    } else {
        "index.html"
    };
    let Some((_, asset)) = ASSETS.iter().find(|(path, _)| *path == name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let compressed = match asset {
        Asset::Embedded(bytes) => Bytes::from_static(bytes),
        #[cfg(feature = "compact")]
        Asset::Module(rel) => match tokio::fs::read(module_dir().join(format!("{rel}.gz"))).await {
            Ok(bytes) => Bytes::from(bytes),
            Err(_) => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let (mime, cache) = match name {
        "index.html" => ("text/html; charset=utf-8", "no-store"),
        p if p.ends_with(".css") => (
            "text/css; charset=utf-8",
            "public, max-age=31536000, immutable",
        ),
        _ => (
            "text/javascript; charset=utf-8",
            "public, max-age=31536000, immutable",
        ),
    };
    let mut res = Response::builder()
        .header(header::VARY, "Accept-Encoding")
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache);
    let body = if gzip_ok(&headers) {
        res = res
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONTENT_LENGTH, compressed.len());
        if method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(compressed)
        }
    } else if method == Method::HEAD {
        Body::empty()
    } else {
        // Stream the identity representation under backpressure, including for
        // older clients on the LAN. The compressed index stays in read-only memory.
        let decoder = GzDecoder::new(std::io::Cursor::new(compressed));
        Body::from_stream(futures_util::stream::try_unfold(
            decoder,
            |mut decoder| async move {
                let mut block = vec![0; 16 * 1024];
                let n = decoder.read(&mut block)?;
                block.truncate(n);
                Ok::<_, std::io::Error>((n != 0).then_some((Bytes::from(block), decoder)))
            },
        ))
    };
    res.body(body).expect("static response headers")
}
