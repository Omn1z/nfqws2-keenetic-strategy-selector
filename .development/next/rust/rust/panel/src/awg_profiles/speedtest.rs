use crate::http::{blocking, ApiError, ApiJson, Shared};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::StatusCode,
    response::Response,
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

mod http;
use http::Binding;

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Options {
    url: String,
    iface: String,
    max_bytes: i64,
    timeout_ms: i64,
}
impl Options {
    fn validate(&mut self) -> io::Result<()> {
        self.url = self.url.trim().to_string();
        http::target(&self.url)?;
        self.iface = self.iface.trim().into();
        if !self.iface.is_empty()
            && (self.iface.len() > 15
                || !self
                    .iface
                    .strip_prefix("awg")
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
        {
            return Err(io::Error::other("неверный интерфейс AWG"));
        }
        if self.max_bytes <= 0 {
            self.max_bytes = 10 << 20;
        }
        if self.timeout_ms <= 0 {
            self.timeout_ms = 15000;
        }
        if self.timeout_ms > 300_000 {
            return Err(io::Error::other("предел замера — 5 минут на интерфейс"));
        }
        Ok(())
    }
}
fn wan(table: &str) -> Option<&str> {
    table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let dest = fields.next()?;
            let gateway = fields.next()?;
            let flags = u32::from_str_radix(fields.next()?, 16).ok()?;
            let metric = fields.nth(2)?.parse::<u32>().ok()?;
            let mask = fields.next()?;
            (dest == "00000000"
                && mask == "00000000"
                && flags & 1 == 1
                && flags & 0x200 == 0
                && name != "lo"
                && !name.starts_with("awg"))
            .then_some((gateway == "00000000" || flags & 2 == 0, metric, name))
        })
        .min_by_key(|&(without_gateway, metric, _)| (without_gateway, metric))
        .map(|(_, _, name)| name)
}
type Events = mpsc::Sender<Bytes>;
async fn event(tx: &Events, v: Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&v)?;
    bytes.push(b'\n');
    tx.send(bytes.into())
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe.into())
}
#[derive(Default, Serialize)]
struct Sample {
    rx_bytes: u64,
    duration_ms: u64,
    rx_bytes_per_sec: f64,
    http_status: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}
async fn transfer(
    o: &Options,
    binding: Binding<'_>,
    phase: &str,
    tx: &Events,
    out: &mut Sample,
    start: Instant,
) -> io::Result<()> {
    let mut exchange = http::get(&o.url, binding, o.max_bytes).await?;
    let status = exchange.response.status();
    out.http_status = status.as_u16();
    if !matches!(out.http_status, 200 | 206) {
        return Err(io::Error::other(format!("источник вернул {status}")));
    }
    let mut last = None::<Instant>;
    let body = exchange.response.body_mut();
    while out.rx_bytes < o.max_bytes as u64 {
        let Some(frame) = body.frame().await else {
            break;
        };
        let frame = frame.map_err(io::Error::other)?;
        let Ok(bytes) = frame.into_data() else {
            continue;
        };
        let remaining = o.max_bytes as u64 - out.rx_bytes;
        out.rx_bytes += remaining.min(bytes.len() as u64);
        if last.is_none_or(|previous| previous.elapsed() >= Duration::from_millis(250)) {
            let elapsed = start.elapsed();
            event(tx,json!({"phase":format!("{phase}_progress"),"bytes":out.rx_bytes,"elapsed_ms":elapsed.as_millis() as u64,"rate_bps":out.rx_bytes as f64/elapsed.as_secs_f64().max(0.000001)})).await?;
            last = Some(Instant::now());
        }
    }
    if out.rx_bytes == 0 {
        return Err(io::Error::other("источник вернул пустой ответ"));
    }
    Ok(())
}
async fn sample(
    o: &Options,
    bind: Option<Binding<'_>>,
    phase: &str,
    tx: &Events,
) -> io::Result<Sample> {
    event(tx, json!({"phase":format!("{phase}_start")})).await?;
    let start = Instant::now();
    let mut out = Sample::default();
    let result = match bind {
        Some(b) => tokio::time::timeout(
            Duration::from_millis(o.timeout_ms as u64),
            transfer(o, b, phase, tx, &mut out, start),
        )
        .await
        .map_err(io::Error::other)
        .and_then(|r| r),
        None => Err(io::Error::other("не найден WAN-интерфейс")),
    };
    let elapsed = start.elapsed();
    out.duration_ms = elapsed.as_millis() as u64;
    out.rx_bytes_per_sec = out.rx_bytes as f64 / elapsed.as_secs_f64().max(0.000001);
    if let Err(e) = result {
        out.error = e.to_string();
    }
    event(tx, json!({"phase":format!("{phase}_done"),"sample":out})).await?;
    Ok(out)
}
async fn measure(
    o: &Options,
    tunnel: Binding<'_>,
    direct: Option<Binding<'_>>,
    tx: &Events,
) -> io::Result<()> {
    event(
        tx,
        json!({"phase":"init","url":o.url,"max_bytes":o.max_bytes}),
    )
    .await?;
    let t = sample(o, Some(tunnel), "tunnel", tx).await?;
    let d = sample(o, direct, "direct", tx).await?;
    let comparable =
        d.error.is_empty() && t.error.is_empty() && d.rx_bytes > 0 && t.rx_bytes == d.rx_bytes;
    let gain = if comparable {
        ((t.rx_bytes_per_sec / d.rx_bytes_per_sec - 1.) * 100.) as i64
    } else {
        0
    };
    event(tx,json!({"phase":"result","result":{"via_tunnel":t,"via_direct":d,"comparable":comparable,"tunnel_gain_pc":gain,"sample":o.url}})).await
}
pub(super) async fn handle(
    State(s): State<Shared>,
    ApiJson(mut o): ApiJson<Options>,
) -> Result<Response, ApiError> {
    o.validate()
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let guard = s
        .speedtest
        .clone()
        .try_lock_owned()
        .map_err(|_| ApiError(StatusCode::CONFLICT, "замер уже запущен".into()))?;
    if o.iface.is_empty() {
        let db = s.store.clone();
        o.iface = blocking(move || nfqws2_awg_profile::active_client_iface(&db)).await?;
    }
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let _guard = guard;
        let table = tokio::fs::read_to_string("/proc/net/route")
            .await
            .unwrap_or_default();
        let direct = wan(&table).map(Binding::Device);
        let tunnel = Binding::Device(&o.iface);
        tokio::select! { _=tx.closed()=>(), _=measure(&o,tunnel,direct,&tx)=>() }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|b| (Ok::<_, io::Error>(b), rx))
    });
    Ok(Response::builder()
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap())
}

#[cfg(test)]
mod tests;
