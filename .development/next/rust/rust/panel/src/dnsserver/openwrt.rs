use super::*;
use nfqws2_openwrt_dns::{Binding, Endpoint};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{timeout, Duration},
};

pub(super) fn routes() -> Router<Shared> {
    Router::new()
        .route("/api/dnsserver/openwrt", get(status))
        .route("/api/dnsserver/openwrt/apply", post(apply))
        .route("/api/dnsserver/openwrt/rebind", post(rebind))
        .route("/api/dnsserver/openwrt/restore", post(restore))
}
type ResultState = Result<
    (
        [(header::HeaderName, &'static str); 1],
        Json<nfqws2_openwrt_dns::State>,
    ),
    ApiError,
>;
async fn status(State(s): State<Shared>) -> ResultState {
    let _guard = s.dnsserver.state.lock().await;
    read(&s).await
}
async fn read(s: &Shared) -> ResultState {
    let manager = s.dnsserver.openwrt.clone();
    let state = tokio::task::spawn_blocking(move || manager.status())
        .await
        .map_err(worker_err)?
        .map_err(|e| invalid(e.to_string()))?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(state)))
}
#[derive(Deserialize)]
struct Selection {
    revision: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    instance: String,
}
enum Action {
    Apply,
    Rebind,
    Restore,
}
async fn apply(State(s): State<Shared>, ApiJson(sel): ApiJson<Selection>) -> ResultState {
    change(s, sel, Action::Apply).await
}
async fn rebind(State(s): State<Shared>, ApiJson(sel): ApiJson<Selection>) -> ResultState {
    change(s, sel, Action::Rebind).await
}
async fn restore(State(s): State<Shared>, ApiJson(sel): ApiJson<Selection>) -> ResultState {
    change(s, sel, Action::Restore).await
}
async fn change(s: Shared, sel: Selection, action: Action) -> ResultState {
    if sel.revision.trim().is_empty() {
        return Err(invalid("сначала обновите состояние DNS OpenWrt").into());
    }
    tokio::spawn(async move {
        let state = s.dnsserver.state.lock().await;
        let manager = s.dnsserver.openwrt.clone();
        let result = match action {
            Action::Apply => {
                let active = state
                    .active
                    .as_ref()
                    .filter(|run| run.running())
                    .ok_or_else(|| invalid("сначала включите DNS Server"))?;
                let address = active.addr;
                let binding = Binding {
                    interface: sel.interface,
                    instance: sel.instance,
                    endpoint: Endpoint {
                        host: address.ip().to_string(),
                        port: address.port(),
                    },
                };
                binding.validate().map_err(|e| invalid(e.to_string()))?;
                verify(address).await?;
                tokio::task::spawn_blocking(move || manager.apply(binding, &sel.revision)).await
            }
            Action::Rebind => {
                tokio::task::spawn_blocking(move || manager.rebind(&sel.instance, &sel.revision))
                    .await
            }
            Action::Restore => {
                tokio::task::spawn_blocking(move || manager.restore(&sel.revision)).await
            }
        };
        result
            .map_err(worker_err)?
            .map_err(|e| invalid(e.to_string()))?;
        read(&s).await
    })
    .await
    .map_err(worker_err)?
}
async fn verify(address: SocketAddr) -> io::Result<()> {
    let id = nfqws2_store::new_id()?;
    let id = u16::from_str_radix(&id[..4], 16).unwrap();
    let q = nfqws2_dns::build_query("example.com", 1, id)?;
    let resolver = nfqws2_dns::Resolver::new(0, 0, Duration::from_secs(4));
    for tcp in [false, true] {
        let answer = timeout(
            Duration::from_secs(4),
            resolver.exchange_async(&q, "local", || async {
                if tcp {
                    let mut stream = TcpStream::connect(address).await?;
                    stream.write_u16(q.len() as u16).await?;
                    stream.write_all(&q).await?;
                    let len = stream.read_u16().await?;
                    let mut data = vec![0; usize::from(len)];
                    stream.read_exact(&mut data).await?;
                    Ok(data)
                } else {
                    let socket = UdpSocket::bind(if address.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    })
                    .await?;
                    socket.connect(address).await?;
                    socket.send(&q).await?;
                    let mut data = vec![0; 1232];
                    let len = socket.recv(&mut data).await?;
                    data.truncate(len);
                    Ok(data)
                }
            }),
        )
        .await??;
        if !matches!(answer.wire[3] & 15, 0 | 3) {
            return Err(invalid("локальный DNS upstream не отвечает"));
        }
    }
    Ok(())
}
