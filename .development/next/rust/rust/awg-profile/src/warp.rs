use super::{add_config, conf, invalid, now, peers};
use nfqws2_store::Store;
use serde::Deserialize;
use serde_json::json;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

pub struct WarpEnrollment {
    name: String,
    endpoint: String,
    private: String,
    public: String,
}
impl WarpEnrollment {
    pub fn new(name: &str, endpoint: &str, accept_tos: bool) -> io::Result<Self> {
        if !accept_tos {
            return Err(invalid(
                "нужно подтвердить условия Cloudflare перед созданием WARP",
            ));
        }
        let name = name.trim();
        if name.len() > 512 || name.chars().any(char::is_control) {
            return Err(invalid("неверное название подключения"));
        }
        let endpoint = endpoint.trim();
        let endpoint = if endpoint.is_empty() {
            "188.114.97.100:2408".into()
        } else if let Ok(ip) = endpoint.parse::<IpAddr>() {
            std::net::SocketAddr::new(ip, 2408).to_string()
        } else if endpoint.contains(':') {
            endpoint.into()
        } else {
            format!("{endpoint}:2408")
        };
        conf::endpoint(&endpoint)?;
        let (private, public) = peers::pair()?;
        Ok(Self {
            name: if name.is_empty() {
                "Cloudflare WARP".into()
            } else {
                name.into()
            },
            endpoint,
            private,
            public,
        })
    }
    pub fn public_key(&self) -> &str {
        &self.public
    }
    pub fn finish(self, db: &Store, response: &[u8]) -> io::Result<()> {
        #[derive(Deserialize)]
        struct Registered {
            config: Config,
        }
        #[derive(Deserialize)]
        struct Config {
            interface: Interface,
            peers: Vec<Peer>,
        }
        #[derive(Deserialize)]
        struct Interface {
            addresses: Addresses,
        }
        #[derive(Deserialize)]
        struct Addresses {
            v4: String,
        }
        #[derive(Deserialize)]
        struct Peer {
            public_key: String,
        }
        if response.len() > 128 * 1024 {
            return Err(invalid("ответ регистрации WARP превышает лимит"));
        }
        let registered: Registered = serde_json::from_slice(response)
            .map_err(|_| invalid("неверный ответ регистрации Cloudflare"))?;
        let public = &registered
            .config
            .peers
            .first()
            .ok_or_else(|| invalid("Cloudflare не вернул peer WARP"))?
            .public_key;
        conf::key(public, false)?;
        let address = registered.config.interface.addresses.v4.trim();
        let (ip, prefix) = address.split_once('/').unwrap_or((address, "32"));
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| invalid("неверный IPv4 подключения WARP"))?;
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_loopback()
            || ip.is_broadcast()
            || ip.is_link_local()
            || prefix.parse::<u8>().ok().is_none_or(|p| p > 32)
        {
            return Err(invalid("неверный IPv4 подключения WARP"));
        }
        let text=format!("[Interface]\nPrivateKey = {}\nAddress = {ip}/{prefix}\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n[Peer]\nPublicKey = {public}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}\nPersistentKeepalive = 25\n",self.private,self.endpoint);
        let mut cfg = conf::parse(&text, now())?;
        cfg["warp_standard"] = json!(true);
        add_config(db, cfg, &self.name)
    }
}
