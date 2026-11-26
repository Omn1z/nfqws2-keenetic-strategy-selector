use crate::{invalid, validate};
use rustls::{pki_types::ServerName, version, ClientConfig, ClientConnection, RootCertStore};
use std::{io, sync::Arc};

pub fn generate(sni: &str, protocols: &[String], minimum: u16) -> io::Result<Vec<u8>> {
    let sni = sni.trim().trim_end_matches('.').trim();
    if sni.is_empty() {
        return Err(invalid("укажите домен (SNI)"));
    }
    let name =
        ServerName::try_from(sni.to_owned()).map_err(|_| invalid("неверное доменное имя (SNI)"))?;
    if !matches!(name, ServerName::DnsName(_)) {
        return Err(invalid("SNI должен быть доменом, а не IP-адресом"));
    }
    let versions: &[_] = match minimum {
        0 | 0x0301..=0x0303 => &[&version::TLS13, &version::TLS12],
        0x0304 => &[&version::TLS13],
        _ => return Err(invalid("неподдерживаемая версия TLS")),
    };
    if protocols.iter().any(|p| p.is_empty() || p.len() > 255)
        || protocols.iter().map(|p| p.len() + 1).sum::<usize>() > u16::MAX as usize - 2
    {
        return Err(invalid("неверный ALPN"));
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .map_err(|e| invalid(e.to_string()))?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    let mut client =
        ClientConnection::new(Arc::new(config), name).map_err(|e| invalid(e.to_string()))?;
    let mut record = Vec::new();
    client.write_tls(&mut record)?;
    if !validate(&record).0 {
        return Err(invalid("не удалось собрать ClientHello"));
    }
    Ok(record)
}
