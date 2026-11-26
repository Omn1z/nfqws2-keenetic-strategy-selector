use super::discovery::Peer;
use std::io;
pub async fn exchange(peer: &Peer, original: &[u8]) -> io::Result<Vec<u8>> {
    if original.len() < 12 || original.len() > 65535 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if !(cfg!(test) && peer.device.is_empty()) {
        let addresses = super::super::lan::addresses()?;
        if !addresses.iter().any(|(dev, _)| dev == &peer.device)
            || addresses
                .iter()
                .any(|(_, ip)| ip.to_canonical() == peer.addr.ip().to_canonical())
        {
            return Err(io::ErrorKind::AddrNotAvailable.into());
        }
    }
    super::super::network::exchange(peer.addr, Some((&peer.device, 0)), original).await
}
