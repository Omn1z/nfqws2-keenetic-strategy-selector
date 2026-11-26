//! Transactional ownership of OpenWrt's four managed DNS options.
mod command;
mod manager;
mod ownership;
mod uci;
pub use manager::{Manager, State};
pub use ownership::{Binding, Endpoint};
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}
use std::{io, path::Path};

fn err(s: impl Into<String>) -> io::Error {
    io::Error::other(s.into())
}

pub fn restore_for_uninstall(data_dir: impl AsRef<Path>) -> io::Result<()> {
    if nfqws2_config::Resolver::current().platform() != nfqws2_config::Platform::OpenWrt {
        return Ok(());
    }
    Manager::new(data_dir).restore("")
}
