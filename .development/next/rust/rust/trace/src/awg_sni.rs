use std::io;

#[cfg(target_os = "linux")]
mod capture;

pub fn run() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        capture::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "наблюдение SNI доступно только на Linux",
        ))
    }
}
