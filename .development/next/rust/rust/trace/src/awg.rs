use std::io;
#[cfg(target_os = "linux")]
mod capture;
#[cfg(any(target_os = "linux", test))]
mod flow;
pub fn run(names: Vec<String>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        capture::run(names)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = names;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "наблюдение интерфейсов AWG доступно только на Linux",
        ))
    }
}
