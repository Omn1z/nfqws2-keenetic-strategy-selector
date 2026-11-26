use std::{
    io::{self, Read, Write},
    process::ExitCode,
};

fn run() -> io::Result<()> {
    let mut input = io::stdin().lock().take((36 << 20) + 1);
    let req = serde_json::from_reader(&mut input)?;
    if input.limit() == 0 {
        return Err(io::Error::other("input too large"));
    }
    let result = crate::compile(req)?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut output, &result)?;
    output.flush()
}
pub fn cli() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
