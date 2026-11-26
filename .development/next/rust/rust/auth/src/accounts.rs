use crate::password::check_hash;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const MAX_LINE: usize = 64 * 1024; // Same maximum record size as Go's bufio.Scanner.

pub fn verify(files: &[PathBuf], user: &str, password: &str) -> bool {
    if user.is_empty() || user.contains([':', '\n', '\r', '\0']) || password.contains('\0') {
        return false;
    }
    // SHA-crypt's setup hashes O(password length squared) bytes. Keep an
    // unauthenticated HTTP request from turning a multi-MiB body into hours of CPU.
    if password.len() > 4096 {
        return false;
    }
    files
        .iter()
        .any(|path| lookup(path, user).is_some_and(|hash| check_hash(password, &hash)))
}

fn lookup(path: &Path, user: &str) -> Option<String> {
    let mut reader = BufReader::new(File::open(path).ok()?);
    let mut line = Vec::new();
    loop {
        line.clear();
        let count = (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .ok()?;
        if count == 0 || count > MAX_LINE {
            return None;
        }
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let mut fields = line.splitn(3, |byte| *byte == b':');
        if fields.next()? == user.as_bytes() {
            return std::str::from_utf8(fields.next()?).ok().map(str::to_owned);
        }
    }
}
