use std::{env, io, time::Duration};

pub const USAGE: &str = "usage: router-ssh [--host <host>] [--port 222] [--user root] [--password <password>] <command> [args]
host and password are required via flags or ROUTER_HOST / ROUTER_PASS environment variables

commands:
  exec [--timeout 60s] <command>
  upload [--mode 0755] <local> <remote>
  download <remote> <local>
  diagnose [--only accel,routing] [section ...]";

pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn from_env(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map_or_else(|| default.to_owned(), |v| v.trim().to_owned())
}

pub struct Connection {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

pub fn flags(
    mut args: &[String],
    mut set: impl FnMut(&str, &str) -> io::Result<()>,
) -> io::Result<&[String]> {
    while let Some((flag, rest)) = args.split_first() {
        if flag == "--" {
            return Ok(rest);
        }
        if !flag.starts_with('-') || flag == "-" {
            break;
        }
        let flag = flag
            .strip_prefix("--")
            .or_else(|| flag.strip_prefix('-'))
            .unwrap();
        if let Some((key, val)) = flag.split_once('=') {
            set(key, val)?;
            args = rest;
        } else {
            let (val, tail) = rest
                .split_first()
                .ok_or_else(|| invalid("missing option value"))?;
            set(flag, val)?;
            args = tail;
        }
    }
    Ok(args)
}

pub fn connection(args: &[String]) -> io::Result<(Connection, &str, &[String])> {
    let mut cfg = Connection {
        host: from_env("ROUTER_HOST", ""),
        port: from_env("ROUTER_PORT", "222").parse().unwrap_or(222),
        user: from_env("ROUTER_USER", "root"),
        password: env::var("ROUTER_PASS").unwrap_or_default(),
    };
    let rest = flags(args, |key, val| {
        match key {
            "host" => cfg.host = val.to_owned(),
            "port" => cfg.port = val.parse().map_err(|_| invalid("invalid SSH port"))?,
            "user" => cfg.user = val.to_owned(),
            "password" => cfg.password = val.to_owned(),
            _ => return Err(invalid("unknown connection option")),
        }
        Ok(())
    })?;
    let (cmd, args) = rest.split_first().ok_or_else(|| invalid(USAGE))?;
    if cfg.host.trim().is_empty() {
        return Err(invalid(
            "router host is required: set --host or ROUTER_HOST",
        ));
    }
    if cfg.password.is_empty() {
        return Err(invalid(
            "router password is required: set --password or ROUTER_PASS",
        ));
    }
    if cfg.port == 0 {
        return Err(invalid("invalid SSH port"));
    }
    Ok((cfg, cmd, args))
}

pub fn timeout(input: &str) -> io::Result<Duration> {
    let mut rest = input.strip_prefix(['-', '+']).unwrap_or(input);
    if rest == "0" {
        return Ok(Duration::ZERO);
    }
    let mut nanos = 0u64;
    if rest.is_empty() {
        return Err(invalid("invalid command timeout"));
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        let number = &rest[..digits];
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if (whole.is_empty() && fraction.is_empty())
            || !fraction.bytes().all(|c| c.is_ascii_digit())
        {
            return Err(invalid("invalid command timeout"));
        }
        let whole: u64 = if whole.is_empty() {
            0
        } else {
            whole
                .parse()
                .map_err(|_| invalid("invalid command timeout"))?
        };
        rest = &rest[digits..];
        let (unit, multiplier) = [
            ("ns", 1),
            ("us", 1_000),
            ("µs", 1_000),
            ("μs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))
        .ok_or_else(|| invalid("invalid timeout unit"))?;
        // Accumulate fractional digits from the right. This rounds toward
        // zero at nanosecond precision without floating point overflow.
        let fraction_ns = fraction.bytes().rev().fold(0, |tail, digit| {
            (u64::from(digit - b'0') * multiplier + tail) / 10
        });
        nanos = whole
            .checked_mul(multiplier)
            .and_then(|v| v.checked_add(fraction_ns))
            .and_then(|v| nanos.checked_add(v))
            .ok_or_else(|| invalid("command timeout is too large"))?;
        rest = &rest[unit.len()..];
    }
    if nanos > i64::MAX as u64 + u64::from(input.starts_with('-')) {
        return Err(invalid("command timeout is too large"));
    }
    Ok(Duration::from_nanos(if input.starts_with('-') {
        0
    } else {
        nanos
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_duration_units_signs_and_boundaries() {
        for (s, n) in [
            ("+0", 0),
            ("-1s", 0),
            ("1m0.25s", 60_250_000_000),
            (".55µs2ns", 552),
            ("1.μs", 1000),
            ("9223372036854775807ns", i64::MAX as u64),
        ] {
            assert_eq!(timeout(s).unwrap(), Duration::from_nanos(n));
        }
        for bad in [
            "",
            ".",
            "2",
            "1e2s",
            "1q",
            "1.2.3s",
            "9223372036854775808ns",
        ] {
            assert!(timeout(bad).is_err(), "{bad}");
        }
    }
}
