use crate::{Config, Key, Platform, Resolver};
use serde::Serialize;
use std::{collections::HashMap, path::Path};

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub from: usize,
    pub to: usize,
    pub path: String,
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub replacement: String,
}
#[derive(Serialize)]
pub struct Analysis {
    pub diagnostics: Vec<Diagnostic>,
    pub content: String,
    pub platform: &'static str,
}
struct Layout<'a> {
    conf: &'a str,
    lua: &'a str,
    blobs: &'a str,
    logs: &'a str,
    platform: &'static str,
}
fn below<'a>(p: &'a str, root: &str) -> Option<&'a str> {
    if root.is_empty() {
        return None;
    }
    p.strip_prefix(root)
        .filter(|tail| tail.is_empty() || tail.starts_with('/'))
}
impl Layout<'_> {
    fn relocate(&self, p: &str) -> Option<String> {
        for root in ["/opt/var/log", "/var/log"] {
            if let Some(file) = below(p, root).and_then(|tail| tail.strip_prefix('/')) {
                if !self.logs.is_empty()
                    && [
                        "nfqws2.log",
                        "nfqws2-debug.log",
                        "nfqws.log",
                        "nfqws-debug.log",
                    ]
                    .contains(&file)
                {
                    return Some(format!("{}/{file}", self.logs));
                }
            }
        }
        for root in [
            "/opt/etc/nfqws2",
            "/etc/nfqws2",
            "/opt/etc/nfqws",
            "/etc/nfqws",
        ] {
            let Some(tail) = below(p, root) else { continue };
            if tail.split('/').any(|s| matches!(s, "." | "..")) {
                return Some(String::new());
            }
            for (segment, target) in [("/lua", self.lua), ("/blobs", self.blobs)] {
                if let Some(rest) = below(tail, segment).filter(|_| !target.is_empty()) {
                    return Some(format!("{target}{rest}"));
                }
            }
            return Some(format!("{}{tail}", self.conf));
        }
        [self.conf, self.lua, self.blobs]
            .into_iter()
            .any(|v| below(p, v).is_some())
            .then(|| p.into())
    }
}
fn long_bracket(src: &[u8], i: usize) -> Option<(usize, Vec<u8>)> {
    if src.get(i) != Some(&b'[') {
        return None;
    }
    let mut end = i + 1;
    while src.get(end) == Some(&b'=') {
        end += 1;
    }
    if src.get(end) != Some(&b'[') {
        return None;
    }
    let mut close = src[i..=end].to_vec();
    close[0] = b']';
    *close.last_mut().unwrap() = b']';
    Some((end + 1, close))
}
fn backtick(src: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < src.len() {
        match src[i] {
            b'\\' => i += 2,
            96 => return i + 1,
            _ => i += 1,
        }
    }
    src.len()
}
fn expansion_start(b: &[u8], quote: u8) -> bool {
    matches!(b, [b'$', b'(' | b'{', ..]) || quote == 0 && matches!(b, [b'<' | b'>', b'(', ..])
}
fn comment_start(b: &[u8], i: usize) -> bool {
    i == 0 || b" \t\n\r;".contains(&b[i - 1])
}
fn line_end(src: &[u8], i: usize) -> usize {
    src[i..]
        .iter()
        .position(|v| *v == b'\n')
        .map_or(src.len(), |n| n + i + 1)
}
fn skip_expansion(src: &[u8], start: usize, nesting: u8) -> usize {
    if nesting >= 64 {
        return src.len();
    }
    let open = src[start + 1];
    let close = if open == b'{' { b'}' } else { b')' };
    let mut i = start + 2;
    let mut quote = 0;
    let mut depth = 1;
    while i < src.len() {
        let c = src[i];
        if quote == b'\'' {
            if c == quote {
                quote = 0
            };
            i += 1;
            continue;
        }
        if c == b'\\' {
            i += 2;
            continue;
        }
        if c == 96 {
            i = backtick(src, i);
            continue;
        }
        if expansion_start(&src[i..], quote) {
            i = skip_expansion(src, i, nesting + 1);
            continue;
        }
        if c == b'"' {
            quote = if quote == c { 0 } else { c };
        } else if quote == 0 {
            if c == b'\'' {
                quote = c;
            } else if open == b'(' && c == b'#' && comment_start(src, i) {
                i = line_end(src, i);
                continue;
            } else if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
        }
        i += 1;
    }
    src.len()
}
fn gzip_allowed(text: &str, i: usize, lua: bool) -> bool {
    if lua || i == 0 || text.as_bytes()[i - 1] != b'@' {
        return false;
    }
    text[..i - 1]
        .trim_end_matches(['\'', '"'])
        .strip_suffix("--lua-init=")
        .is_some_and(|prefix| {
            prefix.is_empty()
                || prefix
                    .as_bytes()
                    .last()
                    .is_some_and(|b| b" \t\r\n\"'".contains(b))
        })
}
fn analyze(
    src: &str,
    lua: bool,
    layout: Layout<'_>,
    mut stat: impl FnMut(&str) -> bool,
) -> Analysis {
    let b = src.as_bytes();
    let mut cache = HashMap::new();
    let mut file_exists = |path: &str| *cache.entry(path.to_owned()).or_insert_with(|| stat(path));
    let mut exists = |p: &str, gz: bool| {
        file_exists(p) || (gz && !p.ends_with(".gz") && file_exists(&format!("{p}.gz")))
    };
    let mut result = Analysis {
        content: String::new(),
        diagnostics: Vec::new(),
        platform: layout.platform,
    };
    let (mut copied, mut position, mut utf16) = (0, 0, 0);
    let (mut quote, mut long, mut i) = (0, Vec::new(), 0);
    while i < b.len() {
        let c = b[i];
        if !long.is_empty() && b[i..].starts_with(&long) {
            i += long.len();
            long.clear();
            continue;
        }
        if long.is_empty() && c == b'\\' && (lua || quote != b'\'') {
            i += 2;
            continue;
        }
        if quote == 0 && long.is_empty() {
            if lua && b[i..].starts_with(b"--") {
                if let Some((body, close)) = long_bracket(b, i + 2) {
                    i = b[body..]
                        .windows(close.len())
                        .position(|v| v == close)
                        .map_or(b.len(), |p| body + p + close.len());
                } else {
                    i = line_end(b, i);
                }
                continue;
            }
            if !lua && c == b'#' && comment_start(b, i) {
                i = line_end(b, i);
                continue;
            }
            if lua {
                if let Some((body, close)) = long_bracket(b, i) {
                    i = body;
                    long = close;
                    continue;
                }
            }
        }
        if !lua && quote != b'\'' {
            if c == 96 {
                i = backtick(b, i);
                continue;
            }
            if expansion_start(&b[i..], quote) {
                i = skip_expansion(b, i, 0);
                continue;
            }
        }
        if long.is_empty() && matches!(c, b'"' | b'\'' | 96) {
            if quote == 0 {
                quote = c;
            } else if quote == c {
                quote = 0;
            }
            i += 1;
            continue;
        }
        if c != b'/' || quote == 96 || i > 0 && !b" \t\n\r=\"'@(:[".contains(&b[i - 1]) {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < b.len() && !b" \t\r\n\"';,<>|&(){}[]\\:$".contains(&b[i]) && b[i] != 96 {
            i += 1;
        }
        if matches!(b.get(i), Some(b'$' | b'\\' | 96)) {
            continue;
        }
        let path = &src[start..i];
        let Some(candidate) = layout.relocate(path) else {
            continue;
        };
        let gz = gzip_allowed(src, start, lua);
        let log = !lua
            && !layout.logs.is_empty()
            && candidate
                .rsplit_once('/')
                .is_some_and(|(p, _)| p == layout.logs);
        if path.contains(['*', '?'])
            || exists(path, gz)
            || (log && path == candidate && exists(layout.logs, false))
        {
            continue;
        }
        utf16 += src[position..start].encode_utf16().count();
        let from = utf16;
        utf16 += path.encode_utf16().count();
        position = i;
        let (message, replacement) = if !candidate.is_empty() && candidate != path {
            result.content.push_str(&src[copied..start]);
            result.content.push_str(&candidate);
            copied = i;
            let message = if exists(&candidate, gz) || (log && exists(layout.logs, false)) {
                "Путь от другой платформы; файл найден"
            } else {
                "Путь от другой платформы; после исправления файл также нужно загрузить"
            };
            (format!("{message}: {candidate}"), candidate)
        } else {
            (
                "Файл или каталог не найден на роутере".into(),
                String::new(),
            )
        };
        result.diagnostics.push(Diagnostic {
            from,
            to: utf16,
            path: path.into(),
            message,
            replacement,
        });
    }
    result.content.push_str(&src[copied..]);
    result
}
pub fn analyze_paths(config: &Config, src: &str, kind: &str) -> Analysis {
    let platform = Resolver::current();
    let logs = platform.path(Key::StrategyLogDir).to_string_lossy();
    let conf = config.nfqws2_conf.rsplit_once('/').map_or(".", |(p, _)| p);
    analyze(
        src,
        kind == "lua",
        Layout {
            conf,
            lua: &config.lua_dir,
            blobs: &config.system_blobs_dir,
            logs: &logs,
            platform: if platform.platform() == Platform::OpenWrt {
                "OpenWrt"
            } else {
                "Keenetic / Entware"
            },
        },
        |p| Path::new(p).exists(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn layout() -> Layout<'static> {
        Layout {
            conf: "/etc/nfqws2",
            lua: "/files/lua",
            blobs: "/files/blobs",
            logs: "/var/log",
            platform: "OpenWrt",
        }
    }
    #[test]
    fn same_utf16_positions_and_literal_only_diagnostics() {
        let src="😀$(cat /opt/etc/nfqws2/x) # ignored /opt/etc/nfqws2/y\n--lua-init=@/opt/etc/nfqws2/lua/f.lua --log=/opt/var/log/nfqws2.log";
        let output = analyze(src, false, layout(), |p| {
            p == "/files/lua/f.lua.gz" || p == "/var/log"
        });
        assert_eq!(output.diagnostics.len(), 2);
        assert_eq!(
            output.diagnostics[0].from,
            src[..src.find("/opt/etc/nfqws2/lua").unwrap()]
                .encode_utf16()
                .count()
        );
        assert_eq!(output.diagnostics[0].replacement, "/files/lua/f.lua");
        assert!(output
            .diagnostics
            .iter()
            .all(|d| d.message.contains("файл найден")));
        assert!(output.content.contains("$(cat /opt/etc/nfqws2/x)"));
    }
    #[test]
    fn lua_long_comments_nested_shell_and_traversal() {
        for expr in [
            "$(cat /opt/etc/nfqws2/x)",
            "\u{60}cat /opt/etc/nfqws2/x\u{60}",
            "\u{24}{f:-$(cat /opt/etc/nfqws2/x)}",
            "<(cat /opt/etc/nfqws2/x)",
        ] {
            assert!(analyze(expr, false, layout(), |_| false)
                .diagnostics
                .is_empty());
        }
        let out=analyze("--[=[ /opt/etc/nfqws2/ignored ]=]\na=[==[/opt/etc/nfqws2/lua/a]==]\nb='/opt/etc/nfqws2/../x'",true,layout(),|_|false);
        assert_eq!(out.diagnostics.len(), 2);
        assert_eq!(out.diagnostics[0].replacement, "/files/lua/a");
        assert_eq!(out.diagnostics[1].replacement, "");
    }
}
