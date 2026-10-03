package nfqws2

import (
	"os"
	"path"
	"strings"
	"unicode/utf8"

	routerpath "nfqws2strategy/internal/tools/path"
)

// Editor offsets are UTF-16 positions, as used by JavaScript and CodeMirror.
type PathDiagnostic struct {
	From        int    `json:"from"`
	To          int    `json:"to"`
	Path        string `json:"path"`
	Message     string `json:"message"`
	Replacement string `json:"replacement,omitempty"`
}
type PathAnalysis struct {
	Diagnostics []PathDiagnostic `json:"diagnostics"`
	Content     string           `json:"content"`
	Platform    string           `json:"platform"`
}

// AnalyzePaths never evaluates the configuration. Only literal paths below a
// known NFQWS root are considered: shell variables, commands and comments are
// left alone. Custom paths outside these roots retain their original meaning.
func (m *Manager) AnalyzePaths(content, kind string) PathAnalysis {
	platform := "Keenetic / Entware"
	if routerpath.IsOpenWrt() {
		platform = "OpenWrt"
	}
	return analyzePaths(content, kind, pathLayout{
		conf: path.Dir(m.cfg.Nfqws2Conf), lua: m.cfg.LuaDir,
		blobs: m.cfg.SystemBlobsDir, logs: routerpath.Path(routerpath.StrategyLogDir), platform: platform,
	}, os.Stat)
}

type pathLayout struct{ conf, lua, blobs, logs, platform string }
type pathStat func(string) (os.FileInfo, error)

func (l pathLayout) relocate(p string) (string, bool) {
	// Standard NFQWS log destinations are output paths. Their parent follows
	// the same cached platform layout; unrelated files below /var stay alone.
	if l.logs != "" {
		for _, root := range []string{"/opt/var/log", "/var/log"} {
			for _, name := range []string{"nfqws2.log", "nfqws2-debug.log", "nfqws.log", "nfqws-debug.log"} {
				if p == root+"/"+name {
					return l.logs + "/" + name, true
				}
			}
		}
	}
	for _, root := range []string{"/opt/etc/nfqws2", "/etc/nfqws2", "/opt/etc/nfqws", "/etc/nfqws"} {
		if p != root && !strings.HasPrefix(p, root+"/") {
			continue
		}
		rel := strings.TrimPrefix(p, root)
		// Cleaning a path containing '..' can change its meaning. Diagnose it,
		// but do not silently redirect it to another file.
		for _, part := range strings.Split(rel, "/") {
			if part == ".." || part == "." {
				return "", true
			}
		}
		for _, entry := range []struct{ prefix, target string }{{"/lua", l.lua}, {"/blobs", l.blobs}} {
			if entry.target != "" && (rel == entry.prefix || strings.HasPrefix(rel, entry.prefix+"/")) {
				return entry.target + strings.TrimPrefix(rel, entry.prefix), true
			}
		}
		return l.conf + rel, true
	}
	// Configured custom directories also get existence diagnostics.
	for _, root := range []string{l.conf, l.lua, l.blobs} {
		if root != "" && (p == root || strings.HasPrefix(p, root+"/")) {
			return p, true
		}
	}
	return "", false
}

func pathEnd(c byte) bool { return strings.ContainsRune(" \t\r\n\"'`;,<>|&(){}[]\\:$", rune(c)) }

func luaInitGzipFallback(src string, from int, kind string) bool {
	if kind == "lua" || from == 0 || src[from-1] != '@' {
		return false
	}
	prefix := strings.TrimRight(src[:from-1], "\"'")
	const flag = "--lua-init="
	if !strings.HasSuffix(prefix, flag) {
		return false
	}
	start := len(prefix) - len(flag)
	return start == 0 || strings.ContainsRune(" \t\r\n\"'", rune(prefix[start-1]))
}

func luaLongBracket(src string, start int) (body int, close string) {
	if start >= len(src) || src[start] != '[' {
		return 0, ""
	}
	i := start + 1
	for i < len(src) && src[i] == '=' {
		i++
	}
	if i < len(src) && src[i] == '[' {
		return i + 1, "]" + src[start+1:i] + "]"
	}
	return 0, ""
}

func skipBacktick(src string, start int) int {
	for i := start + 1; i < len(src); i++ {
		if src[i] == '\\' {
			i++
		} else if src[i] == '`' {
			return i + 1
		}
	}
	return len(src)
}

// Skip shell substitutions as syntax rather than inspecting their output as a
// literal filename. This also handles nested substitutions inside double quotes.
// Excessive or unfinished nesting is left untouched, never guessed or executed.
func skipShellExpansion(src string, start, nesting int) int {
	if nesting >= 64 {
		return len(src)
	}
	open := src[start+1]
	close := byte(')')
	if open == '{' {
		close = '}'
	}
	depth, quote := 1, byte(0)
	for i := start + 2; i < len(src); {
		c := src[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			i++
			continue
		}
		if c == '\\' {
			i += 2
			continue
		}
		if c == '`' {
			i = skipBacktick(src, i)
			continue
		}
		if i+1 < len(src) && (c == '$' && (src[i+1] == '(' || src[i+1] == '{') || quote == 0 && (c == '<' || c == '>') && src[i+1] == '(') {
			i = skipShellExpansion(src, i, nesting+1)
			continue
		}
		if c == '"' {
			if quote == '"' {
				quote = 0
			} else {
				quote = '"'
			}
			i++
			continue
		}
		if quote == 0 {
			if c == '\'' {
				quote = c
				i++
				continue
			}
			if open == '(' && c == '#' && (i == 0 || strings.ContainsRune(" \t\n\r;", rune(src[i-1]))) {
				if end := strings.IndexByte(src[i:], '\n'); end >= 0 {
					i += end + 1
					continue
				}
				return len(src)
			}
			if c == open {
				depth++
			}
			if c == close {
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		i++
	}
	return len(src)
}

func analyzePaths(src, kind string, layout pathLayout, stat pathStat) PathAnalysis {
	out := PathAnalysis{Diagnostics: []PathDiagnostic{}, Content: src, Platform: layout.platform}
	// Diagnostic offsets are emitted in ascending order. Convert each prefix
	// at most once without allocating an integer array for every source byte.
	bytePosition, units := 0, 0
	position := func(end int) int {
		for bytePosition < end {
			r, n := utf8.DecodeRuneInString(src[bytePosition:end])
			bytePosition += n
			units++
			if r > 0xffff {
				units++
			}
		}
		return units
	}
	quote := byte(0)
	longClose := ""
	var fixed strings.Builder
	last := 0
	checked := map[string]bool{}
	rawExists := func(p string) bool {
		if val, ok := checked[p]; ok {
			return val
		}
		_, err := stat(p)
		ok := err == nil
		checked[p] = ok
		return ok
	}
	exists := func(p string, allowGzip bool) bool {
		// nfqws2's lua_file_open_test tries file and then file.gz for
		// --lua-init=@file. Ordinary Lua, list and blob readers do not.
		return rawExists(p) || allowGzip && !strings.HasSuffix(p, ".gz") && rawExists(p+".gz")
	}
	for i := 0; i < len(src); {
		c := src[i]
		if longClose != "" && strings.HasPrefix(src[i:], longClose) {
			i += len(longClose)
			longClose = ""
			continue
		}
		if longClose == "" && c == '\\' && (kind == "lua" || quote != '\'') {
			i += 2
			continue
		}
		if quote == 0 && longClose == "" && ((kind != "lua" && c == '#' && (i == 0 || strings.ContainsRune(" \t\n\r;", rune(src[i-1])))) || (kind == "lua" && strings.HasPrefix(src[i:], "--"))) {
			if kind == "lua" {
				if body, close := luaLongBracket(src, i+2); close != "" {
					if end := strings.Index(src[body:], close); end >= 0 {
						i = body + end + len(close)
						continue
					}
					break
				}
			}
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j + 1
				continue
			}
			break
		}
		if kind == "lua" && quote == 0 && longClose == "" && c == '[' {
			if body, close := luaLongBracket(src, i); close != "" {
				i, longClose = body, close
				continue
			}
		}
		if kind != "lua" && quote != '\'' {
			if c == '`' {
				i = skipBacktick(src, i)
				continue
			}
			if i+1 < len(src) && (c == '$' && (src[i+1] == '(' || src[i+1] == '{') || quote == 0 && (c == '<' || c == '>') && src[i+1] == '(') {
				i = skipShellExpansion(src, i, 0)
				continue
			}
		}
		if longClose == "" && (c == '\'' || c == '"' || c == '`') {
			if quote == 0 {
				quote = c
			} else if quote == c {
				quote = 0
			}
			i++
			continue
		}
		if c != '/' || quote == '`' {
			i++
			continue
		}
		// A slash in a URL, variable expression or longer path is not a root.
		if i > 0 && !strings.ContainsRune(" \t\n\r=\"'@(:[", rune(src[i-1])) {
			i++
			continue
		}
		end := i + 1
		for end < len(src) && !pathEnd(src[end]) {
			end++
		}
		p := src[i:end]
		if end < len(src) && (src[end] == '$' || src[end] == '`' || src[end] == '\\') {
			i = end
			continue
		}
		candidate, known := layout.relocate(p)
		allowGzip := luaInitGzipFallback(src, i, kind)
		outputLog := kind != "lua" && layout.logs != "" && path.Dir(candidate) == layout.logs
		if !known || strings.ContainsAny(p, "*?") || exists(p, allowGzip) || outputLog && p == candidate && exists(path.Dir(p), false) {
			i = end
			continue
		}
		d := PathDiagnostic{From: position(i), To: position(end), Path: p, Message: "Файл или каталог не найден на роутере"}
		if candidate != "" && candidate != p {
			d.Replacement = candidate
			if exists(candidate, allowGzip) || outputLog && exists(path.Dir(candidate), false) {
				d.Message = "Путь от другой платформы; файл найден: " + candidate
			} else {
				d.Message = "Путь от другой платформы; после исправления файл также нужно загрузить: " + candidate
			}
			if last == 0 {
				fixed.Grow(len(src))
			}
			fixed.WriteString(src[last:i])
			fixed.WriteString(candidate)
			last = end
		}
		out.Diagnostics = append(out.Diagnostics, d)
		i = end
	}
	if last != 0 {
		fixed.WriteString(src[last:])
		out.Content = fixed.String()
	}
	return out
}
