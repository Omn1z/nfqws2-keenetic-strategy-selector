package nfqws2

import (
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestEditorPathDiagnosticOffsetsAndFixesProperty(t *testing.T) {
	random := rand.New(rand.NewSource(37))
	parts := []string{"😀", "текст", " ", "\n", "\"", "'", "# comment\n", "--[[ ignored ]]", "$(echo ", ")", "${X:-", "}", "X=", "--hostlist=", "--lua-init=@", "/opt/etc/nfqws2/lua/test.lua", "/opt/etc/nfqws2/lists/user.list", "/etc/nfqws2/lists/user.list", "/tmp/file", "\\\"", "[=[", "]=]"}
	layout := pathLayout{conf: "/etc/nfqws2", lua: "/etc/nfqws2/lua", blobs: "/etc/nfqws2/blobs"}
	stat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	for n := 0; n < 1000; n++ {
		var source strings.Builder
		for k := 0; k < 40; k++ {
			source.WriteString(parts[random.Intn(len(parts))])
		}
		kind := "conf"
		if n%2 == 0 {
			kind = "lua"
		}
		text := source.String()
		a := analyzePaths(text, kind, layout, stat)
		original := utf16.Encode([]rune(text))
		reconstructed := append([]uint16(nil), original...)
		previous := len(original)
		for i := len(a.Diagnostics) - 1; i >= 0; i-- {
			d := a.Diagnostics[i]
			if d.From < 0 || d.To <= d.From || d.To > previous || string(utf16.Decode(original[d.From:d.To])) != d.Path {
				t.Fatalf("invalid UTF16 span %+v in %q", d, text)
			}
			previous = d.From
			if d.Replacement != "" {
				next := append([]uint16(nil), reconstructed[:d.From]...)
				next = append(next, utf16.Encode([]rune(d.Replacement))...)
				reconstructed = append(next, reconstructed[d.To:]...)
			}
		}
		if fixed := string(utf16.Decode(reconstructed)); fixed != a.Content {
			t.Fatalf("fix-all disagrees with individual diagnostics: %q != %q", a.Content, fixed)
		}
	}
}

func TestEditorPathRepair(t *testing.T) {
	for _, target := range []string{"/etc/nfqws2", "/opt/etc/nfqws2"} {
		t.Run(target, func(t *testing.T) {
			foreign := "/opt/etc/nfqws2"
			if target == foreign {
				foreign = "/etc/nfqws2"
			}
			layout := pathLayout{conf: target, lua: target + "/lua", blobs: target + "/blobs"}
			src := "# 😀 Комментарий " + foreign + "/ignored\nNFQWS_ARGS=\"--hostlist=" + foreign + "/lists/user.list --blob=@" + foreign + "/blobs/quic.bin\"\n"
			calls := map[string]int{}
			stat := func(p string) (os.FileInfo, error) {
				calls[p]++
				if strings.HasPrefix(p, target+"/") {
					return nil, nil
				}
				return nil, os.ErrNotExist
			}
			a := analyzePaths(src, "conf", layout, stat)
			if len(a.Diagnostics) != 2 {
				t.Fatalf("diagnostics: %+v", a)
			}
			if a.Diagnostics[0].From != len([]rune("# 😀 Комментарий "+foreign+"/ignored\nNFQWS_ARGS=\"--hostlist="))+1 {
				t.Fatalf("not UTF16: %+v", a.Diagnostics[0])
			}
			if !strings.Contains(a.Content, "# 😀 Комментарий "+foreign+"/ignored") || !strings.Contains(a.Content, "--blob=@"+target+"/blobs/quic.bin") {
				t.Fatal(a.Content)
			}
			if again := analyzePaths(a.Content, "conf", layout, stat); len(again.Diagnostics) != 0 || again.Content != a.Content {
				t.Fatal("not idempotent", again)
			}
		})
	}
}

func TestEditorPathLeavesExpressionsAndUnknownRootsAlone(t *testing.T) {
	layout := pathLayout{conf: "/etc/nfqws2", lua: "/etc/nfqws2/lua", blobs: "/etc/nfqws2/blobs"}
	src := "# /opt/etc/nfqws2/a\nX=\"/opt/etc/nfqws2/$FILE /opt/etc/nfqws2/*.list /tmp/output /opt/etc/nfqws2evil/a https://example.com/opt/etc/nfqws2/a $ROOT/opt/etc/nfqws2/a $(echo /tmp/x)\"\n"
	a := analyzePaths(src, "conf", layout, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
	if a.Content != src || len(a.Diagnostics) != 0 {
		t.Fatalf("unexpected rewrite: %+v", a)
	}
}

func TestEditorPathMissingAndTraversal(t *testing.T) {
	layout := pathLayout{conf: "/etc/nfqws2"}
	src := `A="/etc/nfqws2/missing /opt/etc/nfqws2/../secret /opt/etc/nfqws2/new.list"`
	a := analyzePaths(src, "conf", layout, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
	if len(a.Diagnostics) != 3 || a.Diagnostics[0].Replacement != "" || a.Diagnostics[1].Replacement != "" || a.Diagnostics[2].Replacement != "/etc/nfqws2/new.list" {
		t.Fatalf("%+v", a)
	}
}

func TestEditorPathLuaAndStatDedup(t *testing.T) {
	n := 0
	a := analyzePaths("-- /opt/etc/nfqws2/ignored\nx='/opt/etc/nfqws2/lua/foo.lua'\ny='/opt/etc/nfqws2/lua/foo.lua'", "lua", pathLayout{conf: "/etc/nfqws2", lua: "/custom/lua"}, func(string) (os.FileInfo, error) { n++; return nil, os.ErrNotExist })
	if len(a.Diagnostics) != 2 || n != 2 || a.Diagnostics[0].Replacement != "/custom/lua/foo.lua" {
		t.Fatalf("%+v, stats=%d", a, n)
	}
}

func TestEditorPathLuaLongCommentsAndStrings(t *testing.T) {
	layout := pathLayout{conf: "/etc/nfqws2", lua: "/etc/nfqws2/lua"}
	for _, equals := range []string{"", "=", "===="} {
		open, close := "["+equals+"[", "]"+equals+"]"
		src := "--" + open + " comment\n/opt/etc/nfqws2/ignored\n-- not a new comment\n" + close + "\nx=" + open + "/opt/etc/nfqws2/lua/a.lua" + close + "\ny='-- /opt/etc/nfqws2/lua/b.lua'\n--" + open + " unfinished\n/opt/etc/nfqws2/also-ignored"
		a := analyzePaths(src, "lua", layout, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
		if len(a.Diagnostics) != 2 || a.Diagnostics[0].Path != "/opt/etc/nfqws2/lua/a.lua" || a.Diagnostics[1].Path != "/opt/etc/nfqws2/lua/b.lua" {
			t.Fatalf("delimiter %q: %+v", equals, a)
		}
		if !strings.Contains(a.Content, "/opt/etc/nfqws2/ignored") || !strings.Contains(a.Content, "/opt/etc/nfqws2/also-ignored") || !strings.Contains(a.Content, open+"/etc/nfqws2/lua/a.lua"+close) {
			t.Fatal(a.Content)
		}
	}
	a := analyzePaths("x=[=[-- literal, not comment\n/opt/etc/nfqws2/lua/a.lua]=]\ny='/opt/etc/nfqws2/lua/b.lua'", "lua", layout, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
	if len(a.Diagnostics) != 2 {
		t.Fatalf("comment marker inside long string swallowed paths: %+v", a)
	}
}

func TestEditorPathsIgnoreShellSubstitutions(t *testing.T) {
	const ignored = "/opt/etc/nfqws2/ignored"
	for _, expr := range []string{
		"$(cat " + ignored + ")", "${FILE:-" + ignored + "}", "${FILE:=$(cat " + ignored + ")}",
		"`cat " + ignored + "`", "\"`cat " + ignored + "`\"", "\"$(cat '" + ignored + "')\"",
		"\"$(echo \"$(cat " + ignored + ")\")\"", "$(( $(cat " + ignored + ") + 1 ))",
		"<(cat " + ignored + ")", ">(cat " + ignored + ")", "$(echo ')' \"(\"; cat " + ignored + ")",
		"$( # ignored parenthesis )\ncat " + ignored + "\n)",
	} {
		t.Run(expr, func(t *testing.T) {
			src := "VALUE=" + expr + "\nLITERAL='/opt/etc/nfqws2/actual.list'"
			a := analyzePaths(src, "conf", pathLayout{conf: "/etc/nfqws2"}, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
			if len(a.Diagnostics) != 1 || a.Diagnostics[0].Path != "/opt/etc/nfqws2/actual.list" || !strings.Contains(a.Content, expr) {
				t.Fatalf("rewrote substitution: %+v", a)
			}
		})
	}
	for _, src := range []string{"X=$(cat " + ignored, "X=${FILE:-" + ignored, "X=`cat " + ignored, strings.Repeat("$(", 1000) + ignored + strings.Repeat(")", 1000)} {
		a := analyzePaths(src, "conf", pathLayout{conf: "/etc/nfqws2"}, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist })
		if len(a.Diagnostics) != 0 || a.Content != src {
			t.Fatalf("rewrote unfinished/excessive expansion: %+v", a)
		}
	}
}

func TestEditorPathsLuaInitCompressedFallbackOnly(t *testing.T) {
	layout := pathLayout{conf: "/etc/nfqws2", lua: "/etc/nfqws2/lua"}
	stat := func(p string) (os.FileInfo, error) {
		if p == "/etc/nfqws2/lua/library.lua.gz" || p == "/etc/nfqws2/lists/user.list.gz" || p == "/etc/nfqws2/blobs/quic.bin.gz" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	for _, src := range []string{"NFQWS_ARGS='--lua-init=@/etc/nfqws2/lua/library.lua'", "NFQWS_ARGS=\"--lua-init='@/etc/nfqws2/lua/library.lua'\""} {
		a := analyzePaths(src, "conf", layout, stat)
		if len(a.Diagnostics) != 0 || a.Content != src {
			t.Fatalf("working compressed Lua diagnosed: %+v", a)
		}
	}
	src := "NFQWS_ARGS='--lua-init=@/opt/etc/nfqws2/lua/library.lua'"
	a := analyzePaths(src, "conf", layout, stat)
	if len(a.Diagnostics) != 1 || a.Diagnostics[0].Replacement != "/etc/nfqws2/lua/library.lua" || !strings.Contains(a.Diagnostics[0].Message, "файл найден") {
		t.Fatalf("compressed target not recognized: %+v", a)
	}
	for _, tc := range []struct{ src, kind string }{
		{"--hostlist=/etc/nfqws2/lists/user.list --blob=quic:@/etc/nfqws2/blobs/quic.bin", "conf"},
		{"io.open('/etc/nfqws2/lua/library.lua')", "lua"},
		{"X='/etc/nfqws2/lua/library.lua'", "conf"},
	} {
		a := analyzePaths(tc.src, tc.kind, layout, stat)
		if len(a.Diagnostics) == 0 {
			t.Fatalf("gzip masked literal missing file: %+v", tc)
		}
	}
}

func BenchmarkEditorPaths(b *testing.B) {
	src := strings.Repeat("X=\"--hostlist=/opt/etc/nfqws2/lists/user.list\"\n", 100)
	layout := pathLayout{conf: "/etc/nfqws2"}
	stat := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	b.ReportAllocs()
	for b.Loop() {
		analyzePaths(src, "conf", layout, stat)
	}
}

func TestEditorPathsLogDestinationsUsePlatformDirWithoutRequiringFile(t *testing.T) {
	layout := pathLayout{conf: "/etc/nfqws2", logs: "/var/log"}
	stat := func(p string) (os.FileInfo, error) {
		if p == "/var/log" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	src := `LOG_DEBUG_PATH="@/opt/var/log/nfqws2-debug.log"`
	a := analyzePaths(src, "conf", layout, stat)
	if len(a.Diagnostics) != 1 || a.Diagnostics[0].Replacement != "/var/log/nfqws2-debug.log" {
		t.Fatal(a)
	}
	if again := analyzePaths(a.Content, "conf", layout, stat); len(again.Diagnostics) != 0 {
		t.Fatal(again)
	}
	if ignored := analyzePaths(`X="/opt/var/log/another-app.log"`, "conf", layout, stat); len(ignored.Diagnostics) != 0 {
		t.Fatal(ignored)
	}
}
