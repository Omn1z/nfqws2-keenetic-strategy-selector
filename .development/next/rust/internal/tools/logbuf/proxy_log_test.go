package logbuf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyLogRouting(t *testing.T) {
	Clear()
	t.Cleanup(func() {
		Init(io.Discard, "")
		Clear()
	})
	var common bytes.Buffer
	path := filepath.Join(t.TempDir(), "panel.log.proxy")
	sink := Init(&common, path)
	for _, line := range []string{
		"tgws: connected to pool",
		"tgws: Fake-TLS verify failed -> masking via example.net",
		"tgws: WS session closed (relay: error reading closed socket)",
		"tgws: H2 session closed (HTTP download: MTProto transport error -404)",
		"tgws: bad handshake (wrong secret or proto)",
		"socks5: proxy listening",
		"tgws: listener failed; reopening",
		"socks5: autostart: address in use",
		"proxy: save config failed",
		"engine reload completed",
	} {
		if _, err := fmt.Fprintln(sink, line); err != nil {
			t.Fatal(err)
		}
	}
	Append("socks5", "warn", "restart delayed")

	if out := common.String(); !strings.Contains(out, "engine reload completed") || strings.Count(out, "\n") != 1 {
		t.Errorf("unexpected common log: %q", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out := string(data); strings.Count(out, "\n") != 6 || !strings.Contains(out, "MTProto transport error") || !strings.Contains(out, "listener failed") || !strings.Contains(out, "restart delayed") {
		t.Errorf("unexpected proxy log: %q", out)
	}
	if got := Snapshot("socks5", 0); len(got) != 2 || got[0].Level != "error" || got[1].Level != "warn" {
		t.Errorf("unexpected SOCKS5 log entries: %+v", got)
	}
}

func TestProxyLogKeepsCompleteRecentRecordsWithinLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.log.proxy")
	log := newProxyLog(path)
	for record := range 160 {
		line := fmt.Sprintf("%03d %s\n", record, strings.Repeat("x", 1019))
		if _, err := io.WriteString(log, line); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if info.Size() > proxyLogLimit {
			t.Fatalf("file grew to %d bytes after record %d", info.Size(), record)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) == 0 || strings.HasPrefix(lines[0], "000 ") || !strings.HasPrefix(lines[len(lines)-1], "159 ") {
		t.Fatal("expected the newest records and eviction of the oldest ones")
	}
	for _, line := range lines {
		if len(line) != 1023 {
			t.Fatalf("retained an incomplete %d-byte record", len(line))
		}
	}
}

func TestProxyLogTrimsOversizedExistingFileOnStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.log.proxy")
	const latest = "last warning\n"
	data := strings.Repeat("old record\n", 15000) + latest
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	newProxyLog(path)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > proxyLogLimit || !strings.HasPrefix(string(got), "old record\n") || !strings.HasSuffix(string(got), latest) {
		t.Errorf("oversized log not trimmed correctly, final size: %d", len(got))
	}
}
