package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	source := t.TempDir()
	files := map[string]string{
		"conn/conn.go":          "package conn\nconst IdealBatchSize = 128\n",
		"conn/bind_std.go":      "package conn\nconst udpSegmentMaxDatagrams = 64\n",
		"conn/bind_std_test.go": "package conn\n",
		"device/device_test.go": "package device\n",
		"device/queueconstants_default.go": `package device
import "github.com/amnezia-vpn/amneziawg-go/v3/conn"
const (
QueueStagedSize            = conn.IdealBatchSize
QueueOutboundSize          = 1024
QueueInboundSize           = 1024
QueueHandshakeSize         = 1024
MaxSegmentSize             = (1 << 16) - 1
PreallocatedBuffersPerPool = 0
)
`,
	}
	for name, text := range files {
		path := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return source
}

func TestPrepareLeavesPinnedCheckoutUnchanged(t *testing.T) {
	source := fixture(t)
	originalPath := filepath.Join(source, "conn", "conn.go")
	original, _ := os.ReadFile(originalPath)
	path, err := prepare(source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Replace map[string]string }
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Replace) != 4 {
		t.Fatalf("overlay covers %d source files", len(manifest.Replace))
	}
	patched, err := os.ReadFile(manifest.Replace[originalPath])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patched), "IdealBatchSize = 64") {
		t.Fatal("router batch profile missing")
	}
	after, _ := os.ReadFile(originalPath)
	if string(after) != string(original) {
		t.Fatal("upstream checkout was modified")
	}
	queuePath := filepath.Join(source, "device", "queueconstants_default.go")
	queue, err := os.ReadFile(manifest.Replace[queuePath])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(queue), "MaxSegmentSize             = (1 << 16) - 1") {
		t.Fatal("full-size GSO/GRO buffers must remain available")
	}
	if !strings.Contains(string(queue), "PreallocatedBuffersPerPool = 0") {
		t.Fatal("a blocking pool limit may deadlock batches awaiting a handshake")
	}
}

func TestPrepareRejectsChangedUpstream(t *testing.T) {
	for _, change := range []struct{ path, old, new string }{
		{"conn/bind_std.go", "udpSegmentMaxDatagrams = 64", "udpSegmentMaxDatagrams = 128"},
		{"conn/conn.go", "IdealBatchSize = 128", "IdealBatchSize = 256"},
		{"device/queueconstants_default.go", "QueueInboundSize           = 1024", "QueueInboundSize           = 2048"},
	} {
		t.Run(change.path, func(t *testing.T) {
			source := fixture(t)
			path := filepath.Join(source, filepath.FromSlash(change.path))
			data, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(strings.Replace(string(data), change.old, change.new, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := prepare(source, t.TempDir()); err == nil {
				t.Fatal("changed upstream silently accepted")
			}
		})
	}
}

func TestPrepareRejectsOutputInsideSource(t *testing.T) {
	source := fixture(t)
	for _, output := range []string{source, filepath.Join(source, "generated")} {
		if _, err := prepare(source, output); err == nil {
			t.Fatalf("output %q could overwrite source files", output)
		}
	}
}
