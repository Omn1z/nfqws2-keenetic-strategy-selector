// Command engine-memory-overlay prepares the router memory profile without
// changing the pinned upstream checkout. Both release and audit builds use it.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed testdata/device_memory_tests.go.txt
var deviceMemoryTests string

//go:embed testdata/conn_memory_tests.go.txt
var connMemoryTests string

type replacement struct{ old, new string }

type sourcePatch struct {
	path         string
	replacements []replacement
}

var routerPatches = []sourcePatch{
	{"conn/conn.go", []replacement{
		{"IdealBatchSize = 128", "IdealBatchSize = 64"},
	}},
	{"device/queueconstants_default.go", []replacement{
		{"QueueStagedSize            = conn.IdealBatchSize", "QueueStagedSize            = 8"},
		{"QueueOutboundSize          = 1024", "QueueOutboundSize          = 32"},
		{"QueueInboundSize           = 1024", "QueueInboundSize           = 32"},
		{"QueueHandshakeSize         = 1024", "QueueHandshakeSize         = 128"},
		// The staged size no longer refers to conn. Remove the unused import.
		{"import \"github.com/amnezia-vpn/amneziawg-go/v3/conn\"\n", ""},
	}},
}

func prepare(sourceDir, outputDir string) (string, error) {
	sourceDir, err := filepath.Abs(sourceDir)
	if err != nil {
		return "", err
	}
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		return "", err
	}
	if relative, err := filepath.Rel(sourceDir, outputDir); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("overlay output must be outside the pinned source checkout")
	}
	// GRO splits at most 64 UDP segments into the batch. A smaller batch would
	// make receiveIP's integer division zero and pass an empty slice to ReadBatch.
	bind, err := os.ReadFile(filepath.Join(sourceDir, "conn", "bind_std.go"))
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(bind), "udpSegmentMaxDatagrams = 64") {
		return "", fmt.Errorf("upstream UDP segmentation changed; review the router memory profile")
	}
	type overlay struct{ Replace map[string]string }
	manifest := overlay{Replace: make(map[string]string)}
	for _, patch := range routerPatches {
		original := filepath.Join(sourceDir, filepath.FromSlash(patch.path))
		content, err := os.ReadFile(original)
		if err != nil {
			return "", err
		}
		text := strings.ReplaceAll(string(content), "\r\n", "\n")
		for _, replacement := range patch.replacements {
			if strings.Count(text, replacement.old) != 1 {
				return "", fmt.Errorf("%s: upstream memory constants changed; review the router memory profile", patch.path)
			}
			text = strings.Replace(text, replacement.old, replacement.new, 1)
		}
		patched := filepath.Join(outputDir, filepath.FromSlash(patch.path))
		if err := os.MkdirAll(filepath.Dir(patched), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(patched, []byte(text), 0o644); err != nil {
			return "", err
		}
		manifest.Replace[original] = patched
	}
	// Append tests to an existing upstream test file so both Go file discovery
	// and older toolchains see them when the overlay is passed to go test.
	for name, addition := range map[string]string{
		"device/device_test.go": deviceMemoryTests,
		"conn/bind_std_test.go": connMemoryTests,
	} {
		originalTests := filepath.Join(sourceDir, filepath.FromSlash(name))
		tests, err := os.ReadFile(originalTests)
		if err != nil {
			return "", err
		}
		patchedTests := filepath.Join(outputDir, filepath.FromSlash(name))
		if err := os.WriteFile(patchedTests, append(tests, []byte(addition)...), 0o644); err != nil {
			return "", err
		}
		manifest.Replace[originalTests] = patchedTests
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(outputDir, "overlay.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func main() {
	source := flag.String("source", "", "pinned AmneziaWG source checkout")
	output := flag.String("output", "", "generated overlay directory")
	flag.Parse()
	if *source == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}
	path, err := prepare(*source, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(path)
}
