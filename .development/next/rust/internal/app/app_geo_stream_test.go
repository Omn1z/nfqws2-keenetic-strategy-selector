package app

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"nfqws2strategy/internal/tools/modules"
)

type geoFillReader struct{}

func (geoFillReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestGeoMultipartStreamsLargeFileAndLateKind(t *testing.T) {
	a := geoTestApp(t)
	const size = 19 << 20
	body := io.MultiReader(
		strings.NewReader("--geo\r\nContent-Disposition: form-data; name=\"file\"; filename=\"long.dat\"\r\n\r\n"),
		io.LimitReader(geoFillReader{}, size), strings.NewReader("end\r\n--geo\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ngeoip\r\n--geo--\r\n"),
	)
	name, kind, err := a.SaveGeoUpload(multipart.NewReader(body, "geo"), "")
	if err != nil || name != "long.dat" || kind != "geoip" || a.geoMeta()[name] != kind {
		t.Fatalf("upload returned %q %q %v", name, kind, err)
	}
	f, err := os.Open(filepath.Join(a.geoDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() != size+3 {
		t.Fatalf("truncated file: %v, %v", info, err)
	}
	var tail [3]byte
	if _, err := f.ReadAt(tail[:], size); err != nil || string(tail[:]) != "end" {
		t.Fatalf("missing suffix: %q, %v", tail, err)
	}
}

func TestGeoIncompleteFormPreservesOriginalAndDiscardsTemp(t *testing.T) {
	a := geoTestApp(t)
	if err := a.SaveGeoFile("original.dat", "text", []byte("original")); err != nil {
		t.Fatal(err)
	}
	const file = "--geo\r\nContent-Disposition: form-data; name=\"file\"; filename=\"original.dat\"\r\n\r\nreplacement"
	for _, suffix := range []string{"", "\r\n--geo\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ngeoip"} {
		if _, _, err := a.SaveGeoUpload(multipart.NewReader(strings.NewReader(file+suffix), "geo"), ""); err == nil {
			t.Fatal("accepted truncated multipart body")
		}
	}
	b, err := os.ReadFile(filepath.Join(a.geoDir(), "original.dat"))
	if err != nil || string(b) != "original" || a.geoMeta()["original.dat"] != "text" {
		t.Fatalf("interruption replaced original: %q, %v", b, err)
	}
	temps, err := os.ReadDir(filepath.Join(a.geoDir(), ".store"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("temporary files after interruption: %v, %v", temps, err)
	}
}

func TestGeoFailedRenameRollsBackKindAndKeepsOtherFiles(t *testing.T) {
	a := geoTestApp(t)
	if err := a.SaveGeoFile("kept.txt", "text", []byte("kept")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(a.geoDir(), "conflict.dat"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveGeoFile("conflict.dat", "geoip", []byte("new")); err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
	meta := a.geoMeta()
	if len(meta) != 1 || meta["kept.txt"] != "text" {
		t.Fatalf("rename failure left mismatched metadata: %v", meta)
	}
}

func TestGeoHTTPFetchPreservesFileOnIncompleteBody(t *testing.T) {
	a := geoTestApp(t)
	const n = 17 << 20
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, source := range []struct {
		body    io.Reader
		length  int64
		success bool
	}{
		{strings.NewReader("partial"), n, false},
		{io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(io.ErrUnexpectedEOF)), -1, false},
		{strings.NewReader(""), -1, false},
		{io.LimitReader(geoFillReader{}, n), n, true},
	} {
		if err := a.SaveGeoFile("geoip.dat", "text", []byte("previous")); err != nil {
			t.Fatal(err)
		}
		http.DefaultTransport = selfUpdateRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, ContentLength: source.length, Body: io.NopCloser(source.body)}, nil
		})
		size, err := a.fetchGeoFile("https://geo.invalid/ip", "geoip.dat", "geoip")
		if source.success {
			if err != nil || size != n || a.geoMeta()["geoip.dat"] != "geoip" {
				t.Fatalf("large fetch: %d, %v", size, err)
			}
		} else {
			data, readErr := os.ReadFile(filepath.Join(a.geoDir(), "geoip.dat"))
			if err == nil || readErr != nil || string(data) != "previous" || a.geoMeta()["geoip.dat"] != "text" {
				t.Fatalf("partial fetch modified file: %q %v %v", data, err, readErr)
			}
		}
	}
}

func TestSlowGeoStreamAllowsConcurrentStoreAndMetadataEdits(t *testing.T) {
	a := geoTestApp(t)
	input, writer := io.Pipe()
	defer writer.Close()
	done := make(chan error, 1)
	go func() { _, err := a.saveGeoStream("slow.dat", "geoip", input); done <- err }()
	if _, err := io.WriteString(writer, "in progress"); err != nil {
		t.Fatal(err)
	}
	concurrent := make(chan struct{})
	go func() {
		var group sync.WaitGroup
		for i := range 8 {
			group.Go(func() {
				if err := a.SaveGeoFile(fmt.Sprintf("small%d", i), "text", []byte("data")); err != nil {
					t.Error(err)
				}
			})
		}
		group.Wait()
		close(concurrent)
	}()
	select {
	case <-concurrent:
	case <-time.After(5 * time.Second):
		t.Fatal("slow reader blocked other store writes")
	}
	writer.Close()
	if err := <-done; err != nil || len(a.geoMeta()) != 9 {
		t.Fatalf("concurrent writes lost metadata: %v, %v", a.geoMeta(), err)
	}
}

func TestGeoFetchMergesStatusWithConcurrentSettingsEdits(t *testing.T) {
	if modules.Compact {
		root := t.TempDir()
		t.Setenv("N2S_MODULE_DIR", root)
		dir := filepath.Join(root, "geo")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		name := "nfqws2-geo"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0755); err != nil {
			t.Fatal(err)
		}
	}
	a := geoTestApp(t)
	settings := &GeoAutoConfig{Enabled: true, GeoSiteURL: "https://geo.invalid/site", GeoIPURL: "https://geo.invalid/ip", IntervalHours: 12}
	if err := a.SetGeoAuto(settings); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/site" {
			// Editing settings in the middle of the first fetch must succeed immediately.
			settings.Enabled, settings.IntervalHours = false, 48
			if err := a.SetGeoAuto(settings); err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: 206, Body: io.NopCloser(strings.NewReader("partial"))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("complete"))}, nil
	})
	updated, err := a.FetchGeoNow()
	if err == nil || updated.Enabled || updated.IntervalHours != 48 || updated.LastGeoIPLen != 8 || updated.LastGeoSiteLen != 0 || *updated != *a.GeoAuto() {
		t.Fatalf("inconsistent settings after partial fetch: %+v, %v", updated, err)
	}
	if err := a.SetGeoAuto(settings); err != nil || a.GeoAuto().LastGeoIPLen != 8 {
		t.Fatalf("stale settings update lost download status: %v", err)
	}
}
