package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadFileRetriesAfterTemporaryFailure(t *testing.T) {
	attempts := 0
	want := []byte("release-binary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary reset stand-in", http.StatusBadGateway)
			return
		}
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "n2s.new")
	if err := downloadFile([]string{srv.URL}, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("downloaded %q, want %q", got, want)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestDownloadFileFallsBackToSecondURL(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer good.Close()

	dst := filepath.Join(t.TempDir(), "n2s.new")
	if err := downloadFile([]string{bad.URL, good.URL}, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("downloaded %q, want ok", got)
	}
}
