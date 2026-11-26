package server

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/nfqws2"
)

func assetMultipartRequest(t *testing.T, fields map[string]string, contents []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if contents != nil {
		f, err := w.CreateFormFile("file", "strategy.zip")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", &body)
	r.Header.Set("Content-Type", w.FormDataContentType())
	return r
}

func TestStrategyArchiveHTTPInputIsUnambiguousAndBounded(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		r := assetMultipartRequest(t, nil, []byte("zip body"))
		data, id, err := strategyArchiveInput(httptest.NewRecorder(), r)
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		if err != nil || id != "" || string(data) != "zip body" {
			t.Fatalf("input=%q %q %v", data, id, err)
		}
	})
	t.Run("snapshot", func(t *testing.T) {
		r := assetMultipartRequest(t, map[string]string{"snapshot": "snapshot-id"}, nil)
		data, id, err := strategyArchiveInput(httptest.NewRecorder(), r)
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		if err != nil || id != "snapshot-id" || data != nil {
			t.Fatalf("input=%q %q %v", data, id, err)
		}
	})
	t.Run("both", func(t *testing.T) {
		r := assetMultipartRequest(t, map[string]string{"snapshot": "snapshot-id"}, []byte("zip"))
		_, _, err := strategyArchiveInput(httptest.NewRecorder(), r)
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		if err == nil {
			t.Fatal("ambiguous source accepted")
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		r := assetMultipartRequest(t, nil, bytes.Repeat([]byte("x"), 4097))
		if err := parseAssetMultipart(httptest.NewRecorder(), r, 4096); err != nil {
			t.Fatal(err)
		}
		defer r.MultipartForm.RemoveAll()
		if _, err := multipartFileBytes(r, 4096); err == nil {
			t.Fatal("truncated oversized upload accepted")
		}
	})
	t.Run("oversized fields", func(t *testing.T) {
		r := assetMultipartRequest(t, map[string]string{"path": strings.Repeat("x", (1<<20)+4097)}, nil)
		if err := parseAssetMultipart(httptest.NewRecorder(), r, 4096); err == nil {
			r.MultipartForm.RemoveAll()
			t.Fatal("unbounded multipart fields")
		}
	})
}

func TestAssetHTTPErrorStatus(t *testing.T) {
	for _, tt := range []struct {
		err    error
		status int
	}{{nfqws2.ErrAssetConflict, 409}, {nfqws2.ErrArchiveChanged, 409}, {&http.MaxBytesError{Limit: 4}, 413}, {errors.New("invalid"), 400}} {
		w := httptest.NewRecorder()
		assetHTTPError(w, tt.err)
		if w.Code != tt.status {
			t.Errorf("%v: %d != %d", tt.err, w.Code, tt.status)
		}
	}
}
