//go:build linux

package awgroute

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSpeedSampleRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != "bytes=0-3" {
			t.Errorf("Range = %q", got)
		}
		w.Header().Set("Content-Range", "bytes 0-3/26")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "abcd")
	}))
	defer server.Close()
	sample := doStreamSample(t.Context(), server.URL, "", time.Second, 4, nil)
	if sample.Error != "" || sample.RxBytes != 4 || sample.RxBytesPerSec <= 0 || sample.HTTPStatus != http.StatusPartialContent {
		t.Fatalf("unexpected sample: %+v", sample)
	}
}

func TestSpeedSampleHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()
	sample := doStreamSample(t.Context(), server.URL, "", time.Second, 1024, nil)
	if !strings.Contains(sample.Error, "429") || sample.HTTPStatus != http.StatusTooManyRequests || sample.RxBytes != 0 {
		t.Fatalf("unexpected sample: %+v", sample)
	}
}

func TestSpeedSampleInterruptedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		_, _ = io.WriteString(w, "1234")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sample := doStreamSample(ctx, server.URL, "", time.Second, 10, func(int64, time.Duration, float64) {
		cancel()
	})
	if sample.Error == "" || sample.RxBytes != 4 || sample.HTTPStatus != http.StatusOK {
		t.Fatalf("unexpected sample: %+v", sample)
	}
}
