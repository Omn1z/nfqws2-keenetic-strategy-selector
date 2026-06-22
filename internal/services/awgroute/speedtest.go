package awgroute

import (
	"encoding/json"
	"net/http"
	"time"
)

// JSONLine marshals + writes + flushes one NDJSON line to a streaming HTTP
// response. The speedtest handler calls this for every SpeedEvent so the
// client sees live progress instead of a single blob at the end.
func JSONLine(w http.ResponseWriter, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// SpeedTestOptions are the per-run inputs (set via the HTTP handler).
type SpeedTestOptions struct {
	URL      string
	MaxBytes int64
	Timeout  time.Duration
	OnEvent  func(evt SpeedEvent)
}

// SpeedEvent is one progress / phase notification emitted while a run is
// in-flight. The HTTP handler turns these into NDJSON lines.
type SpeedEvent struct {
	Phase   string           `json:"phase"`
	Bytes   int64            `json:"bytes,omitempty"`
	Elapsed int64            `json:"elapsed_ms,omitempty"`
	Rate    float64          `json:"rate_bps,omitempty"`
	Sample  *SpeedSample     `json:"sample,omitempty"`
	Result  *SpeedTestResult `json:"result,omitempty"`
	Err     string           `json:"error,omitempty"`
}

// SpeedTestResult is the JSON payload the UI consumes.
type SpeedTestResult struct {
	ViaTunnel    SpeedSample `json:"via_tunnel"`
	ViaDirect    SpeedSample `json:"via_direct"`
	TunnelGainPC int         `json:"tunnel_gain_pc"`
	Sample       string      `json:"sample"`
	Err          string      `json:"error,omitempty"`
}

type SpeedSample struct {
	RxBytes       int64   `json:"rx_bytes"`
	DurationMS    int64   `json:"duration_ms"`
	RxBytesPerSec float64 `json:"rx_bytes_per_sec"`
	HTTPStatus    int     `json:"http_status"`
	Error         string  `json:"error,omitempty"`
}
