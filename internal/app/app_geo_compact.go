//go:build n2s_compact

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"nfqws2strategy/internal/tools/geo"
	"nfqws2strategy/internal/tools/modules"
)

func geoHelper() string {
	name := "nfqws2-geo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(modules.Dir(), "geo", name)
}

func geoModuleAvailable() bool {
	info, err := os.Stat(geoHelper())
	return err == nil && info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0111 != 0)
}

func listGeoCategories(path, kind string) ([]geo.Category, error) {
	return readGeoModule[geo.Category]("list", kind, path)
}

func extractGeoCategory(path, kind, category string, limit int) ([]string, error) {
	return readGeoModule[string]("extract", kind, path, category, strconv.Itoa(max(0, limit)))
}

func readGeoModule[T any](args ...string) ([]T, error) {
	ctx, cancel := context.WithTimeout(context.Background(), geoFetchTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, geoHelper(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("запуск модуля GeoSite/GeoIP: %w", err)
	}
	items, parseErr := readGeoArray[T](out)
	// Release the pipe before Wait if an invalid record stopped the decoder.
	_ = out.Close()
	if err := cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 3 && args[0] == "extract" {
			return nil, fmt.Errorf("category %q not found", args[3])
		}
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("geo: %s", message)
		}
		return nil, fmt.Errorf("geo: %w", err)
	}
	return items, parseErr
}

// Decode one array element at a time. Decoder.Decode(&slice) first buffers the
// entire JSON array, which would duplicate a large GeoIP category in RAM.
func readGeoArray[T any](out io.Reader) ([]T, error) {
	d := json.NewDecoder(out)
	start, err := d.Token()
	if err != nil {
		return nil, err
	}
	if start != json.Delim('[') {
		return nil, errors.New("geo: expected an array")
	}
	items := make([]T, 0)
	for d.More() {
		var item T
		if err := d.Decode(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') {
		return nil, errors.New("geo: incomplete array")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("geo: trailing data")
	}
	return items, nil
}
