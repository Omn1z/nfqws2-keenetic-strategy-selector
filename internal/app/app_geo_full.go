//go:build !n2s_compact

package app

import (
	"fmt"
	"os"
	"strings"

	"nfqws2strategy/internal/tools/geo"
)

func geoModuleAvailable() bool { return true }

func listGeoCategories(path, kind string) ([]geo.Category, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return geo.Categories(geo.Parse(kind, data)), nil
}

func extractGeoCategory(path, kind, category string, limit int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	items, ok := geo.Parse(kind, data)[strings.ToLower(category)]
	if !ok {
		return nil, fmt.Errorf("category %q not found", category)
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return append([]string{}, items...), nil
}
