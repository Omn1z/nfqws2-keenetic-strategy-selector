//go:build !n2s_compact

package catalog

import (
	_ "embed"
	"slices"
	"sync"
)

//go:embed builtin.json
var builtinJSON []byte

var embeddedCatalog = sync.OnceValues(func() ([]Strategy, error) { return parseBuiltin(builtinJSON) })

func Builtin() ([]Strategy, error) {
	items, err := embeddedCatalog()
	return slices.Clone(items), err
}
