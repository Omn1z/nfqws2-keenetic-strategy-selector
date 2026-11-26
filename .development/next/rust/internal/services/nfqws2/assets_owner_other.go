//go:build !linux

package nfqws2

import (
	"io/fs"
	"os"
)

func preserveAssetOwner(_ fs.FileInfo, _ *os.File) error { return nil }

func initializeAssetOwner(_ *os.File, _ *assetOwner) error { return nil }
func newAutolistOwner(_ []byte) (*assetOwner, error)       { return nil, nil }
