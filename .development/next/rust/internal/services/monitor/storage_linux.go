//go:build linux

package monitor

import (
	"math"
	"path/filepath"

	"golang.org/x/sys/unix"

	routerpath "nfqws2strategy/internal/tools/path"
)

func readStorageUsage(dataDir string) *StorageUsage {
	var stat unix.Statfs_t
	if dataDir == "" || unix.Statfs(dataDir, &stat) != nil {
		return nil
	}

	path := filepath.Clean(dataDir)
	if !routerpath.IsOpenWrt() && path == routerpath.Path(routerpath.DataDir) {
		var opt unix.Statfs_t
		if unix.Statfs("/opt", &opt) == nil && opt.Type == stat.Type && opt.Fsid == stat.Fsid {
			path = "/opt"
		}
	}
	return storageFromStat(path, stat)
}

func storageFromStat(path string, stat unix.Statfs_t) *StorageUsage {
	blockSize := stat.Frsize
	if blockSize <= 0 {
		blockSize = stat.Bsize
	}
	if blockSize <= 0 || stat.Blocks == 0 || stat.Bfree > stat.Blocks || stat.Blocks > math.MaxUint64/uint64(blockSize) {
		return nil
	}
	unit := uint64(blockSize)
	var available uint64
	// The kernel may report negative available blocks as an unsigned value.
	if stat.Bavail <= stat.Bfree {
		available = stat.Bavail * unit
	}
	return &StorageUsage{
		Path:           path,
		TotalBytes:     stat.Blocks * unit,
		UsedBytes:      (stat.Blocks - stat.Bfree) * unit,
		AvailableBytes: available,
	}
}
