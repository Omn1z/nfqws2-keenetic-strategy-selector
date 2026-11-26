//go:build !linux

package monitor

func readStorageUsage(string) *StorageUsage { return nil }
