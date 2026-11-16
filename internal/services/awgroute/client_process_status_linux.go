//go:build linux

package awgroute

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func awgClientProcessIdentityOS(iface string) string {
	return awgClientProcessIdentity("/proc", iface)
}

// Include start time as well as PID, so PID reuse cannot authenticate a fresh
// daemon using the previous process's cached status. An upgraded executable
// may still be serving traffic: its inode need not match the installed file.
func awgClientProcessIdentity(procRoot, iface string) string {
	check := func(pid string) string {
		cmd, err := os.ReadFile(filepath.Join(procRoot, pid, "cmdline"))
		if err != nil {
			return ""
		}
		args := strings.Split(string(cmd), "\x00")
		if len(args) < 2 || filepath.Base(args[0]) != "amneziawg-go" || args[1] != iface {
			return ""
		}
		stat, err := os.ReadFile(filepath.Join(procRoot, pid, "stat"))
		if err != nil {
			return ""
		}
		end := strings.LastIndexByte(string(stat), ')')
		if end < 0 {
			return ""
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) <= 19 || fields[0] == "Z" || fields[0] == "X" {
			return ""
		}
		if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
			return ""
		}
		return pid + "/" + fields[19]
	}
	if cached, ok := clientEnginePIDs.Load(iface); ok {
		if id := check(cached.(string)); id != "" {
			return id
		}
	}
	entries, _ := os.ReadDir(procRoot)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if id := check(entry.Name()); id != "" {
			clientEnginePIDs.Store(iface, entry.Name())
			return id
		}
	}
	return ""
}
