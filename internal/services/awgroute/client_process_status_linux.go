//go:build linux

package awgroute

import (
	"bytes"
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
		if !clientCommandMatches(cmd, iface) {
			return ""
		}
		stat, err := os.ReadFile(filepath.Join(procRoot, pid, "stat"))
		if err != nil {
			return ""
		}
		end := bytes.LastIndexByte(stat, ')')
		if end < 0 {
			return ""
		}
		index := 0
		for field := range strings.FieldsSeq(string(stat[end+1:])) {
			if index == 0 && (field == "Z" || field == "X") {
				return ""
			}
			if index == 19 {
				if _, err := strconv.ParseUint(field, 10, 64); err == nil {
					return pid + "/" + field
				}
				return ""
			}
			index++
		}
		return ""
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

func clientCommandMatches(cmd []byte, iface string) bool {
	nul := []byte{0}
	exe, rest, ok := bytes.Cut(cmd, nul)
	if !ok {
		return false
	}
	arg, _, _ := bytes.Cut(rest, nul)
	base := exe[bytes.LastIndexByte(exe, '/')+1:]
	return string(base) == "amneziawg-go" && string(arg) == iface
}
