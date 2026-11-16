package dnsroute

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxDNSHookBytes = 64 << 10

type dnsHookFileState struct {
	exists  bool
	damaged bool
	data    []byte
	info    os.FileInfo
}

// A generated hook can be empty or zero-filled after an interrupted filesystem
// write. Only an exact, sufficiently distinctive header prefix is recoverable
// without the full ownership signature; a generic shell script stays foreign.
func damagedDNSHook(data []byte) bool {
	if len(bytes.Trim(data, "\x00")) == 0 {
		return true
	}
	header := []byte("#!/bin/sh\n" + hookSignature + "\n")
	prefix := []byte("#!/bin/sh\n# NFQWS DNS Server:")
	return len(data) >= len(prefix) && len(data) < len(header) &&
		bytes.HasPrefix(data, prefix) && bytes.HasPrefix(header, data)
}

func inspectDNSHook(filename, operation string) (dnsHookFileState, error) {
	var state dnsHookFileState
	info, err := os.Lstat(filename)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() {
		return state, fmt.Errorf("refusing to %s nonregular netfilter hook %s", operation, filename)
	}
	if info.Size() > maxDNSHookBytes {
		return state, fmt.Errorf("refusing to %s oversized netfilter hook %s", operation, filename)
	}
	f, err := os.Open(filename)
	if err != nil {
		return state, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return state, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return state, fmt.Errorf("netfilter hook changed while inspecting %s", filename)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDNSHookBytes+1))
	if err != nil {
		return state, err
	}
	if len(data) > maxDNSHookBytes {
		return state, fmt.Errorf("refusing to %s oversized netfilter hook %s", operation, filename)
	}
	if !bytes.Contains(data, []byte(hookSignature)) && !damagedDNSHook(data) {
		return state, fmt.Errorf("refusing to %s foreign netfilter hook %s (%d bytes)", operation, filename, len(data))
	}
	return dnsHookFileState{exists: true, damaged: !bytes.Contains(data, []byte(hookSignature)), data: data, info: info}, nil
}

type dnsHookWritableFile interface {
	Name() string
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

type dnsHookFileOps struct {
	createTemp func(string, string) (dnsHookWritableFile, error)
	rename     func(string, string) error
	syncDir    func(string) error
}

func defaultDNSHookFileOps() dnsHookFileOps {
	return dnsHookFileOps{
		createTemp: func(dir, pattern string) (dnsHookWritableFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
		syncDir:    syncDNSHookDir,
	}
}

func dnsHookRecoveryDir(dataDir, filename string) string {
	if strings.TrimSpace(dataDir) != "" {
		return filepath.Join(dataDir, "recovery", "dns-hooks")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filename)), "nfqws2-dns-hook-recovery")
}

func pathWithinDirectory(directory, candidate string) bool {
	rel, err := filepath.Rel(directory, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Resolve existing ancestors before MkdirAll: a nonexistent child of an alias
// into netfilter.d must not create even a recovery directory among live hooks.
func resolveDNSHookDirectory(directory string) (string, error) {
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(directory)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", err
		}
		missing = append(missing, filepath.Base(directory))
		directory = parent
	}
}

func ensureDNSHookDirectory(directory string, mode os.FileMode, ops dnsHookFileOps) error {
	var created []string
	for current := filepath.Clean(directory); ; current = filepath.Dir(current) {
		if _, err := os.Stat(current); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		created = append(created, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	if err := os.MkdirAll(directory, mode); err != nil {
		return err
	}
	// Persist every new link, from the deepest directory to the first parent
	// that already existed. Syncing just the eventual file's directory is not
	// sufficient when a power loss can discard that directory's own name.
	for _, current := range created {
		if err := ops.syncDir(filepath.Dir(current)); err != nil {
			return fmt.Errorf("syncing new DNS hook directory: %w", err)
		}
	}
	return nil
}

func prepareDNSHookRecoveryDir(filename, recoveryDir string, ops dnsHookFileOps) error {
	if strings.TrimSpace(recoveryDir) == "" {
		return fmt.Errorf("DNS hook recovery directory is required")
	}
	hookDir, err := filepath.Abs(filepath.Dir(filename))
	if err != nil {
		return err
	}
	recovery, err := filepath.Abs(recoveryDir)
	if err != nil {
		return err
	}
	if pathWithinDirectory(hookDir, recovery) {
		return fmt.Errorf("DNS hook recovery directory must be outside netfilter hooks")
	}
	resolvedHook, err := filepath.EvalSymlinks(hookDir)
	if err != nil {
		return err
	}
	resolvedRecovery, err := resolveDNSHookDirectory(recovery)
	if err != nil {
		return err
	}
	if pathWithinDirectory(resolvedHook, resolvedRecovery) {
		return fmt.Errorf("DNS hook recovery directory resolves inside netfilter hooks")
	}
	if err := ensureDNSHookDirectory(recoveryDir, 0700, ops); err != nil {
		return err
	}
	resolvedRecovery, err = filepath.EvalSymlinks(recovery)
	if err != nil {
		return err
	}
	if pathWithinDirectory(resolvedHook, resolvedRecovery) {
		return fmt.Errorf("DNS hook recovery directory resolves inside netfilter hooks")
	}
	return nil
}

func writeDNSHookTemp(dir, pattern string, data []byte, mode os.FileMode, ops dnsHookFileOps) (string, error) {
	f, err := ops.createTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
		}
	}()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	keep = true
	return name, nil
}

func preserveDamagedDNSHook(filename, recoveryDir string, state dnsHookFileState, ops dnsHookFileOps) error {
	if !state.damaged {
		return nil
	}
	if err := prepareDNSHookRecoveryDir(filename, recoveryDir, ops); err != nil {
		return err
	}
	backup, err := writeDNSHookTemp(recoveryDir, filepath.Base(filename)+".damaged-", state.data, 0600, ops)
	if err != nil {
		return fmt.Errorf("preserving damaged DNS hook: %w", err)
	}
	if err := ops.syncDir(recoveryDir); err != nil {
		// Retain even a backup whose directory sync failed, but do not replace
		// the original until durable preservation has succeeded.
		return fmt.Errorf("syncing damaged DNS hook backup %s: %w", backup, err)
	}
	return nil
}

func unchangedDNSHook(filename string, prior dnsHookFileState, operation string) error {
	current, err := inspectDNSHook(filename, operation)
	if err != nil {
		return err
	}
	if current.exists != prior.exists || current.exists &&
		(!os.SameFile(current.info, prior.info) || !bytes.Equal(current.data, prior.data)) {
		return fmt.Errorf("netfilter hook changed before %s: %s", operation, filename)
	}
	return nil
}

func installDNSHook(filename, recoveryDir, script string) error {
	return installDNSHookWithOps(filename, recoveryDir, script, defaultDNSHookFileOps())
}

func installDNSHookWithOps(filename, recoveryDir, script string, ops dnsHookFileOps) error {
	state, err := inspectDNSHook(filename, "replace")
	if err != nil {
		return err
	}
	if err := ensureDNSHookDirectory(filepath.Dir(filename), 0755, ops); err != nil {
		return err
	}
	if err := preserveDamagedDNSHook(filename, recoveryDir, state, ops); err != nil {
		return err
	}
	tmpName, err := writeDNSHookTemp(filepath.Dir(filename), ".nfqws-dns-", []byte(script), 0755, ops)
	if err != nil {
		return fmt.Errorf("writing DNS netfilter hook: %w", err)
	}
	defer os.Remove(tmpName)
	if err := unchangedDNSHook(filename, state, "replace"); err != nil {
		return err
	}
	if err := ops.rename(tmpName, filename); err != nil {
		return fmt.Errorf("replacing DNS netfilter hook: %w", err)
	}
	if err := ops.syncDir(filepath.Dir(filename)); err != nil {
		return fmt.Errorf("syncing DNS netfilter hook directory: %w", err)
	}
	return nil
}

func removeDNSHook(filename, recoveryDir string) error {
	state, err := inspectDNSHook(filename, "remove")
	if err != nil || !state.exists {
		return err
	}
	ops := defaultDNSHookFileOps()
	if err := preserveDamagedDNSHook(filename, recoveryDir, state, ops); err != nil {
		return err
	}
	if err := unchangedDNSHook(filename, state, "remove"); err != nil {
		return err
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	return ops.syncDir(filepath.Dir(filename))
}
