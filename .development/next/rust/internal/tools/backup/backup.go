// Package backup builds in-memory snapshots of the selector's portable state
// and applies them back. Backups never persist on the router — the archive
// streams straight to the user's browser; restore accepts the same archive
// back via upload.
//
// The archive is sealed with AES-256-GCM using a key embedded in the binary.
// The point isn't cryptographic privacy (anyone with the binary can decrypt) —
// it's tamper-resistance: the user can't open the file in a text editor and
// hand-edit individual settings, which would silently corrupt the restored
// state. GCM's auth tag + an MD5 envelope reject any byte-flipped archive.
//
//	[ 6  magic "SLBAK1"      ]
//	[ 16 md5(salt|nonce|ct)  ]
//	[ 16 salt                 ]  (reserved — unused at v1, kept for layout stability)
//	[ 12 nonce                ]
//	[ ...ciphertext + 16-byte GCM tag ]
package backup

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	magicV1    = "SLBAK1"
	md5Len     = 16
	saltLen    = 16
	nonceLen   = 12
	maxArchive = 256 * 1024 * 1024
)

var headerLen = len(magicV1) + md5Len + saltLen + nonceLen

// sealKey is the AES-256 key every selector build uses to seal/unseal
// archives. Derived from a fixed magic so the same binary can decrypt any
// archive it produced. Anti-tamper, not anti-disclosure.
var sealKey = sha256.Sum256([]byte("nfqws2-strategy/backup/v1/seal-key"))

// ErrTampered — GCM auth tag verification failed: archive was edited or
// corrupted past what MD5 caught.
var ErrTampered = errors.New("backup: архив подделан/повреждён (auth tag не сошёлся)")

// ErrCorrupt — MD5 didn't match. Likely a transport-level corruption or truncation.
var ErrCorrupt = errors.New("backup: архив битый (MD5 не совпал), отказ")

// ErrNotBackup — magic header missing or wrong format altogether.
var ErrNotBackup = errors.New("backup: не selector backup (неверный заголовок)")

// Build writes an encrypted, zipped snapshot of every file under every root
// into w. Empty / missing roots are skipped silently — broad rootlist + quiet
// skip means we can list everything that MIGHT be on a given install without
// worrying about which paths exist.
func Build(roots []string, w io.Writer) (files int, err error) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for _, root := range roots {
		if internalStorePath(root) {
			continue
		}
		st, err := os.Stat(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if !st.IsDir() {
			// File-level: capture single files too (e.g. /etc/amnezia/amneziawg/awg0.conf).
			if err := addOneFile(zw, root, root, st); err != nil {
				return 0, err
			}
			files++
			continue
		}
		err = filepath.Walk(root, func(p string, fi os.FileInfo, walkErr error) error {
			if internalStorePath(p) {
				if fi != nil && fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if walkErr != nil || fi.IsDir() {
				return walkErr
			}
			if err := addOneFile(zw, root, p, fi); err != nil {
				return err
			}
			files++
			return nil
		})
		if err != nil {
			_ = zw.Close()
			return 0, err
		}
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	// Salt is reserved for a future per-router key tier; kept random for now
	// so the header stays unique-per-archive even with the fixed key.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}

	gcm, err := newGCM()
	if err != nil {
		return 0, err
	}
	ct := gcm.Seal(nil, nonce, zbuf.Bytes(), []byte(magicV1))

	body := make([]byte, 0, len(salt)+len(nonce)+len(ct))
	body = append(body, salt...)
	body = append(body, nonce...)
	body = append(body, ct...)
	sum := md5.Sum(body)

	if _, err := w.Write([]byte(magicV1)); err != nil {
		return 0, err
	}
	if _, err := w.Write(sum[:]); err != nil {
		return 0, err
	}
	if _, err := w.Write(body); err != nil {
		return 0, err
	}
	return files, nil
}

// addOneFile writes one file into the zip. The header path is the file's
// absolute path with the leading "/" stripped, so Restore can drop it back
// at the same absolute location on the target machine.
func addOneFile(zw *zip.Writer, _ string, p string, fi os.FileInfo) error {
	hdr, err := zip.FileInfoHeader(fi)
	if err != nil {
		return err
	}
	name, err := archiveName(p)
	if err != nil {
		return err
	}
	hdr.Name = name
	hdr.Method = zip.Deflate
	hw, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(hw, f)
	return err
}

func archiveName(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	name := filepath.ToSlash(abs)
	if filepath.VolumeName(abs) == "" {
		name = strings.TrimPrefix(name, "/")
	}
	return name, nil
}

// Restore reads an encrypted archive from r, validates its MD5, decrypts it
// with the built-in key, unzips the result, and writes every entry back as
// an absolute path on disk. Restore is allow-listed against the same root
// set Build used — anything outside is silently skipped to keep a tampered
// archive from dropping files into arbitrary system paths.
//
// Error ladder: ErrNotBackup → ErrCorrupt → ErrTampered → I/O.
func Restore(allowedRoots []string, r io.Reader) (int, error) {
	return restoreWithOps(allowedRoots, r, restoreFileOps{})
}

type restoreFileOps struct {
	syncFile  func(*os.File) error
	closeFile func(*os.File) error
	rename    func(string, string) error
	syncDir   func(string) error
}

func (ops restoreFileOps) fileSync(f *os.File) error {
	if ops.syncFile != nil {
		return ops.syncFile(f)
	}
	return f.Sync()
}
func (ops restoreFileOps) fileClose(f *os.File) error {
	if ops.closeFile != nil {
		return ops.closeFile(f)
	}
	return f.Close()
}
func (ops restoreFileOps) move(src, dst string) error {
	if ops.rename != nil {
		return ops.rename(src, dst)
	}
	return os.Rename(src, dst)
}
func (ops restoreFileOps) directorySync(dir string) error {
	if ops.syncDir != nil {
		return ops.syncDir(dir)
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	// Windows cannot fsync directory handles opened by os.Open. File data is
	// still synced; Linux/Entware also durably commits the rename itself.
	if runtime.GOOS == "windows" {
		return f.Close()
	}
	err = f.Sync()
	return errors.Join(err, f.Close())
}

func internalStorePath(path string) bool {
	for _, part := range strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool { return r == '/' || r == '\\' }) {
		if strings.EqualFold(part, ".store") {
			return true
		}
	}
	return false
}

// Prepare every allowed entry before committing any of them. A corrupt ZIP
// member must not truncate either its destination or an earlier valid file.
// Commits are atomic per file; the returned count includes committed files if
// a later rename or directory sync fails. Lifecycle callers reload that state.
func restoreWithOps(allowedRoots []string, r io.Reader, ops restoreFileOps) (int, error) {
	buf, err := io.ReadAll(io.LimitReader(r, maxArchive+1))
	if err != nil {
		return 0, err
	}
	if int64(len(buf)) > maxArchive {
		return 0, fmt.Errorf("backup: архив больше %dMB — отказ", maxArchive/(1024*1024))
	}
	if len(buf) < headerLen || string(buf[:len(magicV1)]) != magicV1 {
		return 0, ErrNotBackup
	}
	storedSum := buf[len(magicV1) : len(magicV1)+md5Len]
	body := buf[len(magicV1)+md5Len:]
	gotSum := md5.Sum(body)
	if !bytes.Equal(storedSum, gotSum[:]) {
		return 0, ErrCorrupt
	}
	nonce := body[saltLen : saltLen+nonceLen]
	ct := body[saltLen+nonceLen:]

	gcm, err := newGCM()
	if err != nil {
		return 0, err
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(magicV1))
	if err != nil {
		return 0, ErrTampered
	}

	zr, err := zip.NewReader(bytes.NewReader(plain), int64(len(plain)))
	if err != nil {
		return 0, fmt.Errorf("backup: zip внутри архива битый: %w", err)
	}
	type stagedFile struct{ temporary, destination string }
	var staged []stagedFile
	defer func() {
		for _, file := range staged {
			_ = os.Remove(file.temporary)
		}
	}()
	seen := map[string]bool{}
	remaining := int64(maxArchive)
	for _, ze := range zr.File {
		if strings.HasSuffix(ze.Name, "/") {
			continue
		}
		dstAbs, err := restorePath(ze.Name)
		if err != nil {
			return 0, fmt.Errorf("backup: невалидный путь в архиве: %s", ze.Name)
		}
		if internalStorePath(dstAbs) || !isUnderAny(dstAbs, allowedRoots) {
			// Quietly skip anything not under an allowed root — protects
			// against a tampered archive trying to drop files into /etc or
			// /root after surviving the auth check (shouldn't happen with
			// our key, but defense-in-depth is cheap).
			continue
		}
		if seen[dstAbs] {
			return 0, fmt.Errorf("backup: повторный путь в архиве: %s", ze.Name)
		}
		seen[dstAbs] = true
		if ze.UncompressedSize64 > uint64(remaining) {
			return 0, fmt.Errorf("backup: распакованные файлы превышают %dMB", maxArchive/(1024*1024))
		}
		// Older builds recorded a leaf symlink's mode but archived the bytes
		// read from its target. Recover those bytes as a private regular file;
		// archive entries never create links or follow an existing destination.
		legacySymlink := ze.Mode()&os.ModeSymlink != 0
		if !ze.Mode().IsRegular() && !legacySymlink {
			return 0, fmt.Errorf("backup: не обычный файл: %s", ze.Name)
		}
		if err := rejectSymlinkParents(dstAbs, allowedRoots); err != nil {
			return 0, err
		}
		if err := ensureRestoreDirectory(filepath.Dir(dstAbs), ops); err != nil {
			return 0, err
		}
		rc, err := ze.Open()
		if err != nil {
			return 0, err
		}
		f, err := os.CreateTemp(filepath.Dir(dstAbs), ".n2s-restore-*")
		if err != nil {
			_ = rc.Close()
			return 0, err
		}
		staged = append(staged, stagedFile{f.Name(), dstAbs})
		written, copyErr := io.Copy(f, io.LimitReader(rc, remaining+1))
		readCloseErr := rc.Close()
		if written > remaining {
			copyErr = fmt.Errorf("backup: распакованные файлы превышают %dMB", maxArchive/(1024*1024))
		}
		remaining -= written
		mode := ze.Mode().Perm() & 0o777
		if mode == 0 || legacySymlink {
			mode = 0o600
		}
		// Do not broaden access to an existing private file when importing an
		// archive created by an older restore that forced all modes to 0644.
		if info, err := os.Stat(dstAbs); err == nil && info.Mode().Perm()&0o077 == 0 {
			mode &^= 0o077
		}
		if filepath.Base(dstAbs) == "awg.json" {
			mode = 0o600
		}
		if copyErr == nil && readCloseErr == nil {
			err = f.Chmod(mode)
		} else {
			err = errors.Join(copyErr, readCloseErr)
		}
		if err == nil {
			err = ops.fileSync(f)
		}
		err = errors.Join(err, ops.fileClose(f))
		if err != nil {
			return 0, err
		}
	}
	count := 0
	for _, file := range staged {
		if err := rejectSymlinkParents(file.destination, allowedRoots); err != nil {
			return count, err
		}
		if err := ops.move(file.temporary, file.destination); err != nil {
			return count, err
		}
		count++
		if err := ops.directorySync(filepath.Dir(file.destination)); err != nil {
			return count, fmt.Errorf("backup: записано файлов %d, синхронизация каталога не подтверждена: %w", count, err)
		}
	}
	return count, nil
}

func ensureRestoreDirectory(dir string, ops restoreFileOps) error {
	var missing []string
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("backup: путь не является каталогом")
			}
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, current)
		if filepath.Dir(current) == current {
			return err
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o755); err != nil && !os.IsExist(err) {
			return err
		}
		if err := ops.directorySync(filepath.Dir(missing[i])); err != nil {
			return err
		}
	}
	return nil
}

func rejectSymlinkParents(destination string, roots []string) error {
	info, err := os.Lstat(destination)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup: файл назначения является символической ссылкой")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, root := range roots {
		root, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(root, destination)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		// An explicitly allowed root may itself be a symlink. Descendants
		// must not redirect a lexical allow-listed path outside that root.
		parent := filepath.Dir(destination)
		for parent != root && len(parent) > len(root) {
			info, err := os.Lstat(parent)
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("backup: каталог назначения является символической ссылкой")
			}
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			next := filepath.Dir(parent)
			if next == parent {
				break
			}
			parent = next
		}
		return nil
	}
	return fmt.Errorf("backup: путь вне разрешённых каталогов")
}

func restorePath(name string) (string, error) {
	local := filepath.FromSlash(name)
	if !filepath.IsAbs(local) && filepath.VolumeName(local) == "" {
		// POSIX backups store "/opt/..." as "opt/..."; put the root back.
		local = string(filepath.Separator) + local
	}
	return filepath.Abs(filepath.Clean(local))
}

func newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(sealKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func isUnderAny(p string, roots []string) bool {
	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		st, err := os.Stat(rootAbs)
		// File-level root: exact match wins.
		if err == nil && !st.IsDir() && p == rootAbs {
			return true
		}
		// Dir-level root: prefix check with a trailing separator so
		// "/opt/etc/x" doesn't accidentally cover "/opt/etc/xy".
		if strings.HasPrefix(p+string(filepath.Separator), rootAbs+string(filepath.Separator)) {
			return true
		}
		// Also accept the file-level case for the prefix-check path (Stat may
		// fail when the file doesn't exist yet — we still need to allow the
		// path through restore so it can be created).
		if p == rootAbs {
			return true
		}
	}
	return false
}

// Filename returns the suggested download filename for a snapshot taken now.
func Filename(t time.Time) string {
	return "selector-" + t.UTC().Format("20060102-150405") + ".bak"
}
