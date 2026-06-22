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
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			// File-level: capture single files too (e.g. /etc/amnezia/amneziawg/awg0.conf).
			if err == nil && !st.IsDir() {
				if err := addOneFile(zw, root, root, st); err == nil {
					files++
				}
			}
			continue
		}
		err = filepath.Walk(root, func(p string, fi os.FileInfo, walkErr error) error {
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
	count := 0
	for _, ze := range zr.File {
		if strings.HasSuffix(ze.Name, "/") {
			continue
		}
		dstAbs, err := restorePath(ze.Name)
		if err != nil {
			return count, fmt.Errorf("backup: невалидный путь в архиве: %s", ze.Name)
		}
		if !isUnderAny(dstAbs, allowedRoots) {
			// Quietly skip anything not under an allowed root — protects
			// against a tampered archive trying to drop files into /etc or
			// /root after surviving the auth check (shouldn't happen with
			// our key, but defense-in-depth is cheap).
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dstAbs), 0o755); err != nil {
			return count, err
		}
		rc, err := ze.Open()
		if err != nil {
			return count, err
		}
		f, err := os.OpenFile(dstAbs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return count, err
		}
		_, err = io.Copy(f, rc)
		rc.Close()
		f.Close()
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
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
