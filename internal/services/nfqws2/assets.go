package nfqws2

// The explorer works with archive-relative names. Server-owned roots are the
// only bridge to the router filesystem; uploads can never select another root.
import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"nfqws2strategy/internal/tools/config"
	routerpath "nfqws2strategy/internal/tools/path"
)

const (
	AssetMaxBytes           = 16 << 20
	ArchiveMaxBytes         = 32 << 20
	ArchiveExpandedMaxBytes = 64 << 20
	ArchiveMaxFiles         = 1024
)

var ErrAssetConflict = errors.New("файл уже существует: подтвердите замену")
var ErrArchiveChanged = errors.New("файлы изменились после предварительного просмотра; откройте архив повторно")

type Asset struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	Size       int64     `json:"size"`
	Editable   bool      `json:"editable"`
	Protected  bool      `json:"protected"`
	ModifiedAt time.Time `json:"modified_at"`
}

type Assets struct {
	Files             []Asset              `json:"files"`
	Directories       []string             `json:"directories"`
	DirectoryModified map[string]time.Time `json:"directory_modified"`
	Roots             map[string]string    `json:"roots"`
}

type assetLocation struct{ root, name, kind string }

type assetOwner struct{ uid, gid int }

// Only plain text intended for the Unix engine is normalized. Blob and gzip
// uploads must remain byte-for-byte intact, even if their bytes resemble text.
func prepareAssetData(kind, name string, data []byte) ([]byte, bool, error) {
	if kind == "blob" || strings.HasSuffix(strings.ToLower(name), ".gz") {
		return data, false, nil
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, false, fmt.Errorf("конфиги, списки и скрипты должны быть текстом UTF-8")
	}
	if kind == "lua" {
		return data, false, nil
	}
	original := data
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if kind == "conf" {
		normalized, err := config.NormalizeWANInterfaces(string(data))
		if err != nil {
			return nil, false, err
		}
		data = []byte(normalized)
	}
	return data, !bytes.Equal(data, original), nil
}

func (m *Manager) assetRoots() map[string]string {
	conf := filepath.Dir(m.cfg.Nfqws2Conf)
	if m.cfg.Nfqws2Conf == "" {
		conf = routerpath.Path(routerpath.Nfqws2Dir)
	}
	blobs, lua := m.cfg.SystemBlobsDir, m.cfg.LuaDir
	if blobs == "" {
		blobs = filepath.Join(conf, "blobs")
	}
	if lua == "" {
		lua = filepath.Join(conf, "lua")
	}
	return map[string]string{"conf": conf, "list": filepath.Join(conf, "lists"), "blob": blobs, "lua": lua, "script": conf}
}

func cleanAssetName(name string) error {
	if name == "" || len(name) > 512 || strings.ContainsAny(name, "\\:\x00\r\n") || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return fmt.Errorf("недопустимый путь: %q", name)
	}
	parts := strings.Split(name, "/")
	if len(parts) > 10 {
		return fmt.Errorf("слишком глубокий путь: %s", name)
	}
	for _, part := range parts {
		if part == "." || part == ".." || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || len(part) > 180 {
			return fmt.Errorf("недопустимый путь: %q", name)
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return fmt.Errorf("недопустимое имя файла: %q", part)
			}
		}
	}
	return nil
}

func (m *Manager) assetLocation(name string) (assetLocation, error) {
	if err := cleanAssetName(name); err != nil {
		return assetLocation{}, err
	}
	roots := m.assetRoots()
	if name == "nfqws2.conf" {
		base := filepath.Base(m.cfg.Nfqws2Conf)
		if m.cfg.Nfqws2Conf == "" {
			base = "nfqws2.conf"
		}
		return assetLocation{roots["conf"], base, "conf"}, nil
	}
	prefix, tail, found := strings.Cut(name, "/")
	if !found || tail == "" {
		return assetLocation{}, fmt.Errorf("путь должен начинаться с lists/, blobs/, lua/, scripts/ или configs/: %s", name)
	}
	kind := map[string]string{"lists": "list", "blobs": "blob", "lua": "lua", "scripts": "script", "configs": "conf"}[prefix]
	if kind == "" {
		return assetLocation{}, fmt.Errorf("неизвестный каталог: %s", prefix)
	}
	if kind == "conf" {
		if strings.Contains(tail, "/") || !(strings.HasSuffix(tail, ".conf") || strings.HasSuffix(tail, ".conf-old") || strings.HasSuffix(tail, ".conf-opkg") || strings.HasSuffix(tail, ".apk-new")) || tail == filepath.Base(m.cfg.Nfqws2Conf) || tail == "nfqws2.conf" {
			return assetLocation{}, fmt.Errorf("недопустимый конфиг: %s", tail)
		}
	}
	if kind == "script" && (strings.Contains(tail, "/") || !strings.HasSuffix(tail, ".sh")) {
		return assetLocation{}, fmt.Errorf("скрипт должен иметь имя scripts/имя.sh")
	}
	return assetLocation{roots[kind], filepath.FromSlash(tail), kind}, nil
}

// Root paths come from trusted server configuration: Entware may itself be a
// symlink to attached storage. Resolve that root before opening os.Root; reject
// symlinks in all client-selected descendants separately.
func openAssetRoot(dir string, create bool) (*os.Root, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if create {
		if err = os.MkdirAll(abs, 0755); err != nil {
			return nil, err
		}
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	return os.OpenRoot(resolved)
}

func checkAssetDescendants(root *os.Root, name string) error {
	parts := strings.Split(filepath.ToSlash(name), "/")
	for i := range parts {
		p := filepath.FromSlash(strings.Join(parts[:i+1], "/"))
		st, err := root.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !st.IsDir() || i == len(parts)-1 && !st.Mode().IsRegular() {
			return fmt.Errorf("путь содержит ссылку или специальный файл: %s", p)
		}
	}
	return nil
}

func readAssetLocation(loc assetLocation) ([]byte, fs.FileMode, error) {
	r, err := openAssetRoot(loc.root, false)
	if err != nil {
		return nil, 0, err
	}
	defer r.Close()
	if err = checkAssetDescendants(r, loc.name); err != nil {
		return nil, 0, err
	}
	f, err := r.Open(loc.name)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !st.Mode().IsRegular() || st.Size() > AssetMaxBytes {
		return nil, 0, fmt.Errorf("файл превышает предел 16 МиБ или имеет неподдерживаемый тип")
	}
	b, err := io.ReadAll(io.LimitReader(f, AssetMaxBytes+1))
	if len(b) > AssetMaxBytes {
		return nil, 0, fmt.Errorf("файл превышает предел 16 МиБ")
	}
	return b, st.Mode().Perm(), err
}

func writeAssetLocation(loc assetLocation, data []byte, mode fs.FileMode, newOwner ...*assetOwner) error {
	r, err := openAssetRoot(loc.root, true)
	if err != nil {
		return err
	}
	defer r.Close()
	if err = checkAssetDescendants(r, loc.name); err != nil {
		return err
	}
	if dir := filepath.Dir(loc.name); dir != "." {
		if err = r.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(loc.name), ".n2s-"+hex.EncodeToString(random[:]))
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	if st, statErr := r.Lstat(loc.name); statErr == nil {
		// Appending autolists belongs to the engine's unprivileged user. An
		// atomic replacement must not silently transfer them to root.
		if err = preserveAssetOwner(st, f); err != nil {
			f.Close()
			return err
		}
		if err = f.Chmod(st.Mode().Perm()); err != nil {
			f.Close()
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		f.Close()
		return statErr
	} else if len(newOwner) > 0 && newOwner[0] != nil {
		if err = initializeAssetOwner(f, newOwner[0]); err != nil {
			f.Close()
			return err
		}
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return r.Rename(tmp, loc.name)
}

func removeAssetLocation(loc assetLocation) error {
	r, err := openAssetRoot(loc.root, false)
	if err != nil {
		return err
	}
	defer r.Close()
	if err = checkAssetDescendants(r, loc.name); err != nil {
		return err
	}
	return r.Remove(loc.name)
}

func (m *Manager) listAssetsLocked() (Assets, error) {
	out := Assets{Files: []Asset{}, Directories: []string{}, DirectoryModified: map[string]time.Time{}, Roots: m.assetRoots()}
	for _, group := range []struct{ kind, prefix string }{{"conf", ""}, {"list", "lists/"}, {"blob", "blobs/"}, {"lua", "lua/"}} {
		root, err := openAssetRoot(out.Roots[group.kind], false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return out, err
		}
		err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if name == "." {
				st, e := entry.Info()
				if e != nil {
					return e
				}
				if group.kind == "conf" {
					// These are virtual sections backed by the same physical
					// directory, not the latest timestamp of their children.
					out.DirectoryModified["configs"] = st.ModTime().UTC()
					out.DirectoryModified["scripts"] = st.ModTime().UTC()
				} else {
					out.DirectoryModified[strings.TrimSuffix(group.prefix, "/")] = st.ModTime().UTC()
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if entry.IsDir() {
				if group.kind == "conf" || strings.HasPrefix(entry.Name(), ".") {
					return fs.SkipDir
				}
				// Include empty directories too, but only those in which an
				// explorer upload can create a valid asset. Prune unsupported
				// names/depth before walking arbitrary subtrees on the router.
				directory := group.prefix + name
				if cleanAssetName(directory+"/x") != nil {
					return fs.SkipDir
				}
				st, e := entry.Info()
				if e != nil {
					return e
				}
				out.Directories = append(out.Directories, directory)
				out.DirectoryModified[directory] = st.ModTime().UTC()
				// A valid imported file can have eight distinct parent folders
				// (ten path components including its section and filename).
				if len(out.Directories) > ArchiveMaxFiles*8 {
					return fmt.Errorf("слишком много папок (максимум %d)", ArchiveMaxFiles*8)
				}
				return nil
			}
			archiveName := group.prefix + name
			if group.kind == "conf" {
				switch {
				case name == filepath.Base(m.cfg.Nfqws2Conf) || m.cfg.Nfqws2Conf == "" && name == "nfqws2.conf":
					archiveName = "nfqws2.conf"
				case strings.HasSuffix(name, ".sh"):
					archiveName = "scripts/" + name
				default:
					archiveName = "configs/" + name
				}
			}
			loc, e := m.assetLocation(archiveName)
			if e != nil {
				return nil
			}
			st, e := entry.Info()
			if e != nil {
				return e
			}
			if !st.Mode().IsRegular() {
				return nil
			}
			editable := loc.kind != "blob" && !strings.HasSuffix(name, ".gz") && st.Size() <= readCap
			out.Files = append(out.Files, Asset{Path: archiveName, Kind: loc.kind, Size: st.Size(), Editable: editable, Protected: archiveName == "nfqws2.conf", ModifiedAt: st.ModTime().UTC()})
			if len(out.Files) > ArchiveMaxFiles {
				return fmt.Errorf("слишком много файлов (максимум %d)", ArchiveMaxFiles)
			}
			return nil
		})
		root.Close()
		if err != nil {
			return out, err
		}
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	sort.Strings(out.Directories)
	return out, nil
}

func (m *Manager) Assets() (Assets, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	return m.listAssetsLocked()
}

func (m *Manager) AssetBytes(name string) ([]byte, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	loc, err := m.assetLocation(name)
	if err != nil {
		return nil, err
	}
	b, _, err := readAssetLocation(loc)
	return b, err
}

func (m *Manager) currentAutolistOwner(name string) (*assetOwner, error) {
	if !automaticStrategyList(name) {
		return nil, nil
	}
	confLoc, _ := m.assetLocation("nfqws2.conf")
	conf, _, err := readAssetLocation(confLoc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return newAutolistOwner(conf)
}

func (m *Manager) SaveAsset(name string, data []byte, overwrite bool) error {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	if len(data) > AssetMaxBytes {
		return fmt.Errorf("файл превышает предел 16 МиБ")
	}
	loc, err := m.assetLocation(name)
	if err != nil {
		return err
	}
	data, _, err = prepareAssetData(loc.kind, name, data)
	if err != nil {
		return err
	}
	_, mode, err := readAssetLocation(loc)
	if err == nil && !overwrite {
		return ErrAssetConflict
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if mode == 0 {
		mode = 0644
		if loc.kind == "script" {
			mode = 0755
		}
	}
	var owner *assetOwner
	if errors.Is(err, os.ErrNotExist) && automaticStrategyList(name) {
		owner, err = m.currentAutolistOwner(name)
		if err != nil {
			return err
		}
	}
	return writeAssetLocation(loc, data, mode, owner)
}

func (m *Manager) DeleteAsset(name string) error {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	if name == "nfqws2.conf" {
		return fmt.Errorf("активный конфиг нельзя удалить; его можно заменить")
	}
	loc, err := m.assetLocation(name)
	if err != nil {
		return err
	}
	return removeAssetLocation(loc)
}
