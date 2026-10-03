package nfqws2

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
)

type archiveEntry struct {
	data       []byte
	mode       fs.FileMode
	normalized bool
}
type archiveFiles map[string]archiveEntry

type ArchiveFilePreview struct {
	Path          string `json:"path"`
	Size          int    `json:"size"`
	Exists        bool   `json:"exists"`
	ProtectedList bool   `json:"protected_list"`
}
type ArchivePreview struct {
	Digest         string               `json:"digest"`
	Files          []ArchiveFilePreview `json:"files"`
	Conflicts      []string             `json:"conflicts"`
	ProtectedLists []string             `json:"protected_lists"`
	Removed        []string             `json:"removed"`
	Warnings       []string             `json:"warnings"`
}
type ArchiveImportOptions struct {
	Digest    string
	Overwrite bool
	Lists     string
}
type ArchiveImportResult struct {
	Snapshot Snapshot `json:"snapshot"`
	Imported []string `json:"imported"`
	Kept     []string `json:"kept"`
	Removed  []string `json:"removed"`
}
type Snapshot struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
	Automatic bool   `json:"automatic"`
}

func protectedStrategyList(name string) bool {
	if !strings.HasPrefix(name, "lists/") {
		return false
	}
	base := strings.ToLower(path.Base(name))
	base = strings.TrimSuffix(base, ".gz")
	stem := strings.TrimSuffix(base, path.Ext(base))
	return stem == "user" || stem == "auto" || stem == "userlist" || stem == "autolist" || strings.HasPrefix(stem, "userlist-") || strings.HasPrefix(stem, "autolist-") || stem == "hostlist-auto"
}

func automaticStrategyList(name string) bool {
	if !strings.HasPrefix(name, "lists/") || strings.HasSuffix(strings.ToLower(name), ".gz") {
		return false
	}
	base := strings.ToLower(path.Base(name))
	stem := strings.TrimSuffix(base, path.Ext(base))
	return stem == "auto" || stem == "autolist" || strings.HasPrefix(stem, "autolist-") || stem == "hostlist-auto" || stem == "hostlist_auto"
}

// A plain list shadows its compressed sibling in the editor. Treat both as
// the same personal list when keeping the user's existing data, but never
// decompress, rename or delete the alternate format implicitly.
func existingPersonalList(current archiveFiles, name string) string {
	if _, exists := current[name]; exists {
		return name
	}
	alternate := name + ".gz"
	if strings.EqualFold(path.Ext(name), ".gz") {
		alternate = name[:len(name)-3]
	}
	if _, exists := current[alternate]; exists {
		return alternate
	}
	return ""
}

func keepExistingPersonalList(current archiveFiles, name, choice string) bool {
	return choice == "keep" && protectedStrategyList(name) && existingPersonalList(current, name) != ""
}

func sortedArchiveNames(files archiveFiles) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (m *Manager) collectArchiveLocked() (archiveFiles, error) {
	assets, err := m.listAssetsLocked()
	if err != nil {
		return nil, err
	}
	out := make(archiveFiles, len(assets.Files))
	total := 0
	for _, item := range assets.Files {
		loc, err := m.assetLocation(item.Path)
		if err != nil {
			return nil, err
		}
		data, mode, err := readAssetLocation(loc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", item.Path, err)
		}
		total += len(data)
		if total > ArchiveExpandedMaxBytes {
			return nil, fmt.Errorf("размер стратегии превышает 64 МиБ")
		}
		out[item.Path] = archiveEntry{data: data, mode: mode}
	}
	return out, nil
}

func encodeStrategyArchive(files archiveFiles) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range sortedArchiveNames(files) {
		entry := files[name]
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(entry.mode.Perm())
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err = w.Write(entry.data); err != nil {
			return nil, err
		}
		if buf.Len() > ArchiveMaxBytes {
			return nil, fmt.Errorf("ZIP превышает 32 МиБ")
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > ArchiveMaxBytes {
		return nil, fmt.Errorf("ZIP превышает 32 МиБ")
	}
	return buf.Bytes(), nil
}

func (m *Manager) decodeStrategyArchive(data []byte) (archiveFiles, error) {
	if len(data) == 0 || len(data) > ArchiveMaxBytes {
		return nil, fmt.Errorf("ZIP должен быть не больше 32 МиБ")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть ZIP: %w", err)
	}
	if len(zr.File) > ArchiveMaxFiles*2 {
		return nil, fmt.Errorf("слишком много записей в ZIP")
	}
	out := make(archiveFiles)
	seen := make(map[string]bool)
	total := uint64(0)
	for _, file := range zr.File {
		name := file.Name
		if file.FileInfo().IsDir() {
			if err = cleanAssetName(strings.TrimSuffix(name, "/")); err != nil {
				return nil, err
			}
			continue
		}
		if file.Mode()&fs.ModeType != 0 {
			return nil, fmt.Errorf("ссылки и специальные файлы запрещены: %s", name)
		}
		if err = cleanAssetName(name); err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, "lits/") {
			name = "lists/" + strings.TrimPrefix(name, "lits/")
		}
		if !strings.Contains(name, "/") && strings.HasSuffix(name, ".sh") {
			name = "scripts/" + name
		}
		if !strings.Contains(name, "/") && (strings.HasSuffix(name, ".lua") || strings.HasSuffix(name, ".lua.gz")) {
			name = "lua/" + name
		}
		loc, err := m.assetLocation(name)
		if err != nil {
			return nil, err
		}
		// Case aliases are ambiguous when a strategy moves through Windows.
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("повторяющийся путь в ZIP: %s", name)
		}
		seen[strings.ToLower(name)] = true
		if len(out) >= ArchiveMaxFiles {
			return nil, fmt.Errorf("слишком много файлов в ZIP")
		}
		if file.UncompressedSize64 > AssetMaxBytes || file.UncompressedSize64 > ArchiveExpandedMaxBytes-total {
			return nil, fmt.Errorf("размер распакованного ZIP превышает лимит")
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(reader, AssetMaxBytes+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("%s: %w", name, readErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(body) > AssetMaxBytes || uint64(len(body)) != file.UncompressedSize64 {
			return nil, fmt.Errorf("неверный размер файла в ZIP: %s", name)
		}
		total += uint64(len(body))
		if total > ArchiveExpandedMaxBytes {
			return nil, fmt.Errorf("ZIP после распаковки превышает 64 МиБ")
		}
		body, normalized, err := prepareAssetData(loc.kind, name, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		// Archives may not introduce special permission bits or executable blobs.
		mode := fs.FileMode(0644)
		if loc.kind == "script" {
			mode = 0755
		}
		out[name] = archiveEntry{data: body, mode: mode, normalized: normalized}
	}
	if _, exists := out["nfqws2.conf"]; !exists {
		return nil, fmt.Errorf("в архиве отсутствует nfqws2.conf")
	}
	return out, nil
}

func archivePreview(files, current archiveFiles, restore bool) ArchivePreview {
	out := ArchivePreview{Files: []ArchiveFilePreview{}, Conflicts: []string{}, ProtectedLists: []string{}, Removed: []string{}, Warnings: []string{}}
	h := sha256.New()
	if restore {
		h.Write([]byte("restore\x00"))
	} else {
		h.Write([]byte("import\x00"))
	}
	for groupIndex, group := range []archiveFiles{files, current} {
		for _, name := range sortedArchiveNames(group) {
			// NFQWS appends autolists while the preview is open. Their incoming
			// contents remain bound below, but live contents need no reapproval:
			// keep preserves the latest list and replace is an explicit choice.
			if groupIndex == 1 && protectedStrategyList(name) {
				fmt.Fprintf(h, "%s\x00personal-list\n", name)
				continue
			}
			sum := sha256.Sum256(group[name].data)
			fmt.Fprintf(h, "%s\x00%o\x00%x\n", name, group[name].mode, sum)
		}
		h.Write([]byte("\x00"))
	}
	out.Digest = hex.EncodeToString(h.Sum(nil))
	textNormalized := false
	personalFormatDiffers := false
	for _, name := range sortedArchiveNames(files) {
		textNormalized = textNormalized || files[name].normalized
		_, exists := current[name]
		protected := protectedStrategyList(name)
		out.Files = append(out.Files, ArchiveFilePreview{Path: name, Size: len(files[name].data), Exists: exists, ProtectedList: protected})
		if exists {
			out.Conflicts = append(out.Conflicts, name)
		}
		if protected {
			out.ProtectedLists = append(out.ProtectedLists, name)
			existing := existingPersonalList(current, name)
			personalFormatDiffers = personalFormatDiffers || existing != "" && existing != name
		}
	}
	if len(out.ProtectedLists) > 0 {
		out.Warnings = append(out.Warnings, "«Оставить свои» сохраняет существующие личные списки; отсутствующие списки будут импортированы из архива.")
	}
	if personalFormatDiffers {
		out.Warnings = append(out.Warnings, "Личные списки есть в другом формате — обычном или .gz. При выборе «Оставить свои» сохранятся их текущие имена; проверьте ссылки на эти списки в импортированном конфиге.")
	}
	if textNormalized {
		out.Warnings = append(out.Warnings, "В текстовых файлах Windows окончания строк будут заменены на LF, начальная метка UTF-8 BOM будет удалена.")
	}
	if restore {
		for _, name := range sortedArchiveNames(current) {
			if _, exists := files[name]; !exists {
				out.Removed = append(out.Removed, name)
			}
		}
		if len(out.Removed) > 0 {
			out.Warnings = append(out.Warnings, "При восстановлении будут удалены файлы, добавленные после этого снимка. Личные списки сохранятся при выборе «Оставить свои».")
		}
	}
	out.Warnings = append(out.Warnings, "Импорт сохраняет файлы. Для запуска стратегии примените конфиг отдельно.")
	return out
}

func (m *Manager) StrategyExport() ([]byte, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	files, err := m.collectArchiveLocked()
	if err != nil {
		return nil, err
	}
	if _, exists := files["nfqws2.conf"]; !exists {
		return nil, fmt.Errorf("активный nfqws2.conf не найден")
	}
	return encodeStrategyArchive(files)
}

func (m *Manager) StrategyPreview(data []byte, snapshot string) (ArchivePreview, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	if snapshot != "" {
		var err error
		data, err = m.snapshotBytesLocked(snapshot)
		if err != nil {
			return ArchivePreview{}, err
		}
	}
	files, err := m.decodeStrategyArchive(data)
	if err != nil {
		return ArchivePreview{}, err
	}
	current, err := m.collectArchiveLocked()
	if err != nil {
		return ArchivePreview{}, err
	}
	return archivePreview(files, current, snapshot != ""), nil
}

func (m *Manager) StrategyImport(data []byte, snapshot string, opts ArchiveImportOptions) (ArchiveImportResult, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	out := ArchiveImportResult{Imported: []string{}, Kept: []string{}, Removed: []string{}}
	if snapshot != "" {
		var err error
		data, err = m.snapshotBytesLocked(snapshot)
		if err != nil {
			return out, err
		}
	}
	files, err := m.decodeStrategyArchive(data)
	if err != nil {
		return out, err
	}
	current, err := m.collectArchiveLocked()
	if err != nil {
		return out, err
	}
	preview := archivePreview(files, current, snapshot != "")
	if opts.Digest == "" || opts.Digest != preview.Digest {
		return out, ErrArchiveChanged
	}
	if len(preview.ProtectedLists) > 0 && opts.Lists != "keep" && opts.Lists != "replace" {
		return out, fmt.Errorf("выберите, сохранить свои userlist/autolist или применить списки из архива")
	}
	if opts.Lists != "" && opts.Lists != "keep" && opts.Lists != "replace" {
		return out, fmt.Errorf("неверный режим личных списков")
	}
	for _, name := range preview.Conflicts {
		if keepExistingPersonalList(current, name, opts.Lists) {
			continue
		}
		if !opts.Overwrite {
			return out, ErrAssetConflict
		}
	}
	if len(preview.Removed) > 0 && !opts.Overwrite {
		return out, ErrAssetConflict
	}
	var newListOwner *assetOwner
	for name := range files {
		if !keepExistingPersonalList(current, name, opts.Lists) {
			if _, exists := current[name]; !exists && automaticStrategyList(name) {
				newListOwner, err = newAutolistOwner(files["nfqws2.conf"].data)
				if err != nil {
					return out, err
				}
				break
			}
		}
	}
	// Rollback uses the same in-memory originals as the automatic snapshot.
	// The snapshot is durable before any live file is replaced.
	out.Snapshot, err = m.createSnapshotLocked("Перед импортом стратегии", true, current)
	if err != nil {
		return out, fmt.Errorf("не удалось создать резервный снимок: %w", err)
	}
	changed := []string{}
	rollback := func(cause error) (ArchiveImportResult, error) {
		var failures []error
		for i := len(changed) - 1; i >= 0; i-- {
			name := changed[i]
			loc, e := m.assetLocation(name)
			if e == nil {
				if old, exists := current[name]; exists {
					e = writeAssetLocation(loc, old.data, old.mode)
				} else {
					e = removeAssetLocation(loc)
					if errors.Is(e, os.ErrNotExist) {
						e = nil
					}
				}
			}
			if e != nil {
				failures = append(failures, fmt.Errorf("%s: %w", name, e))
			}
		}
		if len(failures) > 0 {
			return out, fmt.Errorf("%w; откат не завершён: %v; резервный снимок: %s", cause, errors.Join(failures...), out.Snapshot.ID)
		}
		return out, fmt.Errorf("%w; исходные файлы восстановлены", cause)
	}
	// Write config last so failures in assets cannot expose a half-new strategy.
	names := sortedArchiveNames(files)
	sort.SliceStable(names, func(i, j int) bool { return names[i] != "nfqws2.conf" && names[j] == "nfqws2.conf" })
	for _, name := range names {
		if keepExistingPersonalList(current, name, opts.Lists) {
			out.Kept = append(out.Kept, name)
			continue
		}
		entry := files[name]
		loc, _ := m.assetLocation(name)
		var owner *assetOwner
		if automaticStrategyList(name) {
			owner = newListOwner
		}
		if err = writeAssetLocation(loc, entry.data, entry.mode, owner); err != nil {
			return rollback(fmt.Errorf("%s: %w", name, err))
		}
		changed = append(changed, name)
		out.Imported = append(out.Imported, name)
	}
	for _, name := range preview.Removed {
		if protectedStrategyList(name) && opts.Lists != "replace" {
			out.Kept = append(out.Kept, name)
			continue
		}
		loc, _ := m.assetLocation(name)
		if err = removeAssetLocation(loc); err != nil {
			return rollback(fmt.Errorf("%s: %w", name, err))
		}
		changed = append(changed, name)
		out.Removed = append(out.Removed, name)
	}
	return out, nil
}

func (m *Manager) snapshotDir() string { return filepath.Join(m.cfg.DataDir, "strategy-snapshots") }

func validSnapshotID(id string) bool {
	if len(id) != 41 || !strings.HasSuffix(id, ".zip") {
		return false
	}
	if id[16] != '-' {
		return false
	}
	if _, err := time.Parse("20060102T150405Z", id[:16]); err != nil {
		return false
	}
	_, err := hex.DecodeString(id[17:37])
	return err == nil
}

func (m *Manager) listSnapshotsLocked() ([]Snapshot, error) {
	out := []Snapshot{}
	r, err := openAssetRoot(m.snapshotDir(), false)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	entries, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !validSnapshotID(entry.Name()) {
			continue
		}
		st, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			continue
		}
		item := Snapshot{ID: entry.Name(), Name: "Стратегия", Size: st.Size(), CreatedAt: st.ModTime().UTC().Format(time.RFC3339Nano)}
		if metaFile, err := r.Open(entry.Name() + ".json"); err == nil {
			b, readErr := io.ReadAll(io.LimitReader(metaFile, 4097))
			metaFile.Close()
			var meta Snapshot
			if readErr == nil && len(b) <= 4096 && json.Unmarshal(b, &meta) == nil {
				item.Name = meta.Name
				item.Automatic = meta.Automatic
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		iTime, _ := time.Parse(time.RFC3339Nano, out[i].CreatedAt)
		jTime, _ := time.Parse(time.RFC3339Nano, out[j].CreatedAt)
		return iTime.After(jTime)
	})
	return out, nil
}

func (m *Manager) createSnapshotLocked(name string, automatic bool, files archiveFiles) (Snapshot, error) {
	var out Snapshot
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Стратегия"
	}
	if len(name) > 160 || strings.ContainsAny(name, "\x00\r\n") {
		return out, fmt.Errorf("слишком длинное или недопустимое имя снимка")
	}
	existing, err := m.listSnapshotsLocked()
	if err != nil {
		return out, err
	}
	manual := 0
	var total int64
	for _, s := range existing {
		if !s.Automatic {
			manual++
		}
		total += s.Size
	}
	if !automatic && manual >= 10 {
		return out, fmt.Errorf("сохранено 10 снимков; удалите ненужный перед созданием нового")
	}
	data, err := encodeStrategyArchive(files)
	if err != nil {
		return out, err
	}
	if total+int64(len(data)) > 128<<20 {
		return out, fmt.Errorf("снимки занимают больше 128 МиБ; удалите ненужные")
	}
	var idBytes [10]byte
	if _, err = rand.Read(idBytes[:]); err != nil {
		return out, err
	}
	id := time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(idBytes[:]) + ".zip"
	out = Snapshot{ID: id, Name: name, Size: int64(len(data)), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Automatic: automatic}
	loc := assetLocation{m.snapshotDir(), id, "snapshot"}
	if err = writeAssetLocation(loc, data, 0600); err != nil {
		return Snapshot{}, err
	}
	meta, _ := json.Marshal(out)
	if err = writeAssetLocation(assetLocation{m.snapshotDir(), id + ".json", "snapshot"}, meta, 0600); err != nil {
		_ = removeAssetLocation(loc)
		return Snapshot{}, err
	}
	// Keep the last three automatic rollback points. Named user snapshots remain.
	if automatic {
		count := 1
		for _, s := range existing {
			if s.Automatic {
				count++
				if count > 3 {
					_ = m.deleteSnapshotLocked(s.ID)
				}
			}
		}
	}
	return out, nil
}

func (m *Manager) StrategySnapshots() ([]Snapshot, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	return m.listSnapshotsLocked()
}
func (m *Manager) StrategySnapshotCreate(name string) (Snapshot, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	files, err := m.collectArchiveLocked()
	if err != nil {
		return Snapshot{}, err
	}
	if _, exists := files["nfqws2.conf"]; !exists {
		return Snapshot{}, fmt.Errorf("nfqws2.conf не найден")
	}
	return m.createSnapshotLocked(name, false, files)
}
func (m *Manager) snapshotBytesLocked(id string) ([]byte, error) {
	if !validSnapshotID(id) {
		return nil, fmt.Errorf("недопустимый идентификатор снимка")
	}
	r, err := openAssetRoot(m.snapshotDir(), false)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if err = checkAssetDescendants(r, id); err != nil {
		return nil, err
	}
	f, err := r.Open(id)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, ArchiveMaxBytes+1))
	if len(data) > ArchiveMaxBytes {
		return nil, fmt.Errorf("снимок превышает 32 МиБ")
	}
	return data, err
}
func (m *Manager) StrategySnapshotBytes(id string) ([]byte, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	return m.snapshotBytesLocked(id)
}
func (m *Manager) deleteSnapshotLocked(id string) error {
	if !validSnapshotID(id) {
		return fmt.Errorf("недопустимый идентификатор снимка")
	}
	if err := removeAssetLocation(assetLocation{m.snapshotDir(), id, "snapshot"}); err != nil {
		return err
	}
	if err := removeAssetLocation(assetLocation{m.snapshotDir(), id + ".json", "snapshot"}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (m *Manager) StrategySnapshotDelete(id string) error {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	return m.deleteSnapshotLocked(id)
}
