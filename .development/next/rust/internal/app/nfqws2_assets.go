package app

import "nfqws2strategy/internal/services/nfqws2"

func (a *App) Nfqws2Assets() (nfqws2.Assets, error)         { return a.nfqws2.Assets() }
func (a *App) Nfqws2AssetBytes(name string) ([]byte, error) { return a.nfqws2.AssetBytes(name) }
func (a *App) Nfqws2SaveAsset(name string, data []byte, overwrite bool) error {
	return a.nfqws2.SaveAsset(name, data, overwrite)
}
func (a *App) Nfqws2DeleteAsset(name string) error   { return a.nfqws2.DeleteAsset(name) }
func (a *App) Nfqws2StrategyExport() ([]byte, error) { return a.nfqws2.StrategyExport() }
func (a *App) Nfqws2StrategyPreview(data []byte, snapshot string) (nfqws2.ArchivePreview, error) {
	return a.nfqws2.StrategyPreview(data, snapshot)
}
func (a *App) Nfqws2StrategyImport(data []byte, snapshot string, options nfqws2.ArchiveImportOptions) (nfqws2.ArchiveImportResult, error) {
	return a.nfqws2.StrategyImport(data, snapshot, options)
}
func (a *App) Nfqws2StrategySnapshots() ([]nfqws2.Snapshot, error) {
	return a.nfqws2.StrategySnapshots()
}
func (a *App) Nfqws2StrategySnapshotCreate(name string) (nfqws2.Snapshot, error) {
	return a.nfqws2.StrategySnapshotCreate(name)
}
func (a *App) Nfqws2StrategySnapshotBytes(id string) ([]byte, error) {
	return a.nfqws2.StrategySnapshotBytes(id)
}
func (a *App) Nfqws2StrategySnapshotDelete(id string) error {
	return a.nfqws2.StrategySnapshotDelete(id)
}
