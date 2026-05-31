package app

import "nfqws2strategy/internal/nfqws2ctl"

// The nfqws2 engine's file management + version/update/reload now lives in
// internal/nfqws2ctl. These type aliases + thin delegators keep the App method
// surface that the HTTP handlers (internal/server) call unchanged. (Start/Stop
// live in services.go — they're service-control, a separate concern.)

type (
	Nfqws2File        = nfqws2ctl.File
	Nfqws2VersionInfo = nfqws2ctl.VersionInfo
)

func (a *App) ListNfqws2Files(kind string) ([]Nfqws2File, error) { return a.nfqws2.List(kind) }
func (a *App) ReadNfqws2File(kind, name string) (string, error)  { return a.nfqws2.Read(kind, name) }
func (a *App) SaveNfqws2File(kind, name, content string) error {
	return a.nfqws2.Save(kind, name, content)
}
func (a *App) CreateNfqws2File(kind, name string) error { return a.nfqws2.Create(kind, name) }
func (a *App) DeleteNfqws2File(kind, name string) error { return a.nfqws2.Delete(kind, name) }
func (a *App) SaveNfqws2Upload(kind, filename string, data []byte) error {
	return a.nfqws2.Upload(kind, filename, data)
}
func (a *App) Nfqws2FileBytes(kind, name string) ([]byte, string, error) {
	return a.nfqws2.Bytes(kind, name)
}
func (a *App) Nfqws2Version() Nfqws2VersionInfo     { return a.nfqws2.Version() }
func (a *App) Nfqws2CheckUpdate() Nfqws2VersionInfo { return a.nfqws2.CheckUpdate() }
func (a *App) Nfqws2Update() (string, error)        { return a.nfqws2.Update() }
func (a *App) Nfqws2Reload() error                  { return a.nfqws2.Reload() }
