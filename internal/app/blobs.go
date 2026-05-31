package app

import "nfqws2strategy/internal/services/blobs"

// The fake-payload blob store (Blobs tab) now lives in internal/services/blobs.
// This alias + thin delegators keep the App surface the HTTP handlers and
// portable.go (zip import/export) call unchanged. ResolveBlob/Dir/SaveBlob are
// reached directly via a.blobs from the run-strategy expansion and portable.go.

type BlobCapture = blobs.BlobCapture

func (a *App) Blobs() (system, custom []string) { return a.blobs.Blobs() }
func (a *App) SaveBlob(name string, data []byte) (string, error) {
	return a.blobs.SaveBlob(name, data)
}
func (a *App) DeleteBlob(name string) error  { return a.blobs.DeleteBlob(name) }
func (a *App) TrashedBlobs() []string        { return a.blobs.TrashedBlobs() }
func (a *App) RestoreBlob(name string) error { return a.blobs.RestoreBlob(name) }
func (a *App) PurgeBlob(name string) error   { return a.blobs.PurgeBlob(name) }
func (a *App) EmptyTrash() error             { return a.blobs.EmptyTrash() }

func (a *App) ValidateBlob(name string) (bool, string, error) { return a.blobs.ValidateBlob(name) }
func (a *App) GenerateBlob(sni string, alpn []string, minVer uint16, name string) (string, error) {
	return a.blobs.GenerateBlob(sni, alpn, minVer, name)
}

func (a *App) StartBlobCapture(ip string, seconds int) (*BlobCapture, error) {
	return a.blobs.StartBlobCapture(ip, seconds)
}
func (a *App) GetBlobCapture(id string) (*BlobCapture, bool) { return a.blobs.GetBlobCapture(id) }
func (a *App) SaveCapturedBlob(id string, index int, name string) (string, error) {
	return a.blobs.SaveCapturedBlob(id, index, name)
}
