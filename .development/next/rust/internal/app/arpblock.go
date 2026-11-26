package app

import (
	"context"
	"nfqws2strategy/internal/services/arpblock"
)

func (a *App) ARPBlockView(ctx context.Context) (arpblock.View, error) {
	return a.arpblock.View(ctx)
}

func (a *App) SetARPBlockIsolation(ctx context.Context, c arpblock.Change) (arpblock.View, error) {
	return a.arpblock.SetIsolation(ctx, c)
}
