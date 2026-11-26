//go:build n2s_compact

package app

import (
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

func TestCompactUpdatesUsePackageManager(t *testing.T) {
	a := &App{Cfg: &config.Config{Version: "dev"}}
	for _, check := range []func() (UpdateInfo, error){a.CheckUpdate, a.SelfUpdate} {
		info, err := check()
		if err == nil || !strings.Contains(err.Error(), "opkg") || info.Available {
			t.Fatal(info, err)
		}
	}
	state, err := a.StartSelfUpdate()
	if err == nil || state.Running {
		t.Fatal(state, err)
	}
}
