package app

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"nfqws2strategy/internal/tools/store"
)

func TestRunHistoryLoadsOnceAcrossConcurrentReadersAndRestoresInterruptedRuns(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st}
	for _, r := range []Run{{ID: "older", StartedAt: 2, Status: "done"}, {ID: "interrupted", StartedAt: 9, Status: "running"}} {
		if err := st.Save(filepath.Join("runs", r.ID+".json"), &r); err != nil {
			t.Fatal(err)
		}
	}
	if a.ActiveRun() != nil || a.runs != nil {
		t.Fatal("checking live state loaded the saved history")
	}
	start := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 16; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			if i%2 == 0 {
				r, ok := a.GetRun("interrupted")
				if !ok || r.Status != "error" || r.Error != "interrupted" {
					t.Error("missing interrupted run")
				}
			} else if runs := a.Runs(); len(runs) != 2 || runs[0].ID != "interrupted" || runs[1].ID != "older" {
				t.Error("incomplete or duplicated history")
			}
		}()
	}
	close(start)
	readers.Wait()
	if err := st.Delete(filepath.Join("runs", "older.json")); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.GetRun("older"); !ok {
		t.Fatal("history was scanned again")
	}
}

func TestRegisterRunLoadsHistoryBeforeAppendAndRetention(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxStoredRuns {
		r := &Run{ID: fmt.Sprint(i), StartedAt: int64(i), Status: "done"}
		if err := st.Save(filepath.Join("runs", r.ID+".json"), r); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{store: st}
	live := &Run{ID: "new", Status: "running", Results: []StrategyResult{{Name: "original"}}}
	if err := a.registerRun(live, func() {}); err != nil {
		t.Fatal(err)
	}
	runs := a.Runs()
	if len(runs) != maxStoredRuns || runs[0].ID != "new" || runs[len(runs)-1].ID != "1" || st.Exists(filepath.Join("runs", "0.json")) {
		t.Fatal("first new run did not apply retention to previous history")
	}
	live.Results[0].Name = "changed"
	live.Status = "done"
	if runs[0].Status != "running" || runs[0].Results[0].Name != "original" {
		t.Fatal("history reader was given a mutable live run")
	}
}
