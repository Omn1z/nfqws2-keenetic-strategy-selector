package awgroute

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"nfqws2strategy/internal/tools/store"
)

func restoredHistoryWire(t *testing.T, domain string) []byte {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var history routingLearnedHistory
	history.Record("rule", domain, "", []string{"192.0.2.20"}, "dns", true, 0, 0, time.Unix(2000, 0))
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(st.Path(routingLearnedFile))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func awaitRoutingRestore(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("history operation did not finish")
	}
}

func TestRoutingHistoryRestoreQuiescesDelayedAndShutdownFlush(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st}
	svc.discovered.Record("rule", "old.example", "", []string{"192.0.2.1"}, "dns", true, 0, 0, time.Unix(1000, 0))
	if err := svc.discovered.Flush(st); err != nil {
		t.Fatal(err)
	}
	svc.discovered.Record("rule", "pending.example", "", []string{"192.0.2.2"}, "dns", true, 0, 0, time.Unix(1001, 0))
	wire := restoredHistoryWire(t, "restored.example")
	written, release := make(chan struct{}), make(chan struct{})
	restored := make(chan error, 1)
	go func() {
		_, err := svc.RestoreRoutingDiscoveries(func() (int, error) {
			if err := os.WriteFile(st.Path(routingLearnedFile), wire, 0o600); err != nil {
				return 0, err
			}
			close(written)
			<-release
			return 1, nil
		})
		restored <- err
	}()
	<-written
	// This is the same Flush invoked by the delayed persistence callback.
	flushed, closed := make(chan error, 1), make(chan error, 1)
	go func() { svc.flushRoutingDiscoveries(); flushed <- nil }()
	go func() { svc.CloseRoutingDiscoveries(); closed <- nil }()
	// Pausing observational collection cannot hold up a prepared DNS reply.
	recorded := make(chan error, 1)
	go func() {
		svc.discovered.Record("rule", "during.example", "", []string{"192.0.2.3"}, "dns", true, 0, 0, time.Unix(1002, 0))
		recorded <- nil
	}()
	awaitRoutingRestore(t, recorded)
	close(release)
	awaitRoutingRestore(t, restored)
	awaitRoutingRestore(t, flushed)
	awaitRoutingRestore(t, closed)
	entries := svc.discovered.Snapshot("rule", 0, 0, true)
	if len(entries) != 1 || entries[0].Domain != "restored.example" || entries[0].Confirmed {
		t.Fatalf("restored history replaced by running observations: %+v", entries)
	}
	got, err := os.ReadFile(st.Path(routingLearnedFile))
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("restored file overwritten: %s %v", got, err)
	}
	if svc.routingDNSGate.generation != 0 || svc.routingDNSGate.writeEpoch != 0 || svc.routingDNSGate.applying {
		t.Fatal("history restore changed the active routing policy")
	}
}

func TestRoutingHistoryFailedRestoreRetainsDirtyCollectorAndRollsBackPartialFile(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "archive failure", true: "invalid restored history"}[malformed], func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			var history routingLearnedHistory
			history.Record("rule", "old.example", "", []string{"192.0.2.1"}, "dns", true, 7, 9, time.Unix(1000, 0))
			if err := history.Flush(st); err != nil {
				t.Fatal(err)
			}
			previous, err := os.ReadFile(st.Path(routingLearnedFile))
			if err != nil {
				t.Fatal(err)
			}
			history.Record("rule", "pending.example", "", []string{"192.0.2.2"}, "dns", true, 7, 9, time.Unix(1001, 0))
			before := history.Snapshot("rule", 7, 9, true)
			failure := errors.New("truncated archive")
			_, err = history.Restore(st, func() (int, error) {
				if err := os.WriteFile(st.Path(routingLearnedFile), []byte("{partial"), 0o600); err != nil {
					return 0, err
				}
				if malformed {
					return 1, nil
				}
				return 0, failure
			})
			if err == nil || (!malformed && !errors.Is(err, failure)) {
				t.Fatalf("restore error lost: %v", err)
			}
			if got := history.Snapshot("rule", 7, 9, true); !reflect.DeepEqual(got, before) {
				t.Fatalf("failed restore discarded current history: %+v", got)
			}
			got, err := os.ReadFile(st.Path(routingLearnedFile))
			if err != nil || !bytes.Equal(got, previous) {
				t.Fatalf("partial archive replaced original file: %s %v", got, err)
			}
			history.Record("rule", "after.example", "", []string{"192.0.2.3"}, "dns", true, 7, 9, time.Unix(1002, 0))
			if err := history.Flush(st); err != nil {
				t.Fatal(err)
			}
			var loaded routingLearnedHistory
			if err := loaded.Load(st); err != nil || len(loaded.Snapshot("rule", 7, 9, true)) != 3 {
				t.Fatalf("collector did not resume after failure: %v", err)
			}
		})
	}
}

func TestRoutingHistoryRestoreWithoutFileDiscardsOldDirtyMemory(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var history routingLearnedHistory
	history.Record("rule", "old.example", "", []string{"192.0.2.1"}, "dns", true, 0, 0, time.Unix(1000, 0))
	if _, err := history.Restore(st, func() (int, error) { return 0, nil }); err != nil {
		t.Fatal(err)
	}
	if len(history.Snapshot("rule", 0, 0, true)) != 0 {
		t.Fatal("old unsaved history survived restored missing file")
	}
	if err := history.Flush(st); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.Path(routingLearnedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old history recreated after restore: %v", err)
	}
}
