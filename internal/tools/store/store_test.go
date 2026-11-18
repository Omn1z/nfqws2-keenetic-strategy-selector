package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fixtureConfig struct {
	Name  string            `json:"name"`
	Map   map[string]string `json:"map,omitempty"`
	Count int               `json:"count"`
}

func validateFixture(b []byte) error {
	var c fixtureConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.Name == "" {
		return errors.New("missing config identity")
	}
	return nil
}
func protectedFixture(t *testing.T) (*Store, fixtureConfig) {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var empty fixtureConfig
	if _, err = s.LoadConfig("critical.json", &empty, validateFixture); !os.IsNotExist(err) {
		t.Fatalf("first load=%v", err)
	}
	c := fixtureConfig{Name: "configured", Count: 7}
	if err = s.SaveSecret("critical.json", c); err != nil {
		t.Fatal(err)
	}
	return s, c
}
func TestDurableWriteOrdersFlushBeforePublishAndReportsUncertainCommit(t *testing.T) {
	for _, failure := range []string{"", "write", "file-sync", "close", "rename", "dir-sync"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := New(t.TempDir())
			if err := s.Save("settings.json", map[string]int{"value": 1}); err != nil {
				t.Fatal(err)
			}
			var events []string
			s.fault = func(stage, path string) error {
				if path == s.Path("settings.json") {
					events = append(events, stage)
					if stage == failure {
						return errors.New("interrupted")
					}
				}
				return nil
			}
			err := s.Save("settings.json", map[string]int{"value": 2})
			if (err != nil) != (failure != "") {
				t.Fatalf("save=%v", err)
			}
			var got map[string]int
			if err := s.Load("settings.json", &got); err != nil {
				t.Fatal(err)
			}
			want := 1
			if failure == "" || failure == "dir-sync" {
				want = 2
			}
			if got["value"] != want {
				t.Fatal("incomplete or unexpected primary published")
			}
			var committed *CommitError
			if errors.As(err, &committed) != (failure == "dir-sync") {
				t.Fatalf("commit outcome=%v", err)
			}
			if failure == "" && !reflect.DeepEqual(events, []string{"write", "file-sync", "close", "rename", "dir-sync"}) {
				t.Fatalf("durability order=%v", events)
			}
			files, _ := filepath.Glob(filepath.Join(s.dir, ".n2s-write-*"))
			if len(files) != 0 {
				t.Fatal("temporary inode leaked")
			}
		})
	}
}
func TestConfigRecoversLatestVerifiedGenerationAndPreservesEvidence(t *testing.T) {
	for _, bad := range []string{"", "\x00\x00", `{"name":`, "null", "{}", `{"name":"bad","count":"wrong"}`} {
		t.Run(fmt.Sprintf("bytes-%x", []byte(bad)), func(t *testing.T) {
			s, c := protectedFixture(t)
			c.Count = 9
			if err := s.SaveSecret("critical.json", c); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.Path("critical.json"), []byte(bad), 0o600); err != nil {
				t.Fatal(err)
			}
			reopened, _ := New(s.dir)
			var got fixtureConfig
			recovered, err := reopened.LoadConfig("critical.json", &got, validateFixture)
			if err != nil || !recovered || !reflect.DeepEqual(got, c) {
				t.Fatalf("recovery=%v err=%v result=%+v", recovered, err, got)
			}
			evidence, err := os.ReadFile(s.snapshotPrefix("critical.json") + ".corrupt")
			if err != nil || string(evidence) != bad {
				t.Fatal("damaged original was discarded")
			}
			if runtime.GOOS != "windows" {
				for _, name := range append(s.snapshotPaths("critical.json"), s.Path("critical.json")) {
					st, err := os.Stat(name)
					if err != nil || st.Mode().Perm() != 0o600 {
						t.Fatal("credentials/recovery file permissions are not private")
					}
				}
			}
		})
	}
}
func TestConfigRecoveryRejectsCorruptChecksumsAndFallsBackOneGeneration(t *testing.T) {
	s, old := protectedFixture(t)
	next := old
	next.Count = 8
	if err := s.SaveSecret("critical.json", next); err != nil {
		t.Fatal(err)
	}
	snaps, _ := s.snapshots("critical.json", validateFixture)
	latest := snaps[0]
	for _, snap := range snaps {
		if snap.Generation > latest.Generation {
			latest = snap
		}
	}
	latest.Generation += 100 // even a syntactically valid metadata bit flip is covered by the checksum
	b, _ := json.Marshal(latest)
	if err := os.WriteFile(s.snapshotPaths("critical.json")[latest.slot], b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.Path("critical.json")); err != nil {
		t.Fatal(err)
	}
	r, _ := New(s.dir)
	var got fixtureConfig
	ok, err := r.LoadConfig("critical.json", &got, validateFixture)
	if err != nil || !ok || got.Count != old.Count {
		t.Fatalf("fallback=%v %v %+v", ok, err, got)
	}
}
func TestConfigUnrecoverableNeverOverwritesAndRequiresExplicitRecovery(t *testing.T) {
	s, c := protectedFixture(t)
	for _, name := range append(s.snapshotPaths("critical.json"), s.Path("critical.json")) {
		if err := os.WriteFile(name, []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := New(s.dir)
	var got fixtureConfig
	if _, err := r.LoadConfig("critical.json", &got, validateFixture); !errors.Is(err, ErrConfigUnavailable) {
		t.Fatalf("bad load=%v", err)
	}
	if err := r.SaveSecret("critical.json", c); !errors.Is(err, ErrConfigUnavailable) {
		t.Fatalf("unsafe default save=%v", err)
	}
	b, _ := os.ReadFile(s.Path("critical.json"))
	if string(b) != "damaged" {
		t.Fatal("unrecoverable evidence overwritten")
	}
	if err := r.RecoverConfig("critical.json", fixtureConfig{}); err == nil {
		t.Fatal("invalid explicit import accepted")
	}
	if err := r.RecoverConfig("critical.json", c); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.Path("critical.json")); err != nil {
		t.Fatal(err)
	}
	r2, _ := New(r.dir)
	if ok, err := r2.LoadConfig("critical.json", &got, validateFixture); err != nil || !ok || got.Name != c.Name {
		t.Fatalf("explicit recovery did not establish durable backup: %v", err)
	}
}
func TestLoadCandidatesDoNotPartiallyMutateDestination(t *testing.T) {
	s, c := protectedFixture(t)
	bad := `{"name":"bad","map":{"polluted":"true"},"count":"wrong"}`
	if err := os.WriteFile(s.Path("critical.json"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	r, _ := New(s.dir)
	got := fixtureConfig{Map: map[string]string{"default": "kept"}}
	_, err := r.LoadConfig("critical.json", &got, nil)
	if err != nil || got.Count != c.Count || got.Map["polluted"] != "" || got.Map["default"] != "kept" {
		t.Fatalf("candidate contaminated defaults: %v %+v", err, got)
	}
	before := fixtureConfig{Name: "initial", Map: map[string]string{"safe": "yes"}}
	if err := s.WriteBytes("ordinary.json", []byte(bad)); err != nil {
		t.Fatal(err)
	}
	if err := s.Load("ordinary.json", &before); err == nil || before.Name != "initial" || len(before.Map) != 1 {
		t.Fatal("ordinary failed load mutated caller")
	}
}
func TestProtectedStoreRejectsAnotherInstanceAndExternalRestoreStaleWrites(t *testing.T) {
	s, c := protectedFixture(t)
	other, _ := New(s.dir)
	var old fixtureConfig
	if _, err := other.LoadConfig("critical.json", &old, validateFixture); err != nil {
		t.Fatal(err)
	}
	c.Count = 11
	if err := s.SaveSecret("critical.json", c); err != nil {
		t.Fatal(err)
	}
	if err := other.SaveSecret("critical.json", old); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("stale instance overwrote settings: %v", err)
	}
	if err := s.WithExclusive(func() error {
		_, err := s.durableReplace(s.Path("critical.json"), []byte(`{"name":"restored","count":12}`), 0o600)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSecret("critical.json", c); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("old RAM overwrote archive restore: %v", err)
	}
}

func TestUncertainProtectedCommitBlocksOldRAMUntilValidatedReload(t *testing.T) {
	s, old := protectedFixture(t)
	s.fault = func(stage, path string) error {
		if stage == "dir-sync" && path == s.Path("critical.json") {
			return errors.New("directory flush failed")
		}
		return nil
	}
	next := old
	next.Count = 22
	var commit *CommitError
	if err := s.SaveSecret("critical.json", next); !errors.As(err, &commit) {
		t.Fatalf("expected uncertain commit: %v", err)
	}
	s.fault = nil
	if err := s.SaveSecret("critical.json", old); !errors.Is(err, ErrConfigUnavailable) {
		t.Fatalf("old RAM save was not fenced: %v", err)
	}
	var actual fixtureConfig
	if err := s.Load("critical.json", &actual); err != nil || actual.Count != 22 {
		t.Fatal("follow-up save discarded the committed candidate")
	}
	if _, err := s.LoadConfig("critical.json", &actual, validateFixture); err != nil {
		t.Fatal(err)
	}
	actual.Count = 23
	if err := s.SaveSecret("critical.json", actual); err != nil {
		t.Fatalf("validated reload did not clear fence: %v", err)
	}
}
func TestDeleteCannotResurrectAndRecoveryMetadataStaysOutOfFileLists(t *testing.T) {
	s, c := protectedFixture(t)
	files, err := s.ListFiles("")
	if err != nil || !reflect.DeepEqual(files, []string{"critical.json"}) {
		t.Fatalf("internal recovery metadata leaked: %v", files)
	}
	if err := s.Delete("critical.json"); err != nil {
		t.Fatal(err)
	}
	r, _ := New(s.dir)
	if ok, err := r.LoadConfig("critical.json", &c, validateFixture); !os.IsNotExist(err) || ok {
		t.Fatalf("deleted config resurrected: %v %v", ok, err)
	}
}
func TestUniquePrivateTemporaryFileDoesNotReuseLegacyTmp(t *testing.T) {
	s, _ := New(t.TempDir())
	stale := s.Path("secret.json.tmp")
	if err := os.WriteFile(stale, []byte("foreign temporary file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSecret("secret.json", map[string]string{"key": "fixture-only"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(stale)
	if !bytes.Equal(b, []byte("foreign temporary file")) {
		t.Fatal("legacy shared temporary inode reused")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(s.Path("secret.json"))
		if st.Mode().Perm() != 0o600 {
			t.Fatal("secret became public before/after rename")
		}
	}
}
func TestSeparateProcessCannotOverwriteNewerConfiguration(t *testing.T) {
	s, c := protectedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStoreProcessWriter$")
	cmd.Env = append(os.Environ(), "N2S_STORE_TEST_CHILD="+s.dir)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(s.dir, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			_ = cmd.Wait()
			t.Fatalf("child did not load fixture: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Count = 99
	if err := s.SaveSecret("critical.json", c); err != nil {
		cancel()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "continue"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child CAS check: %v %s", err, output.String())
	}
	var got fixtureConfig
	if err := s.Load("critical.json", &got); err != nil || got.Count != 99 {
		t.Fatal("second process replaced newer durable config")
	}
}
func TestStoreProcessWriter(t *testing.T) {
	dir := os.Getenv("N2S_STORE_TEST_CHILD")
	if dir == "" {
		t.Skip("subprocess fixture only")
	}
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var c fixtureConfig
	if _, err = s.LoadConfig("critical.json", &c, validateFixture); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err = os.Stat(filepath.Join(dir, "continue")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent did not release child")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = s.SaveSecret("critical.json", c); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("stale process save=%v", err)
	}
}

func TestInterruptedProtectedWriteStillHasPreviousRecovery(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename", "dir-sync"} {
		t.Run(stage, func(t *testing.T) {
			s, c := protectedFixture(t)
			s.fault = func(at, path string) error {
				if path == s.Path("critical.json") && at == stage {
					return errors.New("power-loss boundary")
				}
				return nil
			}
			next := c
			next.Count = 25
			if err := s.SaveSecret("critical.json", next); err == nil {
				t.Fatal("injected error ignored")
			}
			// Model a lost/torn primary directory entry/data after the crash.
			if err := os.WriteFile(s.Path("critical.json"), []byte(strings.Repeat("\x00", 32)), 0o600); err != nil {
				t.Fatal(err)
			}
			r, _ := New(s.dir)
			var got fixtureConfig
			if ok, err := r.LoadConfig("critical.json", &got, validateFixture); err != nil || !ok || got.Count != c.Count {
				t.Fatalf("last confirmed config lost after %s: %v", stage, err)
			}
		})
	}
}
