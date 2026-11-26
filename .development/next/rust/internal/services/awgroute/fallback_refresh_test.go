package awgroute

import (
	"errors"
	"testing"
)

func TestFallbackChangeRetriesAfterBusyOrFailedApply(t *testing.T) {
	svc := new(Service)
	calls := 0
	hooks := 0
	svc.SetClientRecoveryHook(func() { hooks++ })
	err := errors.New("kernel apply failed")
	apply := func() error { calls++; return err }
	if svc.refreshFallbackRouting("primary", true, apply) || calls != 0 || hooks != 0 {
		t.Fatal("baseline caused startup churn")
	}
	_, unlock := svc.lockClientOps(false)
	if svc.refreshFallbackRouting("backup", true, apply) || calls != 0 || hooks != 0 {
		t.Fatal("busy lifecycle applied policy")
	}
	unlock()
	if svc.clients.fallbackSignature != "primary" {
		t.Fatal("busy lifecycle consumed pending fallback change")
	}
	if svc.refreshFallbackRouting("backup", true, apply) || calls != 1 || hooks != 0 || svc.clients.fallbackSignature != "primary" {
		t.Fatal("failed apply consumed change")
	}
	err = nil
	if !svc.refreshFallbackRouting("backup", true, apply) || calls != 2 || hooks != 1 || svc.clients.fallbackSignature != "backup" {
		t.Fatal("successful retry did not commit new selection")
	}
	if svc.refreshFallbackRouting("backup", true, apply) || calls != 2 || hooks != 1 {
		t.Fatal("unchanged fallback repeated policy rebuild")
	}
	if svc.refreshFallbackRouting("", false, apply) || hooks != 1 || svc.clients.fallbackSignatureSeen {
		t.Fatal("removing all backups retained stale signature")
	}
	if svc.refreshFallbackRouting("new", true, apply) || calls != 2 || hooks != 1 {
		t.Fatal("new baseline rebuilt policy")
	}
}

func TestFallbackSelectionHookRunsAfterPolicyAndOutsideLifecycleLock(t *testing.T) {
	svc := new(Service)
	installed := false
	hooks := 0
	svc.SetClientRecoveryHook(func() {
		hooks++
		if !installed || svc.clients.fallbackSignature != "backup" {
			t.Fatal("route hook ran before the new policy was committed")
		}
		if !svc.clients.ops.TryLock() {
			t.Fatal("route hook held the lifecycle lock")
		}
		svc.clients.ops.Unlock()
	})
	svc.refreshFallbackRouting("primary", true, func() error { t.Fatal("baseline applied"); return nil })
	if !svc.refreshFallbackRouting("backup", true, func() error { installed = true; return nil }) || hooks != 1 {
		t.Fatal("successful fallback did not notify the route owner once")
	}
}

func TestLogicalFallbackSignatureTracksProxyOnlyConnection(t *testing.T) {
	svc, driver, entries := failoverTestService(t)
	primary, backup := entries[0].Manager, entries[1].Manager
	setTestFailover(t, primary, false, entries[1].ID)
	for _, srv := range entries {
		cfg := srv.Manager.Config()
		cfg.Routing.Mode, cfg.Routing.Active, cfg.Routing.Zones = "off", false, nil
		if err := srv.Manager.SetConfig(&cfg); err != nil {
			t.Fatal(err)
		}
	}
	driver.states[primary] = ClientStatus{Running: true, Connected: true}
	driver.states[backup] = ClientStatus{Running: true, Connected: true}
	first, has := svc.fallbackRoutingSignature()
	if !has || first == "" {
		t.Fatal("proxy-only fallback was absent from the selector signature")
	}
	driver.states[primary] = ClientStatus{Running: true}
	second, has := svc.fallbackRoutingSignature()
	if !has || second == first {
		t.Fatal("already-connected reserve did not change the logical selector")
	}
	driver.states[backup] = ClientStatus{Running: true}
	allDown, has := svc.fallbackRoutingSignature()
	if !has || allDown == second || allDown == first {
		t.Fatal("losing all peers did not invalidate the proxy host route")
	}
	driver.states[primary] = ClientStatus{Running: true, Connected: true}
	restored, has := svc.fallbackRoutingSignature()
	if !has || restored != first {
		t.Fatal("primary recovery did not restore the original logical selector")
	}
}
