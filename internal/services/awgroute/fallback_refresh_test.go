package awgroute

import (
	"errors"
	"testing"
)

func TestFallbackChangeRetriesAfterBusyOrFailedApply(t *testing.T) {
	svc := new(Service)
	calls := 0
	err := errors.New("kernel apply failed")
	apply := func() error { calls++; return err }
	if svc.refreshFallbackRouting("primary", true, apply) || calls != 0 {
		t.Fatal("baseline caused startup churn")
	}
	_, unlock := svc.lockClientOps(false)
	if svc.refreshFallbackRouting("backup", true, apply) || calls != 0 {
		t.Fatal("busy lifecycle applied policy")
	}
	unlock()
	if svc.clients.fallbackSignature != "primary" {
		t.Fatal("busy lifecycle consumed pending fallback change")
	}
	if svc.refreshFallbackRouting("backup", true, apply) || calls != 1 || svc.clients.fallbackSignature != "primary" {
		t.Fatal("failed apply consumed change")
	}
	err = nil
	if !svc.refreshFallbackRouting("backup", true, apply) || calls != 2 || svc.clients.fallbackSignature != "backup" {
		t.Fatal("successful retry did not commit new selection")
	}
	if svc.refreshFallbackRouting("backup", true, apply) || calls != 2 {
		t.Fatal("unchanged fallback repeated policy rebuild")
	}
	if svc.refreshFallbackRouting("", false, apply) || svc.clients.fallbackSignatureSeen {
		t.Fatal("removing all backups retained stale signature")
	}
	if svc.refreshFallbackRouting("new", true, apply) || calls != 2 {
		t.Fatal("new baseline rebuilt policy")
	}
}
