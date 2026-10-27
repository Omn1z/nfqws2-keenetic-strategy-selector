package awg

import (
	"reflect"
	"testing"
)

func TestSetClientFailoverPolicyPreservesDraftAndClientIdentity(t *testing.T) {
	cfg := Default()
	cfg.Client.Enabled, cfg.Client.PeerID = true, "router-peer"
	manager := NewManager(cfg)
	before := manager.Config()
	ids := []string{"backup"}
	manager.SetClientFailoverPolicy(ids, true)
	ids[0] = "mutated"
	after := manager.Config()
	if after.Client.Enabled != before.Client.Enabled || after.Client.PeerID != before.Client.PeerID || !after.Client.Standby || !reflect.DeepEqual(after.Client.FallbackTunnelIDs, []string{"backup"}) {
		t.Fatal("local failover update changed client identity, intent or exposed the caller's mutable slice")
	}
	after.Client = before.Client
	if !reflect.DeepEqual(after, before) {
		t.Fatal("local failover update validated or changed unrelated draft fields")
	}
}
