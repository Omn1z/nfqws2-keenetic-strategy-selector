package awgroute

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

type fakeConnectionTest struct {
	statuses                       []*ClientStatus
	upErr                          error
	downErr                        error
	dataErr                        error
	upCalls, downCalls, probeCalls int
	iface                          string
	onData                         func(context.Context)
}

func (d *fakeConnectionTest) status(*awg.Manager) *ClientStatus {
	if len(d.statuses) == 0 {
		return nil
	}
	st := d.statuses[0]
	if len(d.statuses) > 1 {
		d.statuses = d.statuses[1:]
	}
	return st
}
func (d *fakeConnectionTest) up(*awg.Manager) error    { d.upCalls++; return d.upErr }
func (d *fakeConnectionTest) down(*awg.Manager) error  { d.downCalls++; return d.downErr }
func (d *fakeConnectionTest) probe(*awg.Manager) error { d.probeCalls++; return nil }
func (d *fakeConnectionTest) data(ctx context.Context, iface string) (string, error) {
	d.iface = iface
	if d.onData != nil {
		d.onData(ctx)
	}
	return "203.0.113.5", d.dataErr
}

func connectionTestService() (*Service, *awg.Manager) {
	cfg := importedLikeConfig()
	cfg.ClientIface = "awg7"
	am := awg.NewManager(cfg)
	return &Service{activeID: "different", servers: map[string]*managedServer{"reserve": {ID: "reserve", Manager: am}}}, am
}

func TestConnectionCheckRestoresOfflineIntentAndUsesRequestedID(t *testing.T) {
	svc, am := connectionTestService()
	before := am.Config()
	d := &fakeConnectionTest{statuses: []*ClientStatus{{}, {Running: true, Connected: true, LastHandshake: 1}}}
	res := svc.testConnection(context.Background(), "reserve", d)
	if !res.Success || !res.Handshake || !res.DataOK || res.EgressIP != "203.0.113.5" || d.iface != "awg7" {
		t.Fatalf("incorrect test result: %+v, iface=%s", res, d.iface)
	}
	if d.upCalls != 1 || d.downCalls != 1 || svc.activeID != "different" || !reflect.DeepEqual(before, am.Config()) {
		t.Fatal("temporary test changed profile selection or persisted intent, or failed to stop reserve")
	}
}

func TestConnectionCheckDoesNotStopExistingTunnelOrClaimHandshakeOnlySuccess(t *testing.T) {
	svc, _ := connectionTestService()
	d := &fakeConnectionTest{statuses: []*ClientStatus{{Running: true}, {Running: true, Connected: true, LastHandshake: 1}}, dataErr: errors.New("HTTPS timeout")}
	res := svc.testConnection(context.Background(), "reserve", d)
	if res.Success || !res.Handshake || res.DataOK || res.Error != "HTTPS timeout" || d.upCalls != 0 || d.downCalls != 0 {
		t.Fatalf("existing tunnel or partial failure handled incorrectly: %+v / %+v", res, d)
	}
}

func TestConnectionCheckCleansUpFailedStartupAndCanceledData(t *testing.T) {
	svc, _ := connectionTestService()
	d := &fakeConnectionTest{statuses: []*ClientStatus{{}}, upErr: errors.New("startup failed")}
	res := svc.testConnection(context.Background(), "reserve", d)
	if res.Success || res.Error != "startup failed" || d.downCalls != 1 || d.probeCalls != 0 {
		t.Fatalf("startup failure left an interface behind: %+v / %+v", res, d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d = &fakeConnectionTest{statuses: []*ClientStatus{{}, {}}, dataErr: context.Canceled, onData: func(context.Context) { cancel() }}
	res = svc.testConnection(ctx, "reserve", d)
	if res.Success || d.downCalls != 1 || !errors.Is(d.dataErr, context.Canceled) {
		t.Fatalf("cancellation left a temporary reserve running: %+v / %+v", res, d)
	}
}

func TestConnectionCheckReportsCleanupFailureAfterSuccessfulData(t *testing.T) {
	svc, _ := connectionTestService()
	d := &fakeConnectionTest{statuses: []*ClientStatus{{}, {Running: true, Connected: true, LastHandshake: 1}}, downErr: errors.New("interface remains")}
	res := svc.testConnection(context.Background(), "reserve", d)
	if res.Success || !res.Handshake || !res.DataOK || res.Error == "" {
		t.Fatalf("cleanup failure hidden by successful connection test: %+v", res)
	}
}

func TestConnectionCheckRejectsUnknownOrUnsupportedWithoutNetwork(t *testing.T) {
	svc, _ := connectionTestService()
	d := new(fakeConnectionTest)
	for _, id := range []string{"missing", "reserve"} {
		res := svc.testConnection(context.Background(), id, d)
		if res.Success || res.Error == "" || d.upCalls != 0 || d.probeCalls != 0 {
			t.Fatalf("invalid test attempted network access: %+v", res)
		}
	}
}
