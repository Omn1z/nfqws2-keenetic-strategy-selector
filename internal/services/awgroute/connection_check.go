package awgroute

import (
	"context"
	"strings"
	"time"

	"nfqws2strategy/internal/services/awg"
)

// ConnectionTestResult distinguishes an authenticated peer from a working
// Internet path. Interface creation alone is never reported as success.
type ConnectionTestResult struct {
	ServerID  string `json:"server_id"`
	Success   bool   `json:"success"`
	Handshake bool   `json:"handshake"`
	DataOK    bool   `json:"data_ok"`
	LatencyMS int64  `json:"latency_ms"`
	Endpoint  string `json:"endpoint"`
	EgressIP  string `json:"egress_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt int64  `json:"checked_at"`
}

type connectionTestDriver interface {
	status(*awg.Manager) *ClientStatus
	up(*awg.Manager) error
	down(*awg.Manager) error
	probe(*awg.Manager) error
	data(context.Context, string) (string, error)
}

type systemConnectionTestDriver struct{ svc *Service }

func (d systemConnectionTestDriver) status(am *awg.Manager) *ClientStatus {
	return d.svc.awgClientStatusManagerOS(am)
}
func (d systemConnectionTestDriver) up(am *awg.Manager) error {
	return d.svc.awgClientUpManagerOS(am)
}
func (d systemConnectionTestDriver) down(am *awg.Manager) error {
	// Request cancellation must not strand a temporarily started reserve.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.svc.awgClientDownManagerContextOS(ctx, am)
}
func (d systemConnectionTestDriver) probe(am *awg.Manager) error {
	return d.svc.awgProbeClientOS(am)
}
func (d systemConnectionTestDriver) data(ctx context.Context, iface string) (string, error) {
	return probeConnectionDataOS(ctx, iface)
}

// AWG2TestConnection serializes with recovery and manual down/delete operations.
// It tests the requested ID, never the currently selected editing profile.
func (svc *Service) AWG2TestConnection(parent context.Context, id string) ConnectionTestResult {
	opCtx, unlock := svc.lockClientOps(false)
	defer unlock()
	ctx, cancel := context.WithTimeout(opCtx, 45*time.Second)
	defer cancel()
	// Capture this operation's cancel function: a late HTTP cancellation must
	// not cancel a subsequent operation after the lifecycle lock is released.
	svc.clients.mu.Lock()
	cancelOperation := svc.clients.cancel
	svc.clients.mu.Unlock()
	stop := context.AfterFunc(parent, cancelOperation)
	defer stop()
	if err := parent.Err(); err != nil {
		return ConnectionTestResult{ServerID: id, CheckedAt: time.Now().Unix(), Error: err.Error()}
	}
	// The lifecycle routines also inherit the total test deadline.
	deadlineStop := context.AfterFunc(ctx, cancelOperation)
	defer deadlineStop()
	return svc.testConnection(ctx, id, systemConnectionTestDriver{svc})
}

// Called with clients.ops held; isolated driver permits cancellation and intent
// regression tests without touching the host's routing or network.
func (svc *Service) testConnection(ctx context.Context, id string, driver connectionTestDriver) (out ConnectionTestResult) {
	id = strings.TrimSpace(id)
	out = ConnectionTestResult{ServerID: id, CheckedAt: time.Now().Unix()}
	svc.mu.RLock()
	srv := svc.servers[id]
	svc.mu.RUnlock()
	if srv == nil {
		out.Error = "AWG-подключение не найдено"
		return out
	}
	am := srv.Manager
	cfg := am.RuntimeConfig()
	out.Endpoint = cfg.Endpoint
	if err := ctx.Err(); err != nil {
		out.Error = err.Error()
		return out
	}
	if !cfg.Enabled || !awgCanStartLocalClient(cfg) {
		out.Error = "включите подключение и сохраните рабочий профиль перед проверкой"
		return out
	}
	before := driver.status(am)
	if before == nil {
		out.Error = "проверка AWG доступна только на роутере Linux"
		return out
	}
	if !before.Running {
		defer func() {
			if err := driver.down(am); err != nil {
				out.Success = false
				if out.Error != "" {
					out.Error += "; "
				}
				out.Error += "не удалось остановить временный туннель: " + err.Error()
			}
		}()
		if err := driver.up(am); err != nil {
			out.Error = err.Error()
			return out
		}
	}
	if err := driver.probe(am); err != nil {
		out.Error = err.Error()
		return out
	}
	start := time.Now()
	egressIP, errData := driver.data(ctx, awgClientIfaceName(cfg))
	out.EgressIP = egressIP
	out.LatencyMS = time.Since(start).Milliseconds()
	out.DataOK = errData == nil
	if after := driver.status(am); after != nil {
		out.Handshake = after.Running && after.LastHandshake > 0 &&
			(after.Connected || after.RxBytes > before.RxBytes || after.LastHandshake > before.LastHandshake)
		if after.Endpoint != "" {
			out.Endpoint = after.Endpoint
		}
	}
	out.Success = out.Handshake && out.DataOK
	if errData != nil {
		out.Error = errData.Error()
	} else if !out.Handshake {
		out.Error = "HTTPS ответил, но подтверждённый handshake AWG не найден"
	}
	return out
}
