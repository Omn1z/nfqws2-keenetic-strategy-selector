package dnsserver

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	mdns "github.com/miekg/dns"
	"nfqws2strategy/internal/services/openwrtdns"
)

type openWrtDNSManager interface {
	Status(context.Context) (openwrtdns.State, error)
	Apply(context.Context, string, string, openwrtdns.Endpoint, string) error
	Restore(context.Context, string) error
	CurrentBinding() (*openwrtdns.Binding, error)
}

func (s *Service) OpenWrtDNSStatus(ctx context.Context) (openwrtdns.State, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.openwrt.Status(ctx)
}

// Configuration changes share the service lifecycle lock. Closing a browser
// after writes begin cannot interrupt commit/rollback halfway through.
func (s *Service) ApplyOpenWrtDNS(ctx context.Context, iface, instance, revision string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := s.openwrt.Status(ctx)
	if err != nil {
		return err
	}
	if !state.Supported {
		return fmt.Errorf("автонастройка DNS доступна только на OpenWrt")
	}
	s.mu.RLock()
	running, host, port := s.active != nil, s.host, s.cfg.DNSPort
	s.mu.RUnlock()
	if !running {
		return fmt.Errorf("сначала включите DNS Server и дождитесь успешного запуска")
	}
	if port == 53 {
		return fmt.Errorf("для пересылки из dnsmasq выберите отдельный порт DNS Server, например 5356")
	}
	endpoint := openwrtdns.Endpoint{Host: host, Port: port}
	if err := checkOpenWrtDNSListener(ctx, endpoint); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transaction, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	return s.openwrt.Apply(transaction, iface, instance, endpoint, revision)
}

func (s *Service) RestoreOpenWrtDNS(ctx context.Context, revision string) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	transaction, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	return s.openwrt.Restore(transaction, revision)
}

func checkOpenWrtDNSListener(ctx context.Context, endpoint openwrtdns.Endpoint) error {
	address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	for _, transport := range []string{"udp", "tcp"} {
		question := new(mdns.Msg)
		question.SetQuestion("example.com.", mdns.TypeA)
		client := mdns.Client{Net: transport, Timeout: 4 * time.Second}
		conn, err := client.DialContext(ctx, address)
		if err != nil {
			return fmt.Errorf("DNS Server не ответил на проверку %s: %w", transport, err)
		}
		// ExchangeContext only forwards the context's deadline to the socket;
		// cancellation after dialing must also interrupt an outstanding read.
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		answer, _, err := client.ExchangeWithConnContext(ctx, question, conn)
		stop()
		_ = conn.Close()
		if ctx.Err() != nil {
			return fmt.Errorf("DNS Server не ответил на проверку %s: %w", transport, ctx.Err())
		}
		if err != nil {
			return fmt.Errorf("DNS Server не ответил на проверку %s: %w", transport, err)
		}
		if answer == nil || (answer.Rcode != mdns.RcodeSuccess && answer.Rcode != mdns.RcodeNameError) {
			return fmt.Errorf("DNS Server вернул ошибку проверки %s; сначала проверьте его DNS-маршруты", transport)
		}
	}
	return nil
}

// Disable/port/import changes must not leave dnsmasq aimed at a closed socket.
// A normal restart of the same endpoint keeps its persistent binding. A changed
// endpoint first returns OpenWrt to its original DNS; the UI can apply it again.
const openWrtRestoreNotice = "Прежний DNS OpenWrt уже восстановлен; после проверки настроек нажмите «Подключить DNS Server» повторно."

func (s *Service) reconcileOpenWrtDNSLocked(cfg Config, host string) (bool, error) {
	if s.openwrt == nil {
		return false, nil
	}
	binding, err := s.openwrt.CurrentBinding()
	if err != nil {
		return false, fmt.Errorf("проверка привязки DNS OpenWrt: %w", err)
	}
	if binding == nil || cfg.Enabled && binding.Endpoint.Host == host && binding.Endpoint.Port == cfg.DNSPort {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := s.openwrt.Restore(ctx, ""); err != nil {
		return false, fmt.Errorf("сначала восстановите DNS OpenWrt перед отключением или сменой адреса DNS Server: %w", err)
	}
	s.logs.Append(LogEntry{Level: "info", Event: "openwrt", Message: "Прежний DNS OpenWrt восстановлен перед отключением или сменой адреса DNS Server. Для нового адреса доступно повторное применение."})
	return true, nil
}
