package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"nfqws2strategy/internal/services/nfqws2"
)

func (s *Server) serviceStrategiesRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/nfqws2/service-strategies", s.getServiceStrategies)
	m.HandleFunc("POST /api/nfqws2/service-strategies", s.saveServiceStrategies)
	m.HandleFunc("POST /api/nfqws2/service-strategies/preview", s.previewServiceStrategies)
	m.HandleFunc("POST /api/nfqws2/service-strategies/check", s.checkServiceDomains)
}

func serviceStrategiesError(w http.ResponseWriter, err error) {
	if errors.Is(err, nfqws2.ErrServiceStrategiesChanged) {
		httpErr(w, http.StatusConflict, err)
		return
	}
	assetHTTPError(w, err)
}

func (s *Server) getServiceStrategies(w http.ResponseWriter, r *http.Request) {
	state, err := s.app.Nfqws2ServiceStrategies()
	if err != nil {
		serviceStrategiesError(w, err)
		return
	}
	writeJSON(w, 200, state)
}

type serviceStrategiesInput struct {
	Services []nfqws2.ServiceStrategy `json:"services"`
	Revision string                   `json:"revision"`
}

func (s *Server) saveServiceStrategies(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var in serviceStrategiesInput
	if err := readJSON(r, &in); err != nil {
		serviceStrategiesError(w, err)
		return
	}
	state, err := s.app.SaveNfqws2ServiceStrategies(in.Services, in.Revision)
	if err != nil {
		serviceStrategiesError(w, err)
		return
	}
	writeJSON(w, 200, state)
}

func (s *Server) previewServiceStrategies(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var in serviceStrategiesInput
	if err := readJSON(r, &in); err != nil {
		serviceStrategiesError(w, err)
		return
	}
	preview, err := s.app.PreviewNfqws2ServiceStrategies(in.Services)
	if err != nil {
		serviceStrategiesError(w, err)
		return
	}
	writeJSON(w, 200, preview)
}

type serviceDomainCheck struct {
	Domain string `json:"domain"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Ms     int64  `json:"ms"`
}

func normalizeServiceCheckDomains(domains []string) ([]string, error) {
	if len(domains) == 0 || len(domains) > 64 {
		return nil, fmt.Errorf("проверка принимает от 1 до 64 доменов")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, domain := range domains {
		normalized, err := nfqws2.NormalizeServiceDomain(domain)
		if err != nil {
			return nil, err
		}
		if !seen[normalized] {
			seen[normalized] = true
			out = append(out, normalized)
		}
	}
	return out, nil
}

// Check real HTTPS reachability through the current router configuration. It
// neither launches a sandbox nor claims to exercise UDP/game traffic or drafts.
func checkServiceDomain(ctx context.Context, client *http.Client, domain string) serviceDomainCheck {
	result := serviceDomainCheck{Domain: domain}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/", nil)
	if err == nil {
		req.Header.Set("User-Agent", "nfqws2-strategy/service-check")
		var response *http.Response
		response, err = client.Do(req)
		if err == nil {
			_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			result.OK = err == nil
			result.Detail = fmt.Sprintf("HTTPS: HTTP %d", response.StatusCode)
		}
	}
	if err != nil {
		result.Detail = err.Error()
	}
	result.Ms = time.Since(start).Milliseconds()
	return result
}

func (s *Server) checkServiceDomains(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var in struct {
		Domains []string `json:"domains"`
	}
	if err := readJSON(r, &in); err != nil {
		serviceStrategiesError(w, err)
		return
	}
	domains, err := normalizeServiceCheckDomains(in.Domains)
	if err != nil {
		serviceStrategiesError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 6 * time.Second, ResponseHeaderTimeout: 8 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	results := make([]serviceDomainCheck, len(domains))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = checkServiceDomain(ctx, client, domains[i])
			}
		}()
	}
	for i := range domains {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	writeJSON(w, 200, map[string]any{"results": results})
}
