package catalog

import (
	"fmt"
	"strings"
)

// Strategy is one nfqws2 desync profile under test. ArgLine holds the nfqws2
// arguments for this profile (filters + payload + lua-desync directives), which
// are appended after the shared base args (lua libs + blobs). It must NOT
// contain --new (profiles are separated by the engine when needed).
type Strategy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	L7      string `json:"l7"` // tls | http | quic (informational)
	ArgLine string `json:"args"`
	Source  string `json:"source"` // builtin | custom
}

// Args splits the ArgLine into argv tokens.
func (s Strategy) Args() []string { return strings.Fields(s.ArgLine) }

// Builtin returns the seed catalog of known-good TCP/TLS strategies (and a few
// HTTP/QUIC). These are derived from the shipped nfqws2-keenetic config and
// common zapret2 combinations. Users can add custom strategies on top.
func Builtin() []Strategy {
	return []Strategy{
		{
			ID: "tls-fake-multisplit-google", L7: "tls", Source: "builtin",
			Name: "fake(tls google)+multisplit midsld seqovl",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=10000 " +
				"--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello",
		},
		{
			ID: "tls-fake-ack-multisplit", L7: "tls", Source: "builtin",
			Name: "fake(0x0,ack-66000)+multisplit",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:repeats=2 " +
				"--lua-desync=multisplit:pos=1,midsld",
		},
		{
			ID: "tls-multisplit-sniext", L7: "tls", Source: "builtin",
			Name: "multisplit at sniext+midsld",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=multisplit:pos=1,sniext,midsld",
		},
		{
			ID: "tls-multidisorder-midsld", L7: "tls", Source: "builtin",
			Name: "multidisorder at midsld",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=multidisorder:pos=1,midsld",
		},
		{
			ID: "tls-fake-badsum-multisplit", L7: "tls", Source: "builtin",
			Name: "fake(badsum)+multisplit midsld",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=fake:blob=tls_clienthello:badsum " +
				"--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello",
		},
		{
			ID: "tls-fakedsplit-midsld", L7: "tls", Source: "builtin",
			Name: "fakedsplit midsld seqovl",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=fakedsplit:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello",
		},
		{
			ID: "tls-fake-md5-multisplit", L7: "tls", Source: "builtin",
			Name: "fake(tcp_md5)+multisplit midsld",
			ArgLine: "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
				"--lua-desync=fake:blob=tls_clienthello:tcp_md5 " +
				"--lua-desync=multisplit:pos=1,midsld",
		},
		{
			ID: "http-methodeol", L7: "http", Source: "builtin",
			Name: "http_methodeol badsum",
			ArgLine: "--filter-tcp=80 --filter-l7=http --payload=http_req " +
				"--lua-desync=http_methodeol:badsum",
		},
	}
}

const (
	tlsFilter  = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello "
	httpFilter = "--filter-tcp=80 --filter-l7=http --payload=http_req "
)

// AutoCandidates returns the broad search space used by automatic strategy
// selection. These cover the proven zapret2/winws2 desync combinations (split
// positions, overlap, fakes with badseq/badsum/md5/ttl fooling, disorder) over
// TLS:443 and HTTP:80. They are tested in order; survivors are ranked by speed.
// A candidate that the engine rejects is reported as an error and skipped, so an
// over-broad entry never aborts the run.
func AutoCandidates() []Strategy {
	tls := func(id, name, desync string) Strategy {
		return Strategy{ID: "auto-" + id, Name: name, L7: "tls", Source: "auto", ArgLine: tlsFilter + desync}
	}
	http := func(id, name, desync string) Strategy {
		return Strategy{ID: "auto-" + id, Name: name, L7: "http", Source: "auto", ArgLine: httpFilter + desync}
	}
	return []Strategy{
		// --- plain splits ---
		tls("ms-1", "multisplit pos=1", "--lua-desync=multisplit:pos=1"),
		tls("ms-midsld", "multisplit midsld", "--lua-desync=multisplit:pos=1,midsld"),
		tls("ms-midsld2", "multisplit 2,midsld-2", "--lua-desync=multisplit:pos=2,midsld-2"),
		tls("ms-sniext", "multisplit sniext+1", "--lua-desync=multisplit:pos=1,sniext+1"),
		tls("ms-host", "multisplit host+1", "--lua-desync=multisplit:pos=1,host+1"),
		tls("ms-sld", "multisplit sld+1", "--lua-desync=multisplit:pos=sld+1"),
		// --- splits with seqovl ---
		tls("ms-ovl1", "multisplit midsld seqovl1", "--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
		tls("ms-ovl336", "multisplit midsld seqovl336", "--lua-desync=multisplit:pos=1,midsld:seqovl=336:seqovl_pattern=tls_clienthello"),
		tls("ms-ovl681", "multisplit midsld seqovl681", "--lua-desync=multisplit:pos=1,midsld:seqovl=681:seqovl_pattern=tls_clienthello"),
		// --- disorder ---
		tls("md-midsld", "multidisorder midsld", "--lua-desync=multidisorder:pos=1,midsld"),
		tls("md-sniext", "multidisorder sniext+1", "--lua-desync=multidisorder:pos=1,sniext+1"),
		tls("md-ovl1", "multidisorder midsld seqovl1", "--lua-desync=multidisorder:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
		tls("md-multi", "multidisorder midsld+sniext", "--lua-desync=multidisorder:pos=1,midsld,sniext+1"),
		// --- fakedsplit / fakeddisorder ---
		tls("fds-midsld", "fakedsplit midsld seqovl1", "--lua-desync=fakedsplit:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
		tls("fdd-midsld", "fakeddisorder midsld seqovl1", "--lua-desync=fakeddisorder:pos=midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
		// --- fake + split combos ---
		tls("fake-google-ms", "fake(google sni)+multisplit", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.google.com --lua-desync=multisplit:pos=1,midsld"),
		tls("fake-ack-ms", "fake(0x0,ack-66000)+multisplit", "--lua-desync=fake:blob=0x00000000:tcp_ack=-66000:repeats=2 --lua-desync=multisplit:pos=1,midsld"),
		tls("fake-badsum-ms", "fake(badsum)+multisplit ovl", "--lua-desync=fake:blob=tls_clienthello:badsum --lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello"),
		tls("fake-md5-ms", "fake(tcp_md5)+multisplit", "--lua-desync=fake:blob=tls_clienthello:tcp_md5 --lua-desync=multisplit:pos=1,midsld"),
		tls("fake-rep-md", "fake(rep6,ack)+multidisorder", "--lua-desync=fake:blob=tls_clienthello:repeats=6:tcp_ack=-66000 --lua-desync=multidisorder:pos=1,midsld:tcp_ack=-66000"),
		tls("fake-ttl-ms", "fake(ip_ttl=4)+multisplit", "--lua-desync=fake:blob=tls_clienthello:ip_ttl=4:ip6_ttl=4 --lua-desync=multisplit:pos=1,midsld"),
		tls("fake-autottl-ms", "fake(autottl)+multisplit", "--lua-desync=fake:blob=tls_clienthello:ip_autottl=0,3-20 --lua-desync=multisplit:pos=1,midsld"),
		tls("fake-rep-fds", "fake(rep2)+fakedsplit", "--lua-desync=fake:blob=tls_clienthello:repeats=2 --lua-desync=fakedsplit:pos=midsld"),
		tls("fake-padencap-ms", "fake(padencap)+multisplit sniext", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,padencap --lua-desync=multisplit:pos=1,sniext+1"),
		tls("fake-google", "fake(google sni) only", "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=10000"),
		// --- HTTP:80 ---
		http("methodeol", "http_methodeol badsum", "--lua-desync=http_methodeol:badsum"),
		http("ms-method", "multisplit method+2", "--lua-desync=multisplit:pos=method+2"),
		http("fake-ms", "fake(http_req)+multisplit", "--lua-desync=fake:blob=http_req --lua-desync=multisplit:pos=method+2"),
		http("md-method", "multidisorder method+2,host+1", "--lua-desync=multidisorder:pos=method+2,host+1"),
	}
}

// luaMethods / dpiModes are the desync function names accepted by the zapret2
// engine; used by Validate to catch typos in manually entered strategies.
var luaMethods = map[string]bool{
	"circular": true, "fake": true, "multisplit": true, "multidisorder": true,
	"split": true, "disorder": true, "fakedsplit": true, "fakeddisorder": true,
	"hostfakesplit": true, "http_methodeol": true, "syndata": true, "send": true,
	"pktmod": true, "tamper": true,
}

var dpiModes = map[string]bool{
	"fake": true, "split": true, "split2": true, "disorder": true, "disorder2": true,
	"fakedsplit": true, "fakeddisorder": true, "multisplit": true, "multidisorder": true,
	"syndata": true, "ipfrag2": true, "udplen": true, "tamper": true,
}

// Validate checks a manually entered strategy argument line the way
// nfqws2-keenetic does (it rejects --new, which the engine reserves as the
// profile separator) plus a light structural check of the desync method names,
// so obvious typos are caught before a run. The real syntax authority is the
// nfqws2 binary; this only guards against the common mistakes.
func Validate(argLine string) error {
	argLine = strings.TrimSpace(argLine)
	if argLine == "" {
		return fmt.Errorf("пустые аргументы стратегии")
	}
	tokens := strings.Fields(argLine)
	for _, tok := range tokens {
		switch {
		case tok == "--new" || strings.HasPrefix(tok, "--new="):
			return fmt.Errorf("--new здесь запрещён: стратегия — это один профиль, профили разделяет движок")
		case strings.HasPrefix(tok, "--lua-desync="):
			m := desyncMethod(strings.TrimPrefix(tok, "--lua-desync="))
			if m != "" && !luaMethods[m] {
				return fmt.Errorf("неизвестный метод --lua-desync: %q", m)
			}
		case strings.HasPrefix(tok, "--dpi-desync="):
			for _, m := range strings.Split(strings.TrimPrefix(tok, "--dpi-desync="), ",") {
				m = strings.TrimSpace(m)
				if m != "" && !dpiModes[m] {
					return fmt.Errorf("неизвестный режим --dpi-desync: %q", m)
				}
			}
		case !strings.HasPrefix(tok, "-"):
			return fmt.Errorf("неожиданный токен %q: аргументы пишутся как --флаг=значение", tok)
		}
	}
	return nil
}

// desyncMethod extracts the method name from a --lua-desync value, i.e. the part
// before the first ':' (params follow as key=value pairs).
func desyncMethod(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[:i]
	}
	return v
}
