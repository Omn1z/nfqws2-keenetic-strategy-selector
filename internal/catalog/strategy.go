package catalog

import "strings"

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
