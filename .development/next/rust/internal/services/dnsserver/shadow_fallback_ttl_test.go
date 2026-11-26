package dnsserver

import (
	"crypto"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestShadowFallbackTTLBoundsCachesWithoutChangingSignedData(t *testing.T) {
	key := &mdns.DNSKEY{Hdr: mdns.RR_Header{Name: "example.ru.", Rrtype: mdns.TypeDNSKEY, Class: mdns.ClassINET, Ttl: 3600}, Flags: 256, Protocol: 3, Algorithm: mdns.ED25519}
	private, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	for _, negative := range []bool{false, true} {
		name := "positive"
		if negative {
			name = "negative"
		}
		t.Run(name, func(t *testing.T) {
			q := new(mdns.Msg)
			q.SetQuestion("example.ru.", mdns.TypeA)
			answer := resolverAnswer(q, 3600)
			set := answer.Answer
			if negative {
				answer = cacheNegativeAnswer(q, mdns.RcodeNameError, 3600, 600)
				answer.Ns[0].Header().Name = q.Question[0].Name
				set = answer.Ns
			}
			now := uint32(time.Now().Unix())
			sig := &mdns.RRSIG{Hdr: mdns.RR_Header{Name: key.Hdr.Name, Rrtype: mdns.TypeRRSIG, Class: mdns.ClassINET, Ttl: 3600}, Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: key.Hdr.Name, Inception: now - 60, Expiration: now + 3600}
			if err := sig.Sign(private.(crypto.Signer), set); err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify(key, set); err != nil {
				t.Fatalf("invalid test signature: %v", err)
			}
			if negative {
				answer.Ns = append(answer.Ns, sig)
			} else {
				answer.Answer = append(answer.Answer, sig)
			}
			answer.SetEdns0(4096, true)
			optBefore := answer.IsEdns0().String()
			clipShadowFallbackTTL(answer)
			if err := sig.Verify(key, set); err != nil {
				t.Fatalf("clipping invalidated DNSSEC signature: %v", err)
			}
			if answer.IsEdns0().String() != optBefore || sig.OrigTtl != 3600 {
				t.Fatal("changed EDNS or signature metadata")
			}
			if negative && set[0].(*mdns.SOA).Minttl != 600 {
				t.Fatal("changed signed SOA RDATA")
			}
			if ttl, isNegative := dnsCacheLifetime(answer, 3600); ttl != 30 || isNegative != negative {
				t.Fatalf("cache lifetime=%d negative=%v", ttl, isNegative)
			}
			// A shorter TTL must never be inflated by fallback clipping.
			set[0].Header().Ttl = 5
			clipShadowFallbackTTL(answer)
			if ttl, _ := dnsCacheLifetime(answer, 3600); ttl != 5 {
				t.Fatalf("extended short upstream TTL: %d", ttl)
			}
		})
	}
}
