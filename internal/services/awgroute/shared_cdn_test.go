package awgroute

import "testing"

func TestSharedCDNProvider(t *testing.T) {
	cases := []struct {
		ip       string
		provider string
		shared   bool
	}{
		{"104.16.1.1", "Cloudflare", true},
		{"172.67.1.1", "Cloudflare", true},
		{"2606:4700::1", "Cloudflare", true},
		{"8.8.8.8", "", false},
		{"not-an-ip", "", false},
	}
	for _, c := range cases {
		provider, shared := sharedCDNProvider(c.ip)
		if shared != c.shared || provider != c.provider {
			t.Errorf("sharedCDNProvider(%q) = (%q, %v), want (%q, %v)", c.ip, provider, shared, c.provider, c.shared)
		}
	}
}
