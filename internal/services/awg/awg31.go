package awg

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	AWGGoVersion     = "v3.1.20260828"
	AWGGoRevision    = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
	AWGToolsVersion  = "v3.1.20260812"
	AWGToolsRevision = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
)

// KeepaliveValue preserves the existing integer API while supporting AWG 3.1
// ranges and explicit zero. A missing historical value keeps the 25s default.
func (p Peer) KeepaliveValue() string {
	if v := strings.TrimSpace(p.KeepaliveRange); v != "" {
		return wireRange(v, 16)
	}
	if p.Keepalive > 0 {
		return strconv.Itoa(p.Keepalive)
	}
	if p.Keepalive < 0 {
		return strconv.Itoa(p.Keepalive)
	}
	return "25"
}

// PeerKeepaliveValue disables timing obfuscation alongside the traffic toggle.
func (c ServerConfig) PeerKeepaliveValue(p Peer) string {
	if !c.UseObfuscation() && strings.Contains(p.KeepaliveValue(), "-") {
		p.KeepaliveRange = ""
	}
	return p.KeepaliveValue()
}

func (o Obfuscation) hasAWG31() bool {
	return strings.TrimSpace(o.HeaderProtectionKey) != "" || o.HasHeaderProtectionKey ||
		strings.TrimSpace(o.ContentPaddingAddition) != "" || strings.TrimSpace(o.RekeyAfterTime) != "" ||
		strings.TrimSpace(o.RekeyTimeout) != "" || strings.TrimSpace(o.RejectAfterTime) != "" ||
		strings.TrimSpace(o.KeepaliveTimeout) != "" || strings.TrimSpace(o.MaxHandshakeAttempts) != "" ||
		o.RandomTrailers || o.DisableCookies
}

// RequiresAWG31 guards the wire features, even if a profile has stale metadata.
func (c ServerConfig) RequiresAWG31() bool {
	if !c.UseObfuscation() {
		return false
	}
	if c.ProtocolVersion == "3.1" || c.Obf.hasAWG31() {
		return true
	}
	for _, p := range c.Peers {
		if strings.Contains(p.KeepaliveValue(), "-") {
			return true
		}
	}
	return false
}

func (c ServerConfig) EffectiveProtocolVersion() string {
	if c.Protocol == "wireguard" {
		return ""
	}
	if c.RequiresAWG31() {
		return "3.1"
	}
	if c.ProtocolVersion != "" {
		return c.ProtocolVersion
	}
	if v := amneziaProtocolVersion(c.Obf); v != "" {
		return v
	}
	return "1.0"
}

// ConfigureTrafficObfuscation is an explicit self-hosted profile change. It
// preserves WG identities and stored obfuscation when disabled. Enabling an old
// profile with protocol_version=3.1 prepares the current Amnezia Client preset;
// both ends must be redeployed before using the changed wire parameters.
func (c *ServerConfig) ConfigureTrafficObfuscation(enabled bool) error {
	if c.Install == "imported" {
		return fmt.Errorf("обфускацию импортированного сервера задаёт его конфигурация")
	}
	if enabled && c.ProtocolVersion == "3.1" && !c.Obf.hasAWG31() {
		if err := RandomizeObf31(&c.Obf); err != nil {
			return err
		}
		for i := range c.Peers {
			c.Peers[i].KeepaliveRange = "25-35"
		}
	}
	c.Protocol = "awg"
	c.TrafficObfuscation = &enabled
	return nil
}

// RandomizeObf31 follows the official Client 5.0.2.1 installer preset. Equal
// 12-byte prefixes support Header Protection and avoid RandomTrailers packet
// misclassification. ContentPaddingAddition is deliberately opt-in upstream.
func RandomizeObf31(o *Obfuscation) error {
	key, err := GenPSK()
	if err != nil {
		return err
	}
	jc, err := randInt(4, 6)
	if err != nil {
		return err
	}
	*o = Obfuscation{
		Jc: jc, Jmin: 10, Jmax: 50,
		S1: 12, S2: 12, S3: 12, S4: 12,
		H1: "1", H2: "2", H3: "3", H4: "4",
		I1:                  "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
		HeaderProtectionKey: key, HasHeaderProtectionKey: true,
		RekeyAfterTime: "100-120", RekeyTimeout: "3-7", RejectAfterTime: "150-180",
		KeepaliveTimeout: "5-15", MaxHandshakeAttempts: "15-20", RandomTrailers: true, DisableCookies: true,
	}
	return nil
}

func validU16Range(s string) bool {
	_, _, ok := numericRange(s, 16)
	return ok
}

func wireRange(s string, bits int) string {
	a, b, ok := numericRange(s, bits)
	if !ok {
		return strings.TrimSpace(s)
	}
	if strings.Contains(s, "-") {
		return strconv.FormatUint(a, 10) + "-" + strconv.FormatUint(b, 10)
	}
	return strconv.FormatUint(a, 10)
}

func numericRange(s string, bits int) (uint64, uint64, bool) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, false
	}
	parse := func(s string) (uint64, error) {
		if bits == 32 {
			v, err := parseU32(s)
			return uint64(v), err
		}
		return strconv.ParseUint(strings.TrimSpace(s), 10, bits)
	}
	a, err := parse(parts[0])
	if err != nil {
		return 0, 0, false
	}
	b := a
	if len(parts) == 2 {
		b, err = parse(parts[1])
	}
	return a, b, err == nil && a <= b
}

// awg31Strings centralizes the exact .conf names; UAPI differs for these keys.
func (o Obfuscation) awg31Strings() []struct{ conf, uapi, value string } {
	return []struct{ conf, uapi, value string }{
		{"ContentPaddingAddition", "content_padding_addition", o.ContentPaddingAddition},
		{"RekeyAfterTime", "rekey_after_time", o.RekeyAfterTime},
		{"RekeyTimeout", "rekey_timeout", o.RekeyTimeout},
		{"RejectAfterTime", "reject_after_time", o.RejectAfterTime},
		{"KeepaliveTimeout", "keepalive_timeout", o.KeepaliveTimeout},
		{"MaxHandshakeAttempts", "max_handshake_attempts", o.MaxHandshakeAttempts},
	}
}
