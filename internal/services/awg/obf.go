package awg

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// DefaultObf returns the baseline obfuscation (vanilla-equivalent headers). Call
// RandomizeObf once at server-key generation to make the server actually
// AmneziaWG-2.0-obfuscated (random headers/paddings).
func DefaultObf() Obfuscation {
	return Obfuscation{Jc: 4, Jmin: 8, Jmax: 80, H1: "1", H2: "2", H3: "3", H4: "4"}
}

func (o *Obfuscation) normalize() {
	if o.H1 == "" {
		o.H1 = "1"
	}
	if o.H2 == "" {
		o.H2 = "2"
	}
	if o.H3 == "" {
		o.H3 = "3"
	}
	if o.H4 == "" {
		o.H4 = "4"
	}
	if o.Jc == 0 && o.Jmin == 0 && o.Jmax == 0 {
		o.Jc, o.Jmin, o.Jmax = 4, 8, 80
	}
}

// Validate returns Russian-language problems with the obfuscation params.
func (o Obfuscation) Validate() []string {
	var errs []string
	if o.Jc < 0 || o.Jc > 128 {
		errs = append(errs, "Jc вне диапазона 0–128")
	}
	if o.Jmin < 0 || o.Jmax < 0 || o.Jmin > o.Jmax {
		errs = append(errs, "требуется 0 ≤ Jmin ≤ Jmax")
	}
	if o.Jmax > 1280 {
		errs = append(errs, "Jmax слишком большой (>1280)")
	}
	for _, s := range []struct {
		n string
		v int
	}{{"S1", o.S1}, {"S2", o.S2}, {"S3", o.S3}, {"S4", o.S4}} {
		if s.v < 0 || s.v > 1280 {
			errs = append(errs, s.n+" вне диапазона 0–1280")
		}
	}
	for _, h := range []struct {
		n string
		v string
	}{{"H1", o.H1}, {"H2", o.H2}, {"H3", o.H3}, {"H4", o.H4}} {
		if !validHeader(h.v) {
			errs = append(errs, h.n+": ожидается число или диапазон x-y")
		}
	}
	for _, ip := range []struct {
		n string
		v string
	}{{"I1", o.I1}, {"I2", o.I2}, {"I3", o.I3}, {"I4", o.I4}, {"I5", o.I5}} {
		if strings.TrimSpace(ip.v) == "" {
			continue
		}
		if err := validateCPS(ip.v); err != nil {
			errs = append(errs, ip.n+": "+err.Error())
		}
	}
	return errs
}

func validHeader(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		a, err1 := parseU32(strings.TrimSpace(s[:i]))
		b, err2 := parseU32(strings.TrimSpace(s[i+1:]))
		return err1 == nil && err2 == nil && a <= b
	}
	_, err := parseU32(s)
	return err == nil
}

func parseU32(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	base := 10
	if len(s) > 2 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 32)
	return uint32(v), err
}

var cpsTokenRe = regexp.MustCompile(`^<\s*(?:b\s+0x[0-9a-fA-F]+|r\s+\d+|rc\s+\d+|rd\s+\d+|t)\s*>`)

// validateCPS checks an I-packet against the AmneziaWG CPS tag DSL:
// <b 0xHEX> | <r N> | <rc N> | <rd N> | <t>, concatenated.
func validateCPS(s string) error {
	rest := strings.TrimSpace(s)
	if rest == "" {
		return fmt.Errorf("пусто")
	}
	for len(rest) > 0 {
		m := cpsTokenRe.FindString(rest)
		if m == "" {
			return fmt.Errorf("неверный тег рядом с %q", trunc(rest, 14))
		}
		if idx := strings.Index(m, "0x"); idx >= 0 {
			hex := strings.TrimRight(m[idx+2:], " >")
			if len(hex)%2 != 0 {
				return fmt.Errorf("в <b 0x..> нужно чётное число hex-символов")
			}
		}
		rest = strings.TrimSpace(rest[len(m):])
	}
	return nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RandomizeObf fills the obfuscation with random AmneziaWG 2.0 values (distinct
// 32-bit headers, modest paddings). Called once when server keys are generated.
func RandomizeObf(o *Obfuscation) error {
	var err error
	if o.Jc, err = randInt(3, 10); err != nil {
		return err
	}
	if o.Jmin, err = randInt(8, 64); err != nil {
		return err
	}
	if o.Jmax, err = randInt(o.Jmin+24, o.Jmin+200); err != nil {
		return err
	}
	if o.S1, err = randInt(15, 150); err != nil {
		return err
	}
	if o.S2, err = randInt(15, 150); err != nil {
		return err
	}
	for o.S1+56 == o.S2 {
		o.S2++
	}
	o.S3, o.S4 = 0, 0
	used := map[uint32]bool{}
	for _, h := range []*string{&o.H1, &o.H2, &o.H3, &o.H4} {
		for {
			v, e := randU32(0x10000011, 0x7FFFFF00)
			if e != nil {
				return e
			}
			if !used[v] {
				used[v] = true
				*h = strconv.FormatUint(uint64(v), 10)
				break
			}
		}
	}
	return nil
}

func randInt(min, max int) (int, error) {
	if max <= min {
		return min, nil
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func randU32(min, max uint32) (uint32, error) {
	if max <= min {
		return min, nil
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return 0, err
	}
	return min + uint32(n.Int64()), nil
}
