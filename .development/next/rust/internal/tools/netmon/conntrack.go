package netmon

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"strings"
)

// ParseConntrack parses /proc/net/nf_conntrack. Malformed lines are skipped so a
// single bad row never aborts the batch.
//
// The hot path here is the bottleneck of every Dashboard tick on a busy router:
// /proc/net/nf_conntrack regularly clears 80 K+ rows, each ~250 bytes. The
// previous strings.Fields-based parser allocated a []string per line plus the
// underlying string copy from sc.Text — totalling 80 K+ allocations per
// Conntrack() call. Byte-level scanning eliminates both: sc.Bytes returns a
// view into the scanner buffer and the tokenizer walks it without copying.
func ParseConntrack(r io.Reader) ([]Conn, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024) // rows are long on Keenetic
	// Preallocate to the typical post-warmup size so we don't spend the first
	// thousand appends on doubling the slice.
	out := make([]Conn, 0, 512)
	for sc.Scan() {
		if c, ok := parseConntrackLineBytes(sc.Bytes()); ok {
			out = append(out, c)
		}
	}
	return out, sc.Err()
}

// parseConntrackLineBytes is the hand-rolled tokenizer. It walks the raw line
// once, advancing a position cursor instead of allocating a fields slice.
//
// Layout is ragged (tcp rows include a STATE word after TTL, udp/icmp don't;
// src/dst/sport/dport/packets/bytes appear once per tuple — original and reply
// — so we de-dup with `seen*` flags).
func parseConntrackLineBytes(line []byte) (Conn, bool) {
	if len(line) == 0 {
		return Conn{}, false
	}
	// nextToken walks past leading whitespace and returns [start, end) of the
	// next space-delimited token. end==start signals EOL; caller does pos = end.
	nextToken := func(pos int) (start, end int) {
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		start = pos
		for pos < len(line) && line[pos] != ' ' {
			pos++
		}
		end = pos
		return
	}

	var c Conn
	pos := 0

	// f[0]: L3 (ipv4 | ipv6)
	s, e := nextToken(pos)
	if e == s {
		return Conn{}, false
	}
	c.L3 = string(line[s:e])
	pos = e
	// f[1]: skip (L3 protocol number)
	_, pos = nextToken(pos)
	// f[2]: Proto
	s, e = nextToken(pos)
	if e == s {
		return Conn{}, false
	}
	c.Proto = string(line[s:e])
	pos = e
	// f[3]: skip (L4 protocol number)
	_, pos = nextToken(pos)
	// f[4]: TTL
	s, e = nextToken(pos)
	if e == s {
		return Conn{}, false
	}
	ttl, ok := parseIntBytes(line[s:e])
	if !ok {
		return Conn{}, false
	}
	c.TTL = ttl
	pos = e

	// f[5]: TCP connection state (only when proto=tcp AND the token isn't a
	// bracket-flag or a key=value pair).
	s, e = nextToken(pos)
	if c.Proto == "tcp" && e > s {
		tok := line[s:e]
		if tok[0] != '[' && bytes.IndexByte(tok, '=') < 0 {
			c.State = string(tok)
			pos = e
			s, e = nextToken(pos) // consume into the first key=value
		}
	}

	// Remaining tokens: brackets, zone words, and key=value pairs. We've already
	// got the first one in (s, e).
	var seenSrc, seenDst, seenSport, seenDport, seenPackets, seenBytes bool
	for {
		if e == s {
			break
		}
		tok := line[s:e]
		pos = e
		if tok[0] == '[' {
			// Bracket flag: short fixed strings. Use byte-equal to avoid
			// allocating a temporary string per token.
			switch {
			case bytes.Equal(tok, bracketAssured):
				c.Assured = true
			case bytes.Equal(tok, bracketUnreplied):
				c.Unreplied = true
			case bytes.Equal(tok, bracketFastNAT):
				c.FastNAT = true
			}
		} else if eq := bytes.IndexByte(tok, '='); eq < 0 {
			// Zone words (Keenetic-specific): one-shot, byte-compared.
			switch {
			case bytes.Equal(tok, zoneSlan):
				c.Zone = "slan"
			case bytes.Equal(tok, zoneSwan):
				c.Zone = "swan"
			}
		} else {
			key := tok[:eq]
			val := tok[eq+1:]
			switch {
			case bytes.Equal(key, keySrc):
				if !seenSrc {
					c.Src, _ = netip.ParseAddr(string(val))
					seenSrc = true
				}
			case bytes.Equal(key, keyDst):
				if !seenDst {
					c.Dst, _ = netip.ParseAddr(string(val))
					seenDst = true
				}
			case bytes.Equal(key, keySport):
				if !seenSport {
					if n, ok := parseIntBytes(val); ok {
						c.SrcPort = n
					}
					seenSport = true
				}
			case bytes.Equal(key, keyDport):
				if !seenDport {
					if n, ok := parseIntBytes(val); ok {
						c.DstPort = n
					}
					seenDport = true
				}
			case bytes.Equal(key, keyPackets):
				if !seenPackets {
					if n, ok := parseInt64Bytes(val); ok {
						c.Packets = n
					}
					seenPackets = true
				}
			case bytes.Equal(key, keyBytes):
				if !seenBytes {
					if n, ok := parseInt64Bytes(val); ok {
						c.Bytes = n
					}
					seenBytes = true
				} else {
					if n, ok := parseInt64Bytes(val); ok {
						c.ReplyBytes = n
					}
				}
			case bytes.Equal(key, keyMAC):
				c.MAC = strings.ToLower(string(val))
			}
		}
		s, e = nextToken(pos)
	}
	return c, true
}

// Package-level byte slices for the hot tokenizer's literal comparisons. These
// are immutable and shared so we don't allocate a temporary []byte on every
// bytes.Equal call.
var (
	bracketAssured   = []byte("[ASSURED]")
	bracketUnreplied = []byte("[UNREPLIED]")
	bracketFastNAT   = []byte("[FASTNAT]")
	zoneSlan         = []byte("slan")
	zoneSwan         = []byte("swan")
	keySrc           = []byte("src")
	keyDst           = []byte("dst")
	keySport         = []byte("sport")
	keyDport         = []byte("dport")
	keyPackets       = []byte("packets")
	keyBytes         = []byte("bytes")
	keyMAC           = []byte("mac")
)

// parseIntBytes parses a decimal []byte into an int without allocating an
// intermediate string. Negative numbers aren't expected in conntrack rows.
func parseIntBytes(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	n := 0
	for _, ch := range b {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	return n, true
}

func parseInt64Bytes(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var n int64
	for _, ch := range b {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int64(ch-'0')
	}
	return n, true
}
