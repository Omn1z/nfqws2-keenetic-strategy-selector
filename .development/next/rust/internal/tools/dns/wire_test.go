package dns

import "testing"

func TestBuildQuery(t *testing.T) {
	q, err := buildQuery("www.google.com")
	if err != nil {
		t.Fatal(err)
	}
	// header(12) + 3www6google3com0(16) + qtype(2) + qclass(2)
	if len(q) != 12+16+4 {
		t.Fatalf("len = %d, want %d", len(q), 12+16+4)
	}
	if q[2] != 0x01 || q[3] != 0x00 { // RD flag
		t.Fatalf("flags = %x %x, want 01 00", q[2], q[3])
	}
	if q[5] != 0x01 { // QDCOUNT low byte
		t.Fatalf("qdcount = %d, want 1", q[5])
	}
	if q[12] != 3 || string(q[13:16]) != "www" {
		t.Fatalf("first label not www: %q", q[13:16])
	}
	qb := q[len(q)-4:]
	if qb[1] != 0x01 || qb[3] != 0x01 {
		t.Fatalf("qtype/qclass not A/IN: %x", qb)
	}
}

func TestBuildQueryBadName(t *testing.T) {
	if _, err := buildQuery(""); err == nil {
		t.Fatal("empty host should error")
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := buildQuery(string(long)); err == nil {
		t.Fatal("64-char label should error")
	}
}

// TestParseA crafts a response with a compressed answer name (pointer to the
// question) carrying one A record, and checks parseA finds the IP.
func TestParseA(t *testing.T) {
	msg := []byte{
		0x12, 0x34, // id
		0x81, 0x80, // flags: response, RD, RA, rcode 0
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// question: example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
		// answer: pointer to offset 12, A IN, ttl, rdlen 4, 93.184.216.34
		0xc0, 0x0c,
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x0e, 0x10, // TTL 3600
		0x00, 0x04, // RDLENGTH
		93, 184, 216, 34,
	}
	ip, err := parseA(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "93.184.216.34" {
		t.Fatalf("ip = %q, want 93.184.216.34", ip)
	}
}

func TestParseANXDomain(t *testing.T) {
	msg := []byte{
		0x00, 0x00,
		0x81, 0x83, // rcode 3 = NXDOMAIN
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err := parseA(msg); err == nil {
		t.Fatal("NXDOMAIN should error")
	}
}

func TestParseANoAnswer(t *testing.T) {
	// A response that only carries the question (no answers).
	msg := []byte{
		0x00, 0x00, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'a', 'b', 'c', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := parseA(msg); err != errNoA {
		t.Fatalf("err = %v, want errNoA", err)
	}
}

func TestDefaultsValid(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Defaults() {
		if seen[s.ID] {
			t.Fatalf("duplicate id %q", s.ID)
		}
		seen[s.ID] = true
		if err := s.Validate(); err != nil {
			t.Fatalf("default %q invalid: %v", s.ID, err)
		}
	}
}
