// Package auth verifies a login/password against the router's system account
// databases (like nfqws-keenetic-web) and manages web sessions.
package auth

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/apr1_crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
)

// Account databases to consult, in order. Same set nfqws-keenetic-web uses.
var dbFiles = []string{"/opt/etc/shadow", "/etc/shadow", "/opt/etc/passwd", "/etc/passwd"}

// Verify reports whether user/password matches an account in the system DBs.
func Verify(user, password string) bool {
	for _, f := range dbFiles {
		hash, ok := lookup(f, user)
		if !ok {
			continue
		}
		switch hash {
		case "", "x", "*", "!", "!!":
			continue // password is elsewhere or login disabled
		}
		if verifyHash(password, hash) {
			return true
		}
	}
	return false
}

func lookup(file, user string) (string, bool) {
	f, err := os.Open(file)
	if err != nil {
		return "", false
	}
	defer f.Close()
	prefix := user + ":"
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				return parts[1], true
			}
		}
	}
	return "", false
}

func verifyHash(password, hash string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	c := crypt.NewFromHash(hash)
	if c == nil {
		return false
	}
	return c.Verify(hash, []byte(password)) == nil
}

// Sessions is an in-memory session-token store.
type Sessions struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{m: map[string]time.Time{}, ttl: ttl}
}

func (s *Sessions) New() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[tok] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return tok
}

func (s *Sessions) Valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

func (s *Sessions) Delete(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}
