package nfqws2

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEngineUserLiteralDoesNotEvaluateShell(t *testing.T) {
	for _, tt := range []struct{ conf, want string }{
		{"USER=nobody\n", "nobody"}, {"# USER=root\n USER = 'nfqws-user' # comment\n", "nfqws-user"}, {"USER=nobody\nexport\tUSER=65534:65534\n", "65534:65534"}, {"USER=\"nobody\"\r\n", "nobody"}, {"OTHER_USER=root\n", ""},
	} {
		got, err := engineUserLiteral([]byte(tt.conf))
		if err != nil || got != tt.want {
			t.Errorf("%q: %q %v", tt.conf, got, err)
		}
	}
	for _, conf := range []string{"USER=$(id)", "USER=`id`", "USER=${WHO:-nobody}", "USER=nobody;id", "USER='nobody' && id", "USER=\"${WHO}\"", "USER='unterminated"} {
		if _, err := engineUserLiteral([]byte(conf)); err == nil {
			t.Errorf("accepted shell expression %q", conf)
		}
	}
}

func TestAutolistOwnerLookupUsesConfiguredAccount(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/:/bin/sh\nnobody:x:65534:65533::/:/bin/false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nobody", "65534"} {
		owner, err := lookupAssetOwner(name, []string{filepath.Join(dir, "missing"), passwd})
		if err != nil || owner.uid != 65534 || owner.gid != 65533 {
			t.Fatalf("%s: %+v %v", name, owner, err)
		}
	}
	owner, err := lookupAssetOwner("1000:1001", nil)
	if err != nil || owner.uid != 1000 || owner.gid != 1001 {
		t.Fatalf("explicit ids: %+v %v", owner, err)
	}
	if _, err = lookupAssetOwner("missing-user", []string{passwd}); err == nil {
		t.Fatal("missing account was guessed")
	}
}
