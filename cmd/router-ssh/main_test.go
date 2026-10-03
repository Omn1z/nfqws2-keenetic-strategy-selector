package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestConnectionCredentialsMustBeExplicit(t *testing.T) {
	t.Setenv("ROUTER_HOST", "")
	t.Setenv("ROUTER_PASS", "")
	t.Setenv("ROUTER_PORT", "")
	t.Setenv("ROUTER_USER", "")
	g, _, _, err := parseGlobal([]string{"exec", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if g.host != "" || g.password != "" || g.port != 222 || g.user != "root" {
		t.Fatal("unexpected connection defaults")
	}
	// These must fail validation without attempting any network connection.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"exec", "true"}, "router host is required"},
		{[]string{"--host", "127.0.0.1", "exec", "true"}, "router password is required"},
		{[]string{"--host", " ", "--password", "test-only-secret", "exec", "true"}, "router host is required"},
	} {
		if err := runMain(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected credential validation error %q", tc.want)
		}
	}
}

func TestCredentialEnvironmentAndFlagPrecedence(t *testing.T) {
	t.Setenv("ROUTER_HOST", "router.example")
	t.Setenv("ROUTER_PASS", " test-only-env-secret ")
	g, _, _, err := parseGlobal([]string{"diagnose"})
	if err != nil || g.host != "router.example" || g.password != " test-only-env-secret " {
		t.Fatal("environment credentials were not preserved")
	}
	g, _, _, err = parseGlobal([]string{"--host", "override.example", "--password", "test-only-flag-secret", "diagnose"})
	if err != nil || g.host != "override.example" || g.password != "test-only-flag-secret" {
		t.Fatal("explicit flags did not override environment credentials")
	}
	var usage bytes.Buffer
	printUsage(&usage)
	if strings.Contains(usage.String(), "test-only-env-secret") || strings.Contains(usage.String(), "test-only-flag-secret") {
		t.Fatal("usage revealed a password")
	}
	if !strings.Contains(usage.String(), "<host>") || !strings.Contains(usage.String(), "<password>") {
		t.Fatal("usage should show placeholders")
	}
}
