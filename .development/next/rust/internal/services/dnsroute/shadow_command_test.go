package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestShadowNativeCommandErrorReportsKnownZeroExitFailure(t *testing.T) {
	output := "[C] Oct 4 00:39:03 ndm: ndmc: system failed [0xcffd0062].\nndmc: initialization failure.\n"
	for _, commandErr := range []error{nil, errors.New("exit status 1")} {
		err := shadowNativeCommandError(context.Background(), "show ip name-server", output, commandErr)
		if err == nil || !strings.Contains(err.Error(), "initialization failure") || !strings.Contains(err.Error(), "show ip name-server") {
			t.Fatalf("did not report native initialization failure: %v", err)
		}
	}
	if err := shadowNativeCommandError(context.Background(), "show log", "ndmc: system failed [0xcffd0062].", nil); err == nil {
		t.Fatal("standalone native failure accepted with exit 0")
	}
}

func TestShadowNativeCommandErrorDoesNotLeakCommandOutput(t *testing.T) {
	private := strings.Repeat("router-private-details\x1b[31m", 10000)
	err := shadowNativeCommandError(context.Background(), "show log", private, fmt.Errorf("execution failed: %s", private))
	if err == nil || len(err.Error()) > 400 || strings.Contains(err.Error(), "router-private-details") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("unsafe native diagnostics: %.500s", err)
	}
}

func TestShadowNativeCommandErrorAllowsEmptyAndHistoricalOutput(t *testing.T) {
	for _, output := range []string{"", "I [Oct 4 00:39:03] ndm: ndmc: initialization failure.\nW [Oct 4 00:40:00] ndm: Dns::InterfaceSpecific: name server 192.0.2.53 is ignored.", "[C] Oct 4 00:39:03 ndm: ndmc: system failed [0xcffd0062]."} {
		if err := shadowNativeCommandError(context.Background(), "show log", output, nil); err != nil {
			t.Fatalf("successful native output rejected: %v", err)
		}
	}
}

func TestShadowNativeCommandErrorPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := shadowNativeCommandError(ctx, "show log", "ndmc: initialization failure.", errors.New("signal: killed")); err != context.Canceled {
		t.Fatalf("canceled caller replaced by native failure: %v", err)
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := shadowNativeCommandError(context.Background(), "show log", "", fmt.Errorf("run command: %w", cause))
		if !errors.Is(err, cause) {
			t.Fatalf("lost cancellation cause: %v", err)
		}
	}
}
