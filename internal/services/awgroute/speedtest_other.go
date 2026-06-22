//go:build !linux

package awgroute

import (
	"context"
	"fmt"
)

func (svc *Service) RunSpeedTest(_ context.Context, _ SpeedTestOptions) SpeedTestResult {
	return SpeedTestResult{Err: "speedtest: not supported on this platform (linux only)"}
}

func ValidateSpeedTestURL(_ string) (string, error) {
	return "", fmt.Errorf("speedtest: not supported on this platform")
}
