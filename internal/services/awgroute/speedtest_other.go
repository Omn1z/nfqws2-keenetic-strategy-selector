//go:build !linux

package awgroute

import "context"

func (svc *Service) RunSpeedTest(_ context.Context, _ SpeedTestOptions) SpeedTestResult {
	return SpeedTestResult{Err: "speedtest: not supported on this platform (linux only)"}
}
