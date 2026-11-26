//go:build !linux

package awgroute

func awgDNSRunningOS(string) bool { return false }
