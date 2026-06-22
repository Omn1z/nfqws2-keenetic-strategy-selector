//go:build !linux

package awgroute

func (svc *Service) awgApplyMultiHostRoutesOS()   {}
func (svc *Service) awgClearMultiHostRoutesOS()   {}
func (svc *Service) awgApplyMultiPolicyOS() error { return nil }
func (svc *Service) awgClearMultiPolicyOS()       {}
