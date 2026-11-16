//go:build !linux

package awgroute

func (*Service) SuspendAccelerationForNFQWSChange() error { return nil }
func (*Service) ResumeAccelerationAfterNFQWSChange()      {}
