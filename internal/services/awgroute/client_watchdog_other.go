//go:build !linux

package awgroute

import "nfqws2strategy/internal/services/awg"

func awgClientCurrentEngineOS(cfg awg.ServerConfig) bool { return true }

func clientSupervisorSupported() bool                               { return false }
func (svc *Service) awgProbeClientOS(am *awg.Manager) error         { return svc.awgClientUpManagerOS(am) }
func (svc *Service) awgRecoverClientOS(am *awg.Manager) error       { return svc.awgClientUpManagerOS(am) }
func (svc *Service) awgRestoreClientRoutesOS(am *awg.Manager) error { return nil }
