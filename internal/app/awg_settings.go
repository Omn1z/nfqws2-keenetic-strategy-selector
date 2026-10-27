package app

import "nfqws2strategy/internal/services/awgroute"

func (a *App) AWG2SetRecoverySettings(settings awgroute.RecoverySettings) error {
	return a.awgroute.AWG2SetRecoverySettings(settings)
}
