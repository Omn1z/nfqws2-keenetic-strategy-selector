//go:build !linux

package awgroute

import (
	"context"
	"fmt"

	"nfqws2strategy/internal/services/awg"
)

func probeConnectionDataOS(context.Context, string) (string, error) {
	return "", fmt.Errorf("проверка AWG доступна только на роутере Linux")
}

func (svc *Service) awgClientDownManagerContextOS(_ context.Context, am *awg.Manager) error {
	return svc.awgClientDownManagerOS(am)
}
