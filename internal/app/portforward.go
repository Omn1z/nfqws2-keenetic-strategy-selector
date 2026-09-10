package app

import "nfqws2strategy/internal/services/portforward"

type PortForwardView = portforward.View
type PortForwardRule = portforward.Rule

func (a *App) PortForwardingView() PortForwardView {
	return a.portfwd.View()
}

func (a *App) SavePortForwardRule(r PortForwardRule) (PortForwardView, error) {
	if _, err := a.portfwd.SaveRule(r); err != nil {
		return a.portfwd.View(), err
	}
	return a.portfwd.View(), nil
}

func (a *App) SetPortForwardRuleEnabled(id string, enabled bool) (PortForwardView, error) {
	if _, err := a.portfwd.SetEnabled(id, enabled); err != nil {
		return a.portfwd.View(), err
	}
	return a.portfwd.View(), nil
}

func (a *App) DeletePortForwardRule(id string) (PortForwardView, error) {
	if err := a.portfwd.DeleteRule(id); err != nil {
		return a.portfwd.View(), err
	}
	return a.portfwd.View(), nil
}
