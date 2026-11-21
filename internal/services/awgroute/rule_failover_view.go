package awgroute

import "strings"

func (svc *Service) awgRuleFailovers() map[string][][]string {
	out := map[string][][]string{}
	for _, srv := range svc.serverSnapshot() {
		for _, rule := range srv.Manager.RuleFailovers() {
			primary := strings.TrimSpace(rule.PrimaryID)
			if primary == "" {
				primary = srv.ID
			}
			out[primary] = append(out[primary], rule.BackupIDs)
		}
	}
	return out
}
