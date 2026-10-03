package app

import "nfqws2strategy/internal/services/nfqws2"

func (a *App) AnalyzeNfqws2Paths(content, kind string) nfqws2.PathAnalysis {
	return a.nfqws2.AnalyzePaths(content, kind)
}
