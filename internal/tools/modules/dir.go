// Package modules locates the optional payloads installed by Entware.
package modules

import "os"

func Dir() string {
	if path := os.Getenv("N2S_MODULE_DIR"); path != "" {
		return path
	}
	return "/opt/lib/nfqws2-strategy/modules"
}
