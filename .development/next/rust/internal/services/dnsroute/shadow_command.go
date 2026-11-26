package dnsroute

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Some firmware versions report a native-control failure with exit status 0.
// Do not mistake a failed command for an empty DNS list. Match standalone CLI
// diagnostics, not historical ndmc failures embedded in `show log` records.
// Output can contain the complete router log, so never include it in the DNS
// error shown to clients. Operations are fixed strings or validated interface
// names; diagnostics stay bounded independently of command output size.
func shadowNativeCommandError(ctx context.Context, operation, output string, commandErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if errors.Is(commandErr, context.Canceled) || errors.Is(commandErr, context.DeadlineExceeded) {
		return commandErr
	}
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "ndmc: initialization failure." || line == "ndmc: initialization failure" || strings.HasPrefix(line, "ndmc: system failed [") {
			return fmt.Errorf("Keenetic: ndmc не смог инициализироваться (%s); проверьте запуск ndmc из Entware: initialization failure", operation)
		}
	}
	if commandErr != nil {
		return fmt.Errorf("Keenetic: не удалось выполнить ndmc %q; проверьте доступ к управлению Keenetic из Entware", operation)
	}
	return nil
}
