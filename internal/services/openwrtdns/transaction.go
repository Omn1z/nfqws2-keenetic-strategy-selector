package openwrtdns

import (
	"context"
	"fmt"
	"reflect"
	"strings"
)

// Resolve an anonymous selector only when a command needs libuci's generated
// name. That name must be read again after commit because its hash can change.
func (m *Manager) reloadInstance(ctx context.Context, instance string) (string, error) {
	if !strings.HasPrefix(instance, "@") {
		return instance, nil
	}
	out, err := m.run(ctx, "uci", "-q", "-X", "show", "dhcp."+instance)
	if err != nil {
		return "", err
	}
	first := strings.SplitN(out, "\n", 2)[0]
	left, right, ok := strings.Cut(first, "=")
	name := strings.TrimPrefix(left, "dhcp.")
	if !ok || right != "dnsmasq" || left == name || !validID(name) {
		return "", fmt.Errorf("не удалось определить имя экземпляра dnsmasq")
	}
	return name, nil
}

func (m *Manager) verifyApplied(ctx context.Context, desired map[string]option, binding Binding, identity string) error {
	var network, dhcp configuration
	for _, v := range []struct {
		name string
		to   *configuration
	}{{"network", &network}, {"dhcp", &dhcp}} {
		out, err := m.run(ctx, "uci", "-q", "-N", "export", v.name)
		if err != nil {
			return err
		}
		*v.to, err = parseExport(out, v.name)
		if err != nil {
			return err
		}
	}
	current, err := managedOptions(network, dhcp, binding)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, desired) {
		return fmt.Errorf("проверка DNS после применения не пройдена: параметры изменены параллельно")
	}
	if err = checkInstanceIdentity(dhcp, &snapshot{Binding: binding, InstanceIdentity: identity}); err != nil {
		return err
	}
	return m.guardChanges(ctx, desired)
}

// The CLI's UCI staging can also be used by other scripts or an SSH session.
// Never commit edits outside the four fields owned by this binding, including
// changes arriving after the initial check. rpcd/LuCI session staging is separate.
func (m *Manager) guardChanges(ctx context.Context, owned map[string]option) error {
	allowed := map[string]bool{}
	instances := map[string]string{}
	for key := range owned {
		allowed[key] = true
		parts := strings.Split(key, ".")
		if len(parts) == 3 && parts[0] == "dhcp" && strings.HasPrefix(parts[1], "@") {
			actual, ok := instances[parts[1]]
			if !ok {
				var err error
				actual, err = m.reloadInstance(ctx, parts[1])
				if err != nil {
					return err
				}
				instances[parts[1]] = actual
			}
			allowed["dhcp."+actual+"."+parts[2]] = true
		}
	}
	for _, pkg := range []string{"network", "dhcp"} {
		out, err := m.run(ctx, "uci", "-q", "changes", pkg)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			key := strings.TrimPrefix(line, "-")
			if i := strings.IndexByte(key, '='); i >= 0 {
				key = strings.TrimSuffix(strings.TrimSuffix(key[:i], "+"), "-")
			}
			if !allowed[key] {
				return fmt.Errorf("обнаружены несохранённые изменения UCI вне управляемых DNS-полей; они не были применены")
			}
		}
	}
	return nil
}
