package openwrtdns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var (
	errUnmatchedInstance = errors.New("сохранённый экземпляр dnsmasq больше не совпадает с конфигурацией UCI; восстановите прежние настройки экземпляра и обновите состояние")
	errAmbiguousInstance = errors.New("невозможно однозначно определить сохранённый экземпляр dnsmasq; проверьте конфигурацию UCI")
)

func instanceIdentity(s section, ignoreTuning bool) string {
	values := make(map[string]option, len(s.Options))
	for key, value := range s.Options {
		switch key {
		case "server", "noresolv":
			continue
		case "cachesize", "logqueries", "logfacility", "logdhcp", "quietdhcp", "quietdhcp6", "logasync":
			if ignoreTuning {
				continue
			}
		}
		values[key] = value
	}
	encoded, _ := json.Marshal(values)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func ownsForwarding(s section, saved *snapshot) bool {
	prefix := "dhcp." + saved.Binding.Instance + "."
	return reflect.DeepEqual(s.Options["server"], saved.Applied[prefix+"server"]) &&
		reflect.DeepEqual(s.Options["noresolv"], saved.Applied[prefix+"noresolv"])
}

// An ordinal may now point to a different section. Prefer an exact identity
// match. A normal tuning change is safe only when established forwarding
// options still identify exactly one instance with the same serving settings.
func resolveInstance(c configuration, saved *snapshot) (*snapshot, error) {
	if !strings.HasPrefix(saved.Binding.Instance, "@") {
		return saved, nil
	}
	var exact string
	for _, s := range c.Sections {
		if s.Type != "dnsmasq" || !strings.HasPrefix(s.ID, "@") {
			continue
		}
		if instanceIdentity(s, false) == saved.InstanceIdentity {
			if exact != "" {
				return nil, errAmbiguousInstance
			}
			exact = s.ID
		}
	}
	if exact != "" {
		return saved.withInstance(exact), nil
	}
	if saved.Pending || saved.InstanceScope == "" {
		return nil, errUnmatchedInstance
	}
	var tuned string
	for _, s := range c.Sections {
		if s.Type != "dnsmasq" || !strings.HasPrefix(s.ID, "@") || !ownsForwarding(s, saved) ||
			instanceIdentity(s, true) != saved.InstanceScope {
			continue
		}
		if tuned != "" {
			return nil, errAmbiguousInstance
		}
		tuned = s.ID
	}
	if tuned != "" {
		return saved.withInstance(tuned), nil
	}
	return nil, errUnmatchedInstance
}

// Older snapshots did not record which options determine serving scope.
// Report a candidate for explicit confirmation only if every managed option
// is still in place and no other instance has the same forwarding settings.
func legacyRebindCandidate(network, dhcp configuration, saved *snapshot) *snapshot {
	if saved.Pending || saved.InstanceScope != "" {
		return nil
	}
	var instance string
	for _, s := range dhcp.Sections {
		if s.Type != "dnsmasq" || !ownsForwarding(s, saved) {
			continue
		}
		if instance != "" || !strings.HasPrefix(s.ID, "@") || s.scalar("disabled") == "1" || s.scalar("port") == "0" {
			return nil
		}
		instance = s.ID
	}
	if instance == "" {
		return nil
	}
	candidate := saved.withInstance(instance)
	current, err := managedOptions(network, dhcp, candidate.Binding)
	if err != nil || conflict(current, candidate) != nil {
		return nil
	}
	return candidate
}

func (s *snapshot) withInstance(instance string) *snapshot {
	if s.Binding.Instance == instance {
		return s
	}
	oldPrefix := "dhcp." + s.Binding.Instance + "."
	newPrefix := "dhcp." + instance + "."
	rekey := func(values map[string]option) map[string]option {
		if len(values) == 0 {
			return nil
		}
		result := make(map[string]option, len(values))
		for key, value := range values {
			if suffix, ok := strings.CutPrefix(key, oldPrefix); ok {
				key = newPrefix + suffix
			}
			result[key] = value
		}
		return result
	}
	rebound := *s
	rebound.Binding.Instance = instance
	rebound.Original = rekey(s.Original)
	rebound.Applied = rekey(s.Applied)
	rebound.Before = rekey(s.Before)
	return &rebound
}

func (s *snapshot) captureInstance(c configuration) error {
	if !strings.HasPrefix(s.Binding.Instance, "@") {
		return nil
	}
	selected, ok := c.find(s.Binding.Instance, "dnsmasq")
	if !ok {
		return errUnmatchedInstance
	}
	s.InstanceIdentity = instanceIdentity(selected, false)
	s.InstanceScope = instanceIdentity(selected, true)
	return checkInstanceIdentity(c, s.Binding, s.InstanceIdentity)
}

// Once a transaction starts, its selector must keep pointing at the same
// instance. Do not retarget a partially applied write or rollback.
func checkInstanceIdentity(c configuration, binding Binding, identity string) error {
	if !strings.HasPrefix(binding.Instance, "@") {
		return nil
	}
	for _, other := range c.Sections {
		if other.Type == "dnsmasq" && other.ID != binding.Instance &&
			strings.HasPrefix(other.ID, "@") && instanceIdentity(other, false) == identity {
			return fmt.Errorf("невозможно однозначно определить анонимный экземпляр dnsmasq")
		}
	}
	selected, ok := c.find(binding.Instance, "dnsmasq")
	if !ok || instanceIdentity(selected, false) != identity {
		return fmt.Errorf("анонимный экземпляр dnsmasq изменён или переставлен во время операции")
	}
	return nil
}
