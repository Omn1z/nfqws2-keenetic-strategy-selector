package awgroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/logbuf"
)

func awgJSONObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if len(bytes.TrimSpace(data)) == 0 || json.Unmarshal(data, &object) != nil || object == nil {
		return nil, fmt.Errorf("ожидается непустой JSON-объект настроек Amnezia")
	}
	return object, nil
}

func validateAWGProfile(data []byte) error {
	object, err := awgJSONObject(data)
	if err != nil {
		return err
	}
	_, hasEndpoint := object["endpoint"]
	_, hasPeers := object["peers"]
	_, hasConn := object["conn"]
	_, hasInstall := object["install"]
	if !hasEndpoint || (!hasPeers && !hasConn && !hasInstall) {
		return fmt.Errorf("файл не содержит распознаваемую конфигурацию Amnezia")
	}
	for _, key := range []string{"conn", "client", "routing", "obf"} {
		if value, ok := object[key]; ok {
			if _, err := awgJSONObject(value); err != nil {
				return fmt.Errorf("некорректная структура Amnezia: %s", key)
			}
		}
	}
	var profile awg.ServerConfig
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("некорректные типы полей конфигурации Amnezia")
	}
	switch profile.Install {
	case "", "apt", "userspace", "imported":
	default:
		return fmt.Errorf("неизвестный формат установки Amnezia")
	}
	switch profile.Protocol {
	case "", "awg", "wireguard":
	default:
		return fmt.Errorf("неизвестный протокол Amnezia")
	}
	return nil
}

// This validates the persisted shape, not whether an unfinished profile is
// ready to deploy. Legacy/imported configs may legitimately lack SSH/key data.
func decodePersistedAWG(data []byte) (awgPersisted, error) {
	object, err := awgJSONObject(data)
	if err != nil {
		return awgPersisted{}, err
	}
	if raw, modern := object["servers"]; modern {
		var servers []struct {
			Config  json.RawMessage `json:"config"`
			Applied json.RawMessage `json:"applied_config"`
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &servers) != nil {
			return awgPersisted{}, fmt.Errorf("некорректный список подключений Amnezia")
		}
		var state awgPersisted
		if err := json.Unmarshal(data, &state); err != nil {
			return state, fmt.Errorf("некорректные типы полей состояния Amnezia")
		}
		if len(servers) == 0 && (len(state.PendingRules) == 0 || state.Routing == nil) {
			return state, fmt.Errorf("пустой список подключений без сохранённых правил Amnezia")
		}
		for i, server := range servers {
			if err := validateAWGProfile(server.Config); err != nil {
				return state, fmt.Errorf("подключение Amnezia %d: %w", i+1, err)
			}
			if len(server.Applied) > 0 && !bytes.Equal(bytes.TrimSpace(server.Applied), []byte("null")) {
				if err := validateAWGProfile(server.Applied); err != nil {
					return state, fmt.Errorf("применённая конфигурация Amnezia %d: %w", i+1, err)
				}
			}
		}
		return normalizeAWGState(state), nil
	}
	if err := validateAWGProfile(data); err != nil {
		return awgPersisted{}, err
	}
	var legacy awg.ServerConfig
	if err := json.Unmarshal(data, &legacy); err != nil {
		return awgPersisted{}, fmt.Errorf("некорректная устаревшая конфигурация Amnezia")
	}
	legacy.Normalize()
	return normalizeAWGState(awgPersisted{ActiveID: "awg0", Servers: []awgPersistedServer{{ID: "awg0", Config: legacy}}}), nil
}

func validatePersistedAWG(data []byte) error { _, err := decodePersistedAWG(data); return err }

func (svc *Service) loadPersistedAWGState() awgPersisted {
	var data json.RawMessage
	recovered, err := svc.store.LoadConfig(awgConfigFile, &data, validatePersistedAWG)
	if errors.Is(err, os.ErrNotExist) {
		svc.setAWGLoadResult(nil, false)
		return defaultAWGState()
	}
	if err == nil {
		state, decodeErr := decodePersistedAWG(data)
		if decodeErr == nil {
			svc.setAWGLoadResult(nil, recovered)
			if recovered {
				logbuf.Append("awg2", "warn", "Настройки Amnezia восстановлены из проверенной резервной копии")
			}
			return state
		}
		err = decodeErr
	}
	svc.setAWGLoadResult(err, false)
	logbuf.Append("awg2", "error", "Не удалось загрузить настройки Amnezia; исходные файлы сохранены, автоматическая запись и запуск отключены: "+err.Error())
	return defaultAWGState()
}

func (svc *Service) setAWGLoadResult(err error, recovered bool) {
	svc.mu.Lock()
	svc.persistenceErr = err
	svc.configRecovered = recovered
	if err == nil {
		svc.lastSaveErr = nil
	}
	svc.mu.Unlock()
}

func (svc *Service) awgPersistenceReady() error {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	if svc.persistenceErr != nil {
		return fmt.Errorf("настройки Amnezia не загружены; восстановите сохранённую конфигурацию: %w", svc.persistenceErr)
	}
	return nil
}

func (svc *Service) awgPersistenceStatus() (string, bool) {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	err := svc.persistenceErr
	if err == nil {
		err = svc.lastSaveErr
	}
	if err == nil {
		return "", svc.configRecovered
	}
	return err.Error(), svc.configRecovered
}

func (svc *Service) persistAWGState(state *awgPersisted) error {
	if err := svc.awgPersistenceReady(); err != nil {
		return err
	}
	if svc.store == nil {
		return fmt.Errorf("хранилище настроек Amnezia недоступно")
	}
	state.ConnectionRefs = awgRetainedConnectionRefs(state.ConnectionRefs, state.PendingRules, state.Servers)
	err := svc.store.SaveSecret(awgConfigFile, state)
	svc.mu.Lock()
	svc.lastSaveErr = err
	svc.mu.Unlock()
	return err
}

// Backup restoration must reload disk state even after a partial restore
// error: the old live snapshot must never overwrite newly restored bytes.
func (svc *Service) RestorePersistedState(restore func() (int, error)) (int, error) {
	_, unlock := svc.lockClientOps(true)
	defer unlock()
	n, restoreErr := svc.RestoreRoutingDiscoveries(restore)
	state := svc.loadAWGState()
	if err := svc.awgPersistenceReady(); err != nil {
		return n, errors.Join(restoreErr, err)
	}
	if !awgPersistedStatesEqual(svc.snapshotAWGState(), state) {
		svc.installAWGState(state)
	}
	return n, restoreErr
}
