package arpspoof

import (
	"fmt"
	"regexp"
	"strings"
)

var keeneticLinuxBridge = regexp.MustCompile(`^br(0|[1-9][0-9]*)$`)
var terminalEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
var keeneticCommandError = regexp.MustCompile(`(?im)^\s*(?:[a-z][a-z0-9_]*(?:::[a-z][a-z0-9_]*)+\s+error\s*\[|%?error\s*:)`)

func hasKeeneticCommandError(output string) bool {
	return keeneticCommandError.MatchString(terminalEscape.ReplaceAllString(output, ""))
}

func keeneticBridgeID(linuxName string) (string, error) {
	m := keeneticLinuxBridge.FindStringSubmatch(linuxName)
	if m == nil {
		return "", fmt.Errorf("Keenetic MAC changes require a LAN bridge brN, got %q", linuxName)
	}
	return "Bridge" + m[1], nil
}

func parseKeeneticBridgeMAC(output, expectedID string) (string, error) {
	output = terminalEscape.ReplaceAllString(output, "")
	lines := strings.Split(strings.ReplaceAll(output, "\r", ""), "\n")
	column := -1
	for _, line := range lines {
		if i := strings.IndexByte(line, ':'); i >= 0 && strings.TrimSpace(line[:i]) == "id" {
			if column < 0 || i < column {
				column = i
			}
		}
	}
	fields := map[string]string{}
	for _, line := range lines {
		i := strings.IndexByte(line, ':')
		if i < 0 || i != column {
			continue
		}
		key := strings.TrimSpace(line[:i])
		if key != "id" && key != "type" && key != "mac" {
			continue
		}
		if _, exists := fields[key]; exists {
			return "", fmt.Errorf("ambiguous Keenetic %s field", key)
		}
		fields[key] = strings.TrimSpace(line[i+1:])
	}
	if fields["id"] != expectedID || fields["type"] != "Bridge" {
		return "", fmt.Errorf("Keenetic interface is not verified as %s (type Bridge)", expectedID)
	}
	mac, err := normalizeMAC(fields["mac"])
	if err != nil || mac == "" {
		return "", fmt.Errorf("Keenetic %s did not report a valid MAC", expectedID)
	}
	return mac, nil
}
