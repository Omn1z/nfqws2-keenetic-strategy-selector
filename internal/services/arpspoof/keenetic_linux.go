//go:build linux

package arpspoof

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/strs"
)

func keeneticMAC(ndmc, linuxName string) (string, error) {
	nativeID, err := keeneticBridgeID(linuxName)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", linuxName, "bridge")); err != nil {
		return "", fmt.Errorf("%s is not a kernel bridge: %w", linuxName, err)
	}
	out, err := runNDMC(ndmc, "show interface "+nativeID)
	if err != nil {
		return "", err
	}
	return parseKeeneticBridgeMAC(out, nativeID)
}

func setKeeneticMAC(ndmc, linuxName, mac string) error {
	nativeID, err := keeneticBridgeID(linuxName)
	if err != nil {
		return err
	}
	// Verify the native interface before issuing a mutation. No ip-link fallback:
	// it would recreate conflicting ARP SHA / Ethernet source addresses in NDM.
	if _, err := keeneticMAC(ndmc, linuxName); err != nil {
		return err
	}
	if _, err := runNDMC(ndmc, "interface "+nativeID+" mac address "+mac); err != nil {
		return err
	}
	native, err := keeneticMAC(ndmc, linuxName)
	if err != nil {
		return err
	}
	kernel, err := interfaceMAC(linuxName)
	if err != nil || native != mac || kernel != mac {
		return fmt.Errorf("Keenetic MAC verification failed on %s: native=%q kernel=%q want=%q (%v)", linuxName, native, kernel, mac, err)
	}
	logbuf.Append("arp-spoofing", "info", "interface "+linuxName+" / "+nativeID+" MAC -> "+mac)
	return nil
}

func runNDMC(binary, command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "-c", command).CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		return "", fmt.Errorf("Keenetic native MAC command: %w: %s", err, strs.LastLines(result, 4))
	}
	if hasKeeneticCommandError(result) {
		return "", fmt.Errorf("Keenetic rejected MAC command: %s", strs.LastLines(result, 4))
	}
	return result, nil
}
