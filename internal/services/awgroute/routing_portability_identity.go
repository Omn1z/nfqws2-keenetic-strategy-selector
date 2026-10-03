package awgroute

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func awgConnectionReference(server *managedServer) AWG2ConnectionRef {
	if server == nil || server.Manager == nil {
		return AWG2ConnectionRef{}
	}
	cfg := server.Manager.PublicConnectionIdentity()
	ref := AWG2ConnectionRef{Ref: server.ID, Label: server.Name, Endpoint: strings.TrimSpace(cfg.Endpoint), ClientIface: strings.TrimSpace(cfg.ClientIface), ServerPublicKey: strings.TrimSpace(cfg.ServerPublicKey)}
	if strings.EqualFold(strings.TrimSpace(cfg.Protocol), "wireguard") {
		ref.Protocol = "wireguard"
	} else {
		ref.Protocol = "awg/" + cfg.ProtocolVersion
	}
	if endpoint, err := awgCanonicalEndpoint(ref.Endpoint); err == nil {
		ref.Endpoint = endpoint
	} else {
		ref.Endpoint = ""
	}
	if key, err := awgCanonicalPublicKey(ref.ServerPublicKey); err == nil {
		ref.ServerPublicKey = key
	} else {
		ref.ServerPublicKey = ""
	}
	if !validAWGClientIfaceName(ref.ClientIface) {
		ref.ClientIface = ""
	}
	if !awgValidPortableProtocol(ref.Protocol) {
		ref.Protocol = ""
	}
	ref.Fingerprint = awgConnectionFingerprint(ref)
	return ref
}

// Labels, local IDs and client secrets never identify a remote connection.
// A blank profile cannot acquire an identity merely from its default iface.
func awgConnectionFingerprint(ref AWG2ConnectionRef) string {
	endpoint, err := awgCanonicalEndpoint(ref.Endpoint)
	if err != nil || !validAWGClientIfaceName(ref.ClientIface) || !awgValidPortableProtocol(ref.Protocol) {
		return ""
	}
	key, err := awgCanonicalPublicKey(ref.ServerPublicKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256([]byte(ref.Protocol + "\x00" + endpoint + "\x00" + key + "\x00" + ref.ClientIface))
	return hex.EncodeToString(hash[:16])
}

func awgCanonicalEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint должен быть host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("неверный порт endpoint")
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else if !routingHostname(host) {
		return "", fmt.Errorf("неверное имя endpoint")
	}
	return net.JoinHostPort(host, strconv.Itoa(p)), nil
}

func awgCanonicalPublicKey(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("неверный публичный ключ сервера")
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func awgValidPortableProtocol(protocol string) bool {
	switch protocol {
	case "wireguard", "awg/1.0", "awg/1.5", "awg/2", "awg/3.1":
		return true
	}
	return false
}
