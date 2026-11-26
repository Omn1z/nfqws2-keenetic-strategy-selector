package nfqws2

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var literalEngineUser = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+(?::[0-9]+)?)$`)

// Read a literal USER assignment only. The configuration is never sourced,
// expanded or executed to decide the ownership of a newly imported autolist.
func engineUserLiteral(conf []byte) (string, error) {
	user := ""
	for _, line := range strings.Split(string(conf), "\n") {
		left, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		left = strings.TrimSpace(left)
		if strings.HasPrefix(left, "export ") || strings.HasPrefix(left, "export\t") {
			left = strings.TrimSpace(left[len("export"):])
		}
		if left != "USER" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			user = ""
			continue
		}
		if value[0] == '\'' || value[0] == '"' {
			end := strings.IndexByte(value[1:], value[0])
			if end < 0 {
				return "", fmt.Errorf("для нового autolist укажите USER как обычное имя пользователя без выражений shell")
			}
			end++
			tail := strings.TrimSpace(value[end+1:])
			if tail != "" && !strings.HasPrefix(tail, "#") {
				return "", fmt.Errorf("не удалось безопасно прочитать USER для нового autolist")
			}
			value = value[1:end]
		} else {
			fields := strings.Fields(value)
			if len(fields) > 1 && !strings.HasPrefix(fields[1], "#") {
				return "", fmt.Errorf("не удалось безопасно прочитать USER для нового autolist")
			}
			value = fields[0]
		}
		if value != "" && !literalEngineUser.MatchString(value) {
			return "", fmt.Errorf("для нового autolist укажите USER как обычное имя пользователя без выражений shell")
		}
		user = value
	}
	return user, nil
}

func parseAssetID(value string) (int, error) {
	n, err := strconv.ParseInt(value, 10, 32)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("недопустимый UID/GID")
	}
	return int(n), nil
}

func lookupAssetOwner(user string, passwdPaths []string) (*assetOwner, error) {
	if user == "" {
		return nil, nil
	}
	if uidText, gidText, ok := strings.Cut(user, ":"); ok {
		uid, err := parseAssetID(uidText)
		if err != nil {
			return nil, err
		}
		gid, err := parseAssetID(gidText)
		if err != nil {
			return nil, err
		}
		return &assetOwner{uid: uid, gid: gid}, nil
	}
	for _, file := range passwdPaths {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
		var found *assetOwner
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), ":")
			if len(parts) < 4 || parts[0] != user && parts[2] != user {
				continue
			}
			uid, uidErr := parseAssetID(parts[2])
			gid, gidErr := parseAssetID(parts[3])
			if uidErr == nil && gidErr == nil {
				found = &assetOwner{uid: uid, gid: gid}
				break
			}
		}
		f.Close()
		if found != nil {
			return found, nil
		}
	}
	return nil, fmt.Errorf("пользователь USER=%s не найден: невозможно назначить права новому autolist", user)
}
