package openwrtdns

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type option struct {
	Kind   string   `json:"kind,omitempty"`
	Values []string `json:"values,omitempty"`
}
type section struct {
	ID, Type string
	Options  map[string]option
}
type configuration struct {
	Sections []section
	Raw      string
}

// Generated cfgXXXX IDs change when an anonymous section is committed. Export
// without generated names and use the type's ordinal selector instead.
func parseExport(raw, pkg string) (configuration, error) {
	result := configuration{Raw: raw}
	if len(raw) > 4<<20 {
		return result, fmt.Errorf("слишком большая конфигурация UCI")
	}
	seen := map[string]bool{}
	ordinals := map[string]int{}
	for _, line := range strings.Split(raw, "\n") {
		words, err := uciWords(line)
		if err != nil {
			return result, err
		}
		if len(words) == 0 {
			continue
		}
		switch words[0] {
		case "package":
			if len(words) != 2 || words[1] != pkg {
				return result, fmt.Errorf("неверный пакет UCI")
			}
		case "config":
			if (len(words) != 2 && len(words) != 3) || !validID(words[1]) {
				return result, fmt.Errorf("неверная или повторяющаяся секция UCI")
			}
			id := "@" + words[1] + "[" + strconv.Itoa(ordinals[words[1]]) + "]"
			ordinals[words[1]]++
			if len(words) == 3 {
				if !validID(words[2]) {
					return result, fmt.Errorf("неверное имя секции UCI")
				}
				id = words[2]
			}
			if seen[id] {
				return result, fmt.Errorf("повторяющаяся секция UCI")
			}
			seen[id] = true
			result.Sections = append(result.Sections, section{ID: id, Type: words[1], Options: map[string]option{}})
		case "option", "list":
			if len(words) != 3 || len(result.Sections) == 0 || !validID(words[1]) {
				return result, fmt.Errorf("неверный параметр UCI")
			}
			options := result.Sections[len(result.Sections)-1].Options
			old := options[words[1]]
			if words[0] == "option" {
				if old.Kind != "" {
					return result, fmt.Errorf("повторяющийся параметр UCI")
				}
				options[words[1]] = option{Kind: "option", Values: []string{words[2]}}
			} else {
				if old.Kind != "" && old.Kind != "list" {
					return result, fmt.Errorf("смешанный параметр UCI")
				}
				options[words[1]] = option{Kind: "list", Values: append(old.Values, words[2])}
			}
		default:
			return result, fmt.Errorf("неподдерживаемый вывод UCI")
		}
	}
	return result, nil
}

func validInstance(s string) bool {
	if validID(s) {
		return true
	}
	if !strings.HasPrefix(s, "@dnsmasq[") || !strings.HasSuffix(s, "]") {
		return false
	}
	n, err := strconv.Atoi(s[len("@dnsmasq[") : len(s)-1])
	return err == nil && n >= 0 && n < 1024 && s == "@dnsmasq["+strconv.Itoa(n)+"]"
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// Decode quoting emitted by libuci, including an apostrophe represented by
// '\”. This is a lexer only; variables, substitutions and commands never run.
func uciWords(line string) ([]string, error) {
	var result []string
	var word strings.Builder
	quote, escaped, started := rune(0), false, false
	for _, c := range line {
		if c == 0 || c == '\r' {
			return nil, fmt.Errorf("некорректный текст UCI")
		}
		if escaped {
			word.WriteRune(c)
			escaped = false
			started = true
			continue
		}
		if quote == '\'' {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '\\' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			started = true
			continue
		}
		if c == '#' && !started {
			break
		}
		if unicode.IsSpace(c) {
			if started {
				result = append(result, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		started = true
		word.WriteRune(c)
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("незавершённая строка UCI")
	}
	if started {
		result = append(result, word.String())
	}
	return result, nil
}

func (c configuration) find(id, kind string) (section, bool) {
	for _, s := range c.Sections {
		if s.ID == id && s.Type == kind {
			return s, true
		}
	}
	return section{}, false
}
func (s section) scalar(key string) string {
	if values := s.Options[key].Values; len(values) > 0 {
		return values[0]
	}
	return ""
}

func conditionalServer(value string) bool {
	if !strings.HasPrefix(value, "/") {
		return false
	}
	i := strings.LastIndex(value, "/")
	if i < 1 {
		return false
	}
	for _, domain := range strings.Split(value[1:i], "/") {
		if domain == "#" {
			return false
		}
	}
	return true
}
