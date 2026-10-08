package config

import (
	"fmt"
	"strings"
	"unicode"
)

// NormalizeWANInterfaces makes literal WAN lists compatible with upstream
// shell loops. Only assignment-only configuration files are edited: arbitrary
// shell programs and dynamic ISP_INTERFACE values are preserved verbatim.
func NormalizeWANInterfaces(source string) (string, error) {
	assignments, safe := wanAssignments(source)
	if !safe {
		return source, nil
	}
	var out strings.Builder
	start := 0
	for _, assignment := range assignments {
		if !assignment.literal {
			continue
		}
		ifaces, err := splitWANInterfaces(assignment.value)
		if err != nil {
			return source, err
		}
		value := strings.Join(ifaces, " ")
		if value == assignment.value {
			continue
		}
		encoded := value
		if assignment.quote != 0 {
			encoded = string(assignment.quote) + value + string(assignment.quote)
		} else if strings.Contains(value, " ") {
			encoded = `"` + value + `"`
		}
		out.WriteString(source[start:assignment.from])
		out.WriteString(encoded)
		start = assignment.to
	}
	if start == 0 {
		return source, nil
	}
	out.WriteString(source[start:])
	return out.String(), nil
}

// WANInterfacesFromConf reads the last standalone ISP_INTERFACE assignment
// without evaluating shell. Missing/dynamic values and shell programs return
// nil, allowing callers to retain their existing defaults.
func WANInterfacesFromConf(source string) ([]string, error) {
	assignments, safe := wanAssignments(source)
	if !safe {
		return nil, nil
	}
	var ifaces []string
	for _, assignment := range assignments {
		ifaces = nil
		if !assignment.literal {
			continue
		}
		var err error
		ifaces, err = splitWANInterfaces(assignment.value)
		if err != nil {
			return nil, err
		}
	}
	return ifaces, nil
}

type wanAssignment struct {
	from, to int
	value    string
	quote    byte
	literal  bool
}

func splitWANInterfaces(value string) ([]string, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	ifaces := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, iface := range parts {
		if len(iface) > 15 {
			return nil, fmt.Errorf("ISP_INTERFACE: имя интерфейса %q длиннее 15 байт; разделяйте интерфейсы пробелом или запятой", iface)
		}
		name := strings.TrimSuffix(iface, "+") // iptables permits a terminal prefix wildcard.
		if name == "." || name == ".." {
			return nil, fmt.Errorf("ISP_INTERFACE: недопустимое имя интерфейса %q", iface)
		}
		for _, ch := range name {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || strings.ContainsRune("_.:-", ch)) {
				return nil, fmt.Errorf("ISP_INTERFACE: недопустимое имя интерфейса %q", iface)
			}
		}
		if !seen[iface] {
			seen[iface] = true
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces, nil
}

// A conservative statement scanner deliberately refuses command substitutions,
// compound shell statements and heredocs. It understands quoting/continuations
// so an assignment-looking line inside a multiline strategy is never edited.
func wanAssignments(source string) ([]wanAssignment, bool) {
	var assignments []wanAssignment
	for start := 0; start < len(source); {
		end, safe := wanStatementEnd(source, start)
		if !safe {
			return nil, false
		}
		pos := start
		for pos < end && wanHorizontalSpace(source[pos]) {
			pos++
		}
		if pos == end || source[pos] == '#' {
			start = end + 1
			continue
		}
		if strings.HasPrefix(source[pos:end], "export") && pos+6 < end && wanHorizontalSpace(source[pos+6]) {
			pos += 6
			for pos < end && wanHorizontalSpace(source[pos]) {
				pos++
			}
		}
		keyStart := pos
		for pos < end && wanNameChar(source[pos], pos == keyStart) {
			pos++
		}
		if pos == keyStart || pos == end || source[pos] != '=' {
			return nil, false
		}
		key := source[keyStart:pos]
		pos++
		assignment, safe := wanAssignmentValue(source, pos, end)
		if !safe {
			return nil, false
		}
		if key == "ISP_INTERFACE" {
			assignments = append(assignments, assignment)
		}
		start = end + 1
	}
	return assignments, true
}

func wanHorizontalSpace(ch byte) bool { return ch == ' ' || ch == '\t' || ch == '\r' }

func wanNameChar(ch byte, first bool) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' || !first && ch >= '0' && ch <= '9'
}

func wanStatementEnd(source string, start int) (int, bool) {
	var quote byte
	for pos := start; pos < len(source); pos++ {
		ch := source[pos]
		if ch == '\\' && quote != '\'' {
			if pos+1 == len(source) {
				return len(source), false
			}
			pos++
			continue
		}
		if quote == '\'' {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '`' || ch == '$' && pos+1 < len(source) && (source[pos+1] == '(' || source[pos+1] == '\'') {
			return len(source), false
		}
		if ch == '$' && pos+1 < len(source) && source[pos+1] == '{' {
			// Simple braced variables cannot contain shell syntax or newlines.
			last := pos + 2
			for last < len(source) && wanNameChar(source[last], last == pos+2) {
				last++
			}
			if last == pos+2 || last == len(source) || source[last] != '}' {
				return len(source), false
			}
			pos = last
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '#':
			if pos == start || wanHorizontalSpace(source[pos-1]) {
				if offset := strings.IndexByte(source[pos:], '\n'); offset >= 0 {
					return pos + offset, true
				}
				return len(source), true
			}
		case '\n':
			return pos, true
		}
	}
	return len(source), quote == 0
}

func wanAssignmentValue(source string, from, end int) (wanAssignment, bool) {
	assignment := wanAssignment{from: from, literal: true}
	var value strings.Builder
	var quote byte
	pos := from
	for ; pos < end; pos++ {
		ch := source[pos]
		if quote == 0 && (wanHorizontalSpace(ch) || strings.ContainsRune(";|&<>()", rune(ch))) {
			break
		}
		if ch == '\\' && quote != '\'' {
			if pos+1 == end {
				return assignment, false
			}
			next := source[pos+1]
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", rune(next)) {
				value.WriteByte(ch) // Inside double quotes, \x stays \x.
				continue
			}
			pos++
			if next != '\n' {
				value.WriteByte(next)
			}
			continue
		}
		if quote == 0 && (ch == '\'' || ch == '"') {
			quote = ch
			continue
		}
		if quote != 0 && ch == quote {
			quote = 0
			continue
		}
		if quote != '\'' && ch == '$' {
			assignment.literal = false
		}
		if quote == 0 && ch == '~' && (pos == from || source[pos-1] == ':') {
			assignment.literal = false // Shell assignment words can expand home directories.
		}
		value.WriteByte(ch)
	}
	assignment.to = pos
	assignment.value = value.String()
	if pos-from >= 2 && (source[from] == '\'' || source[from] == '"') && source[pos-1] == source[from] {
		assignment.quote = source[from]
	}
	for pos < end && wanHorizontalSpace(source[pos]) {
		pos++
	}
	return assignment, quote == 0 && (pos == end || source[pos] == '#')
}
