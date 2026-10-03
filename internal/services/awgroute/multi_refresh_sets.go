package awgroute

import (
	"fmt"
	"strings"
)

type awgMultiSetRefresh struct {
	Name    string
	Entries []string
}

// Periodic refresh is the SAME policy, so retain all learned addresses and
// remaining timeout/counter options from the live set. Changed policies use
// the separate full apply path and never union obsolete rule bindings.
func awgMultiSetRefreshDocuments(sets []awgMultiSetRefresh, saved string) (prepare, commit string, err error) {
	definitions := map[string]string{}
	members := map[string][]string{}
	seen := map[string]map[string]bool{}
	wanted := make(map[string]bool, len(sets))
	for _, set := range sets {
		if !strings.HasPrefix(set.Name, "awgm_") || strings.ContainsAny(set.Name, " \t\r\n'\"") {
			return "", "", fmt.Errorf("invalid multi set name")
		}
		wanted[set.Name] = true
		seen[set.Name] = map[string]bool{}
	}
	for _, raw := range strings.Split(saved, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 2 || !wanted[fields[1]] {
			continue
		}
		switch fields[0] {
		case "create":
			if len(fields) < 5 || fields[2] != "hash:net" || fields[3] != "family" || fields[4] != "inet" {
				return "", "", fmt.Errorf("unsupported live multi set definition: %s", fields[1])
			}
			definitions[fields[1]] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "create "+fields[1]))
		case "add":
			if len(fields) < 3 {
				return "", "", fmt.Errorf("invalid multi set member")
			}
			entry, ok := awgNormalizeMultiEntry(fields[2])
			if !ok {
				return "", "", fmt.Errorf("invalid live multi set address")
			}
			seen[fields[1]][entry] = true
			members[fields[1]] = append(members[fields[1]], strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "add "+fields[1])))
		}
	}
	var build, swap strings.Builder
	for _, set := range sets {
		definition, ok := definitions[set.Name]
		if !ok {
			return "", "", fmt.Errorf("live multi set missing: %s", set.Name)
		}
		stage := set.Name + "_r"
		build.WriteString("create " + stage + " " + definition + "\n")
		for _, member := range members[set.Name] {
			build.WriteString("add " + stage + " " + member + "\n")
		}
		for _, raw := range set.Entries {
			entry, ok := awgNormalizeMultiEntry(raw)
			if !ok {
				return "", "", fmt.Errorf("invalid refresh address")
			}
			if !seen[set.Name][entry] {
				build.WriteString("add " + stage + " " + entry + " -exist\n")
				seen[set.Name][entry] = true
			}
		}
		swap.WriteString("swap " + stage + " " + set.Name + "\ndestroy " + stage + "\n")
	}
	return build.String(), swap.String(), nil
}

func awgCommitMultiSetRefresh(prepare, commit string, run func(string) error) error {
	if prepare == "" {
		return nil
	}
	if err := run(prepare); err != nil {
		return fmt.Errorf("prepare multi sets: %w", err)
	}
	if err := run(commit); err != nil {
		return fmt.Errorf("swap multi sets: %w", err)
	}
	return nil
}
