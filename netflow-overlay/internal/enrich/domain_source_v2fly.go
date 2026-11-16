package enrich

import (
	"bufio"
	"fmt"
	"sort"
	"strings"
)

// V2FlyList is a caller-supplied, versioned snapshot of upstream data files.
// The caller is responsible for authenticating and checksumming the snapshot.
type V2FlyList map[string]string

// ParseV2FlyApplication resolves one explicitly mapped list. Unsupported
// keyword/regexp rules and filtered includes are skipped, never guessed.
func ParseV2FlyApplication(files V2FlyList, list, appID, version string) ([]DomainRule, int, error) {
	if list == "" || appID == "" || version == "" {
		return nil, 0, fmt.Errorf("list, application and source version are required")
	}
	var out []DomainRule
	skipped := 0
	active := map[string]bool{}
	visited := map[string]bool{}
	unique := map[string]bool{}
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if depth > 64 {
			return fmt.Errorf("include depth exceeded")
		}
		if active[name] {
			return fmt.Errorf("include cycle: %s", name)
		}
		if visited[name] {
			return nil
		}
		content, ok := files[name]
		if !ok {
			return fmt.Errorf("missing include: %s", name)
		}
		if len(content) > 8<<20 {
			return fmt.Errorf("list exceeds size limit")
		}
		active[name] = true
		defer delete(active, name)
		scanner := bufio.NewScanner(strings.NewReader(content))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line, _, _ := strings.Cut(scanner.Text(), "#")
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 0 {
				continue
			}
			spec := fields[0]
			if strings.HasPrefix(spec, "include:") {
				if len(fields) > 1 {
					skipped++
					continue
				} // attributes require upstream filter semantics
				child := strings.TrimPrefix(spec, "include:")
				if child == "" || strings.ContainsAny(child, "/\\.") {
					return fmt.Errorf("invalid include")
				}
				if err := walk(child, depth+1); err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(spec, "regexp:") || strings.HasPrefix(spec, "keyword:") {
				skipped++
				continue
			}
			match := "suffix"
			if strings.HasPrefix(spec, "full:") {
				match = "exact"
				spec = strings.TrimPrefix(spec, "full:")
			} else if strings.HasPrefix(spec, "domain:") {
				spec = strings.TrimPrefix(spec, "domain:")
			} else if strings.Contains(spec, ":") {
				skipped++
				continue
			}
			domain, err := NormalizeDomain(spec)
			if err != nil {
				skipped++
				continue
			}
			key := match + ":" + domain
			if unique[key] {
				skipped++
				continue
			}
			unique[key] = true
			// This is a community list; it is not evidence of exclusive ownership.
			out = append(out, DomainRule{Domain: domain, Match: match, AppID: appID, Source: "v2fly:" + name + "@" + version, Confidence: "medium", Enabled: true})
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		visited[name] = true
		return nil
	}
	if err := walk(list, 0); err != nil {
		return nil, skipped, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain == out[j].Domain {
			return out[i].Match < out[j].Match
		}
		return out[i].Domain < out[j].Domain
	})
	return out, skipped, nil
}
