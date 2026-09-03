// Package ingress compiles and matches the ordered hostname routing rules
// from config.Ingress, modeled loosely on cloudflared's ingress rule list
// (an ordered top-to-bottom match with an optional catch-all last rule) -
// that overall shape is this project's own design choice for parity with a
// familiar workflow, not something read out of cloudflared's source.
package ingress

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Dankular/Tunneld/internal/config"
)

// Kind identifies what a Rule's Service does.
type Kind int

const (
	// KindHTTP reverse-proxies to a local http:// or https:// service.
	KindHTTP Kind = iota
	// KindTCP proxies raw TCP to a local service on its own listener.
	KindTCP
	// KindStatus always answers with a fixed HTTP status code.
	KindStatus
)

// Rule is one compiled ingress rule.
type Rule struct {
	Hostname   string // empty means catch-all
	PathRegex  *regexp.Regexp
	Kind       Kind
	TargetURL  *url.URL // set when Kind == KindHTTP
	TargetAddr string   // set when Kind == KindTCP ("host:port")
	StatusCode int      // set when Kind == KindStatus
	ListenPort int      // set when Kind == KindTCP
}

// Rules is a compiled, ordered ingress rule list.
type Rules []Rule

// Compile validates and compiles a config.Ingress list, already assumed to
// have passed config.Config.Validate.
func Compile(raw []config.Ingress) (Rules, error) {
	rules := make(Rules, 0, len(raw))
	for i, r := range raw {
		rule := Rule{Hostname: r.Hostname, ListenPort: r.ListenPort}

		if r.PathRegex != "" {
			re, err := regexp.Compile(r.PathRegex)
			if err != nil {
				return nil, fmt.Errorf("ingress[%d]: path regex: %w", i, err)
			}
			rule.PathRegex = re
		}

		switch {
		case strings.HasPrefix(r.Service, "http://"), strings.HasPrefix(r.Service, "https://"):
			u, err := url.Parse(r.Service)
			if err != nil {
				return nil, fmt.Errorf("ingress[%d]: service URL: %w", i, err)
			}
			rule.Kind = KindHTTP
			rule.TargetURL = u

		case strings.HasPrefix(r.Service, "tcp://"):
			rule.Kind = KindTCP
			rule.TargetAddr = strings.TrimPrefix(r.Service, "tcp://")

		case strings.HasPrefix(r.Service, "http_status:"):
			codeStr := strings.TrimPrefix(r.Service, "http_status:")
			code, err := strconv.Atoi(codeStr)
			if err != nil {
				return nil, fmt.Errorf("ingress[%d]: invalid http_status code %q: %w", i, codeStr, err)
			}
			rule.Kind = KindStatus
			rule.StatusCode = code

		default:
			return nil, fmt.Errorf("ingress[%d]: unsupported service %q", i, r.Service)
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

// Match returns the first rule whose Hostname matches host (exact match,
// case-insensitive) and whose PathRegex (if any) matches path, or the
// trailing catch-all rule (Hostname == "") if present, or false if
// nothing matches.
func (rules Rules) Match(host, path string) (Rule, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Strip a port, if the caller passed a Host header verbatim.
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		host = host[:i]
	}

	for _, r := range rules {
		if r.Hostname == "" {
			continue // catch-all, considered last below
		}
		if !strings.EqualFold(r.Hostname, host) {
			continue
		}
		if r.PathRegex != nil && !r.PathRegex.MatchString(path) {
			continue
		}
		return r, true
	}

	if len(rules) > 0 {
		if last := rules[len(rules)-1]; last.Hostname == "" {
			return last, true
		}
	}
	return Rule{}, false
}

// TCPRules returns every rule with a dedicated TCP listener, i.e. Kind ==
// KindTCP, each of which needs its own ListenPort.
func (rules Rules) TCPRules() []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Kind == KindTCP {
			out = append(out, r)
		}
	}
	return out
}

// Hostnames returns every non-empty Hostname across the rule set, in
// order, without duplicates.
func (rules Rules) Hostnames() []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range rules {
		if r.Hostname == "" || seen[r.Hostname] {
			continue
		}
		seen[r.Hostname] = true
		out = append(out, r.Hostname)
	}
	return out
}
