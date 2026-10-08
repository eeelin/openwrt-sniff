package nftset

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Spec struct{ Family, Table, Set string }

func ParseSpecs(value string) ([]Spec, error) {
	var result []Spec
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("invalid nft set %q, expected family:table:set", item)
		}
		result = append(result, Spec{parts[0], parts[1], parts[2]})
	}
	return result, nil
}

type Matcher struct {
	mu       sync.RWMutex
	specs    []Spec
	prefixes []netip.Prefix
	errors   map[string]string
}

func New(specs []Spec) *Matcher  { return &Matcher{specs: specs} }
func (m *Matcher) Enabled() bool { return len(m.specs) > 0 }

func (m *Matcher) Contains(address netip.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, prefix := range m.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (m *Matcher) Errors() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.errors) == 0 {
		return nil
	}
	result := make(map[string]string, len(m.errors))
	for key, value := range m.errors {
		result[key] = value
	}
	return result
}

func (m *Matcher) Run(ctx context.Context) {
	if !m.Enabled() {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Refresh(ctx)
		}
	}
}

func (m *Matcher) Refresh(ctx context.Context) {
	var prefixes []netip.Prefix
	errorsBySet := make(map[string]string)
	for _, spec := range m.specs {
		key := spec.Family + ":" + spec.Table + ":" + spec.Set
		commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		output, err := exec.CommandContext(commandCtx, "nft", "-j", "list", "set", spec.Family, spec.Table, spec.Set).CombinedOutput()
		cancel()
		if err != nil {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			errorsBySet[key] = message
			continue
		}
		parsed, err := parsePrefixes(output)
		if err != nil {
			errorsBySet[key] = err.Error()
			continue
		}
		prefixes = append(prefixes, parsed...)
	}
	m.mu.Lock()
	m.prefixes, m.errors = prefixes, errorsBySet
	m.mu.Unlock()
}

func parsePrefixes(data []byte) ([]netip.Prefix, error) {
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	seen := make(map[netip.Prefix]struct{})
	var result []netip.Prefix
	var walk func(any)
	add := func(prefix netip.Prefix) {
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			result = append(result, prefix)
		}
	}
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			if address, err := netip.ParseAddr(typed); err == nil {
				add(netip.PrefixFrom(address, address.BitLen()))
			}
			if prefix, err := netip.ParsePrefix(typed); err == nil {
				add(prefix)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			if rawPrefix, ok := typed["prefix"].(map[string]any); ok {
				address, aok := rawPrefix["addr"].(string)
				length, lok := rawPrefix["len"].(float64)
				if parsed, err := netip.ParseAddr(address); aok && lok && err == nil && length >= 0 && length <= float64(parsed.BitLen()) && length == float64(int(length)) {
					add(netip.PrefixFrom(parsed, int(length)))
				}
				return
			}
			if rawElem, ok := typed["elem"]; ok {
				walk(rawElem)
				return
			}
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(document)
	return result, nil
}
