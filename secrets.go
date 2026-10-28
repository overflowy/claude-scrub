package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type secret struct {
	value string
	label string
	prio  int
}

// collector gathers candidates from many goroutines and settles on one label
// per value.
type collector struct {
	mu     sync.Mutex
	counts map[string]map[string]int // value -> label -> times seen
	prios  map[string]int            // value -> best priority
	labelP map[string]map[string]int // value -> label -> best priority
}

func newCollector() *collector {
	return &collector{
		counts: map[string]map[string]int{},
		prios:  map[string]int{},
		labelP: map[string]map[string]int{},
	}
}

func (c *collector) add(cd candidate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[cd.value] == nil {
		c.counts[cd.value] = map[string]int{}
		c.labelP[cd.value] = map[string]int{}
		c.prios[cd.value] = cd.prio
	}
	c.counts[cd.value][cd.label]++
	if p, ok := c.labelP[cd.value][cd.label]; !ok || cd.prio < p {
		c.labelP[cd.value][cd.label] = cd.prio
	}
	if cd.prio < c.prios[cd.value] {
		c.prios[cd.value] = cd.prio
	}
}

// secrets returns one secret per value, minus the allowlist, sorted by label
// then value. A value's label is the one from its most trusted source, then
// the most frequent, then the first alphabetically.
func (c *collector) secrets(allow *allowlist) []secret {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []secret
	for value, labels := range c.counts {
		best := c.prios[value]
		label, n := "", -1
		for l, cnt := range labels {
			if c.labelP[value][l] != best {
				continue
			}
			if cnt > n || (cnt == n && l < label) {
				label, n = l, cnt
			}
		}
		if allow.blocks(value, label) {
			continue
		}
		out = append(out, secret{value: value, label: label, prio: best})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].label != out[j].label {
			return out[i].label < out[j].label
		}
		return out[i].value < out[j].value
	})
	return out
}

// allowlist holds values and labels never to redact.
type allowlist struct {
	values map[string]bool
	labels map[string]bool
}

func (a *allowlist) blocks(value, label string) bool {
	return a.values[value] || a.labels[label]
}

// loadAllowlist reads one value per line; "label:NAME" skips a whole label.
// Blank lines and lines starting with # are ignored.
func loadAllowlist(path string, required bool) (*allowlist, error) {
	a := &allowlist{values: map[string]bool{}, labels: map[string]bool{}}
	err := readLines(path, required, func(line string) error {
		if l, ok := strings.CutPrefix(line, "label:"); ok {
			a.labels[labelFor(l)] = true
		} else {
			a.values[line] = true
		}
		return nil
	})
	return a, err
}

// loadSecretsFile reads trusted "label=value" lines. Every value is redacted
// whatever its shape, as long as it has at least 6 characters.
func loadSecretsFile(path string, required bool, c *collector) error {
	return readLines(path, required, func(line string) error {
		label, value, ok := strings.Cut(line, "=")
		value = unquote(strings.TrimSpace(value))
		if !ok || strings.TrimSpace(label) == "" || value == "" {
			return fmt.Errorf("expected label=value")
		}
		if len(value) < 6 {
			return fmt.Errorf("value for %q is shorter than 6 characters", strings.TrimSpace(label))
		}
		c.add(candidate{value: value, label: labelFor(label), prio: prioKnown})
		return nil
	})
}

var envLineRe = regexp.MustCompile(`^(?:-\s*)?["']?(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[=:]\s*(.*)$`)

// loadEnvFile pulls secrets out of a .env, shell or YAML file. Values of
// secret-looking names only need 6 characters; any other value has to pass
// the same check as a value found in history, so DB_HOST=localhost stays.
func loadEnvFile(path string, c *collector) error {
	return readLines(path, true, func(line string) error {
		m := envLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil
		}
		name, value := m[1], unquote(strings.TrimSpace(m[2]))
		if secretNameRe.MatchString(name) && len(value) >= 6 && !isPlaceholder(value) {
			c.add(candidate{value: value, label: labelFor(name), prio: prioKnown})
		} else if plausibleSecret(value) && charClasses(value) >= 3 {
			c.add(candidate{value: value, label: labelFor(name), prio: prioKnown})
		}
		return nil
	})
}

// unquote strips one pair of matching quotes, and a trailing quote left over
// from a YAML list item such as - "KEY=value".
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return strings.TrimRight(s, `"'`)
}

func readLines(path string, required bool, fn func(string) error) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := fn(line); err != nil {
			return fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	return sc.Err()
}
