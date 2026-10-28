package main

import (
	"bytes"
	"encoding/json"
	"sort"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// form is one way a secret can be written in a file: as is, escaped once
// (inside a JSON string) or twice (JSON inside a JSON string).
type form struct {
	text   string
	secret int
}

type replacer struct {
	secrets []secret
	forms   []form
	trie    *ahocorasick.Trie
}

func newReplacer(secrets []secret) *replacer {
	r := &replacer{secrets: secrets}
	var patterns []string
	for i, s := range secrets {
		seen := map[string]bool{}
		for _, f := range []string{s.value, jsonEscape(s.value), jsonEscape(jsonEscape(s.value))} {
			if !seen[f] {
				seen[f] = true
				r.forms = append(r.forms, form{text: f, secret: i})
				patterns = append(patterns, f)
			}
		}
	}
	if len(patterns) > 0 {
		r.trie = ahocorasick.NewTrieBuilder().AddStrings(patterns).Build()
	}
	return r
}

func (r *replacer) placeholder(secret int) string {
	return "[REDACTED:" + r.secrets[secret].label + "]"
}

type hit struct {
	start, end int
	secret     int
}

// find returns the non-overlapping occurrences in b, leftmost first and the
// longest at each position. With escaped set, b is JSON and an occurrence
// right after an odd run of backslashes is skipped: its first character
// belongs to an escape sequence, so cutting there would corrupt the string.
func (r *replacer) find(b []byte, escaped bool) []hit {
	if r.trie == nil {
		return nil
	}
	var hits []hit
	for _, m := range r.trie.Match(b) {
		f := r.forms[m.Pattern()]
		start := int(m.Pos())
		if escaped && oddBackslashesBefore(b, start) {
			continue
		}
		hits = append(hits, hit{start: start, end: start + len(f.text), secret: f.secret})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end > hits[j].end
	})
	out := hits[:0]
	end := -1
	for _, h := range hits {
		if h.start >= end {
			out = append(out, h)
			end = h.end
		}
	}
	return out
}

func oddBackslashesBefore(b []byte, i int) bool {
	n := 0
	for i--; i >= 0 && b[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// fileKind says how a file's bytes are laid out.
type fileKind int

const (
	kindText      fileKind = iota
	kindJSONLines          // one JSON document per line
	kindJSONDoc            // a single JSON document
)

type redaction struct {
	out    []byte
	counts map[int]int // secret index -> occurrences
	// Lines (or the document) left untouched because redacting them would
	// have made valid JSON invalid
	skipped int
}

// redact replaces every occurrence of a secret in data with its placeholder.
func (r *replacer) redact(data []byte, kind fileKind) redaction {
	res := redaction{counts: map[int]int{}}
	hits := r.find(data, kind != kindText)
	if len(hits) == 0 {
		res.out = data
		return res
	}

	switch kind {
	case kindText:
		res.out = r.apply(data, hits, res.counts)
	case kindJSONDoc:
		out := r.apply(data, hits, map[int]int{})
		if json.Valid(data) && !json.Valid(out) {
			res.out, res.skipped = data, 1
			return res
		}
		res.out = r.apply(data, hits, res.counts)
	case kindJSONLines:
		var buf bytes.Buffer
		buf.Grow(len(data))
		lineStart := 0
		for len(hits) > 0 {
			// The line holding the next hit
			ls := lineStart + bytes.LastIndexByte(data[lineStart:hits[0].start], '\n') + 1
			le := len(data)
			if i := bytes.IndexByte(data[hits[0].start:], '\n'); i >= 0 {
				le = hits[0].start + i
			}
			n := 0
			for n < len(hits) && hits[n].start < le {
				n++
			}
			// A multi-line secret cannot sit inside one JSON line
			var lineHits []hit
			for _, h := range hits[:n] {
				if h.end <= le {
					lineHits = append(lineHits, hit{start: h.start - ls, end: h.end - ls, secret: h.secret})
				}
			}
			hits = hits[n:]

			line := data[ls:le]
			counts := map[int]int{}
			newLine := r.apply(line, lineHits, counts)
			buf.Write(data[lineStart:ls])
			if json.Valid(line) && !json.Valid(newLine) {
				buf.Write(line)
				res.skipped++
			} else {
				buf.Write(newLine)
				for k, v := range counts {
					res.counts[k] += v
				}
			}
			lineStart = le
		}
		buf.Write(data[lineStart:])
		res.out = buf.Bytes()
	}
	return res
}

func (r *replacer) apply(data []byte, hits []hit, counts map[int]int) []byte {
	var buf bytes.Buffer
	buf.Grow(len(data))
	prev := 0
	for _, h := range hits {
		buf.Write(data[prev:h.start])
		buf.WriteString(r.placeholder(h.secret))
		counts[h.secret]++
		prev = h.end
	}
	buf.Write(data[prev:])
	return buf.Bytes()
}
