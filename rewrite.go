package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// form is one way a secret can be written in a file: as is, or escaped once for
// each level of JSON string it sits in.
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
		f := s.value
		for range maxDepth + 1 {
			if !seen[f] {
				seen[f] = true
				r.forms = append(r.forms, form{text: f, secret: i})
				patterns = append(patterns, f)
			}
			f = jsonEscape(f)
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
	joined     []int // other secrets whose tails this hit was extended over
}

// shift returns h with its offsets moved back by n.
func (h hit) shift(n int) hit {
	h.start -= n
	h.end -= n
	return h
}

// countHits adds each hit to counts.
func countHits(counts map[int]int, hits []hit) {
	for _, h := range hits {
		counts[h.secret]++
		for _, s := range h.joined {
			counts[s]++
		}
	}
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
	return mergeHits(hits)
}

// mergeHits sorts hits and joins the overlapping ones, leftmost first. Dropping
// the second of two that overlap would leave its tail in the file.
func mergeHits(hits []hit) []hit {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end > hits[j].end
	})
	out := hits[:0]
	for _, h := range hits {
		if len(out) == 0 || h.start >= out[len(out)-1].end {
			out = append(out, h)
			continue
		}
		last := &out[len(out)-1]
		if h.end > last.end {
			last.end = h.end
			for _, s := range append([]int{h.secret}, h.joined...) {
				if s != last.secret && !slices.Contains(last.joined, s) {
					last.joined = append(last.joined, s)
				}
			}
		}
	}
	return out
}

// findAll returns every occurrence in data, however it is spelled.
func (r *replacer) findAll(data []byte, kind fileKind) []hit {
	return mergeHits(append(r.find(data, kind != kindText), r.findDecoded(data, kind)...))
}

// findDecoded returns the occurrences that only show once text is decoded,
// because it spells a character in a way jsonEscape never does: \u00e4 for ä or
// \/ for /. It looks inside JSON strings, and treats anything else as one body:
// text files, lines that are not JSON and lines cut short. Cuts fall on escape
// boundaries, so they cannot corrupt the string they are in.
func (r *replacer) findDecoded(data []byte, kind fileKind) []hit {
	if r.trie == nil || !hasOtherEscape(data) {
		return nil
	}
	var hits []hit
	eachUnit(data, kind, func(unit []byte, base int) {
		if kind == kindText || !looksLikeJSON(unit) {
			hits = append(hits, r.findInBody(unit, base)...)
			return
		}
		ok := scanJSON(unit, func(lit literal) {
			hits = append(hits, r.findInBody(unit[lit.start+1:lit.end-1], base+lit.start+1)...)
		})
		if !ok {
			hits = append(hits, r.findInBody(unit, base)...)
		}
	})
	return hits
}

// findInBody is findDecoded for the body of one JSON string, whose offsets
// start at base. It decodes up to maxDepth times, or until nothing changes.
func (r *replacer) findInBody(body []byte, base int) []hit {
	var hits []hit
	var toBody []int // offset in text -> offset in body
	text := body
	for range maxDepth {
		if !hasOtherEscape(text) {
			break
		}
		next, offs := decodeMapped(text)
		if bytes.Equal(next, text) {
			break
		}
		if toBody != nil {
			for i, o := range offs {
				offs[i] = toBody[o]
			}
		}
		text, toBody = next, offs
		for _, h := range r.find(text, false) {
			h.start, h.end = base+toBody[h.start], base+toBody[h.end]
			hits = append(hits, h)
		}
	}
	return hits
}

// keepNested splits the hits in unit, a line or document of JSON, into those to
// redact and those that would break JSON held inside a string. A match can begin
// on the n of an inner \n, and that is not the secret. Text inside a string that
// is not JSON has nothing to break, so a secret after a backslash there still
// goes.
func (r *replacer) keepNested(unit []byte, hits []hit) (kept, dropped []hit) {
	if !bytes.Contains(unit, []byte(`\"`)) || !json.Valid(unit) {
		return hits, nil
	}
	next := 0
	scanJSON(unit, func(lit literal) {
		for next < len(hits) && hits[next].start <= lit.start {
			kept = append(kept, hits[next])
			next++
		}
		first := next
		for next < len(hits) && hits[next].end < lit.end {
			next++
		}
		if first == next {
			return
		}
		k, d := r.splitCuts(unit[lit.start+1:lit.end-1], lit.start+1, hits[first:next])
		kept, dropped = append(kept, k...), append(dropped, d...)
	})
	return append(kept, hits[next:]...), dropped
}

// splitCuts is keepNested for the body of one string, whose offsets start at
// base. Almost always all of them are fine, which one check settles.
func (r *replacer) splitCuts(body []byte, base int, hits []hit) (kept, dropped []hit) {
	redacted := func(hs ...hit) []byte {
		shifted := make([]hit, len(hs))
		for i, h := range hs {
			shifted[i] = h.shift(base)
		}
		return r.apply(body, shifted, map[int]int{})
	}
	if !breaksNested(body, redacted(hits...), maxDepth) {
		return hits, nil
	}
	for _, h := range hits {
		if breaksNested(body, redacted(h), maxDepth) {
			dropped = append(dropped, h)
		} else {
			kept = append(kept, h)
		}
	}
	return kept, dropped
}

// breaksNested reports whether after, a changed copy of the JSON string body
// before, no longer decodes to valid JSON where before did, at any depth.
func breaksNested(before, after []byte, depth int) bool {
	if depth == 0 || bytes.Equal(before, after) {
		return false
	}
	b, a := decodeInto(before, nil), decodeInto(after, nil)
	if !json.Valid(b) {
		return false
	}
	if !json.Valid(a) {
		return true
	}
	bs, as := literalBodies(b), literalBodies(a)
	if len(bs) != len(as) {
		return false
	}
	for i := range bs {
		if breaksNested(bs[i], as[i], depth-1) {
			return true
		}
	}
	return false
}

func literalBodies(data []byte) [][]byte {
	var bodies [][]byte
	scanJSON(data, func(lit literal) {
		bodies = append(bodies, data[lit.start+1:lit.end-1])
	})
	return bodies
}

// snippet returns the part of text within around bytes of [start, end) with
// every secret redacted; hits are those findAll returned for text. The window is
// widened over any secret it would cut, as a fragment would match nothing.
func (r *replacer) snippet(text string, hits []hit, start, end, around int) string {
	lo, hi := max(0, start-around), min(len(text), end+around)
	for _, h := range hits {
		if h.start < lo && lo < h.end {
			lo = h.start
		}
		if h.start < hi && hi < h.end {
			hi = h.end
		}
	}
	var inside []hit
	for _, h := range hits {
		if h.start >= lo && h.end <= hi {
			inside = append(inside, h.shift(lo))
		}
	}
	return strings.ToValidUTF8(string(r.apply([]byte(text[lo:hi]), inside, map[int]int{})), "")
}

// hasOtherEscape reports whether b holds an escape jsonEscape would not write,
// or one that a further decode could turn into one.
func hasOtherEscape(b []byte) bool {
	return bytes.Contains(b, []byte(`\u`)) || bytes.Contains(b, []byte(`\/`))
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
	// Lines (or the document) with matches left in place because redacting them
	// would have made valid JSON invalid
	skipped int
	left    map[int]int // secret index -> occurrences left in place
}

// redact replaces every occurrence of a secret in data with its placeholder.
func (r *replacer) redact(data []byte, kind fileKind) redaction {
	res := redaction{counts: map[int]int{}, left: map[int]int{}}
	hits := r.findAll(data, kind)
	if len(hits) == 0 {
		res.out = data
		return res
	}

	switch kind {
	case kindText:
		res.out = r.apply(data, hits, res.counts)
	case kindJSONDoc:
		res.out, res.skipped = r.redactUnit(data, hits, res.counts, res.left)
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
			// A hit can start on the newline itself, ending this line
			for n < len(hits) && hits[n].start <= le {
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

			newLine, skipped := r.redactUnit(data[ls:le], lineHits, res.counts, res.left)
			buf.Write(data[lineStart:ls])
			buf.Write(newLine)
			res.skipped += skipped
			lineStart = le
		}
		buf.Write(data[lineStart:])
		res.out = buf.Bytes()
	}
	return res
}

// redactUnit redacts a line or document of JSON. A hit that would break JSON
// inside a string stays, and so does the whole unit if it would end up invalid.
// It returns the result, and 1 if anything was left in place.
func (r *replacer) redactUnit(unit []byte, hits []hit, counts, left map[int]int) ([]byte, int) {
	kept, dropped := r.keepNested(unit, hits)
	countHits(left, dropped)
	out := r.apply(unit, kept, map[int]int{})
	if json.Valid(unit) && !json.Valid(out) {
		countHits(left, kept)
		return unit, 1
	}
	countHits(counts, kept)
	if len(dropped) > 0 {
		return out, 1
	}
	return out, 0
}

func (r *replacer) apply(data []byte, hits []hit, counts map[int]int) []byte {
	var buf bytes.Buffer
	buf.Grow(len(data))
	prev := 0
	for _, h := range hits {
		buf.Write(data[prev:h.start])
		buf.WriteString(r.placeholder(h.secret))
		prev = h.end
	}
	countHits(counts, hits)
	buf.Write(data[prev:])
	return buf.Bytes()
}
