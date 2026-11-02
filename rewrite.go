package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"

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
// longest at each position.
func (r *replacer) find(b []byte) []hit {
	return mergeHits(r.matches(b, nil))
}

// matches is find before overlapping occurrences are joined. An occurrence right
// after an odd run of backslashes is skipped where isJSON says b is JSON: its
// first character belongs to an escape sequence, so cutting there would corrupt
// the string.
func (r *replacer) matches(b []byte, isJSON func(at int) bool) []hit {
	if r.trie == nil {
		return nil
	}
	var hits []hit
	for _, m := range r.trie.Match(b) {
		f := r.forms[m.Pattern()]
		start := int(m.Pos())
		if isJSON != nil && oddBackslashesBefore(b, start) && isJSON(start) {
			continue
		}
		hits = append(hits, hit{start: start, end: start + len(f.text), secret: f.secret})
	}
	return hits
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
	return mergeHits(r.occurrences(data, kind))
}

// occurrences is findAll before overlapping occurrences are joined.
func (r *replacer) occurrences(data []byte, kind fileKind) []hit {
	var isJSON func(int) bool
	if kind != kindText {
		isJSON = jsonAt(data, kind)
	}
	return append(r.matches(data, isJSON), r.findDecoded(data, kind)...)
}

// jsonAt returns a check for whether an offset in data sits in valid JSON. It is
// only asked about the rare match after a backslash, so it parses on demand and
// remembers the last line it saw.
func jsonAt(data []byte, kind fileKind) func(at int) bool {
	validDoc := sync.OnceValue(func() bool { return kind == kindJSONDoc && json.Valid(data) })
	lastLine, lastValid := -1, false
	return func(at int) bool {
		if validDoc() {
			return true
		}
		if ls := lineStartAt(data, at); ls != lastLine {
			lastLine, lastValid = ls, json.Valid(data[ls:lineEndAt(data, at)])
		}
		return lastValid
	}
}

// findDecoded returns the occurrences that only show once text is decoded,
// because it spells a character in a way jsonEscape never does: \u00e4 for ä or
// \/ for /. It looks inside JSON strings. Anything else is one body as well, as
// a secret can sit outside the strings: text files, lines that are not valid JSON
// and lines cut short. Cuts fall on escape boundaries, so they cannot corrupt the
// string they are in.
func (r *replacer) findDecoded(data []byte, kind fileKind) []hit {
	if r.trie == nil || !hasOtherEscape(data) {
		return nil
	}
	var hits []hit
	eachUnit(data, kind, func(u unit) {
		if !hasOtherEscape(u.data) {
			return
		}
		if kind == kindText {
			hits = append(hits, r.findInBody(u.data, u.base)...)
			return
		}
		whole := u.literals(func(lit literal) {
			hits = append(hits, r.findInBody(u.data[lit.start+1:lit.end-1], u.base+lit.start+1)...)
		})
		if !whole {
			hits = append(hits, r.findInBody(u.data, u.base)...)
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
		for _, h := range r.find(text) {
			h.start, h.end = base+toBody[h.start], base+toBody[h.end]
			hits = append(hits, h)
		}
	}
	return hits
}

// keepNested splits the hits in unit, a valid line or document of JSON, into
// those to redact and those that would break JSON held inside a string. A match
// can begin on the n of an inner \n, and that is not the secret. Text inside a
// string that is not JSON has nothing to break, so a secret after a backslash
// there still goes.
func (r *replacer) keepNested(unit []byte, hits []hit) (kept, dropped []hit) {
	if !bytes.Contains(unit, []byte(`\"`)) {
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
	if !isStructuredJSON(b) {
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

// isStructuredJSON reports whether b is JSON with something to protect. A bare
// number or word holds no escape and no quotes, so it is text like any other.
func isStructuredJSON(b []byte) bool {
	if !json.Valid(b) {
		return false
	}
	return looksLikeJSON(b) || bytes.TrimLeft(b, " \t\r\n")[0] == '"'
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
	hits := r.occurrences(data, kind)
	if len(hits) == 0 {
		res.out = data
		return res
	}

	switch {
	case kind == kindText:
		res.out = r.apply(data, mergeHits(hits), res.counts)
	case kind == kindJSONDoc && isStructuredJSON(data):
		var anyLeft bool
		res.out, anyLeft = r.redactUnit(data, true, mergeHits(hits), res.counts, res.left)
		if anyLeft {
			res.skipped = 1
		}
	default:
		r.redactLines(data, hits, &res)
	}
	return res
}

// redactLines redacts data line by line, for JSON lines and for a document too
// broken to treat as one. A hit across lines joins them, so it goes only if none
// of them is valid JSON. It is taken out before hits are merged, so that what
// overlaps it on one line still goes.
func (r *replacer) redactLines(data []byte, occurrences []hit, res *redaction) {
	var hits []hit
	leftLines := map[int]bool{}
	for _, h := range occurrences {
		if bytes.IndexByte(data[h.start:h.end], '\n') >= 0 && touchesJSONLine(data, h) {
			countHits(res.left, []hit{h})
			leftLines[lineStartAt(data, h.start)] = true
			continue
		}
		hits = append(hits, h)
	}
	hits = mergeHits(hits)

	var buf bytes.Buffer
	buf.Grow(len(data))
	lineStart := 0
	for len(hits) > 0 {
		// The line holding the next hit, and those a hit runs on to
		ls := lineStart + bytes.LastIndexByte(data[lineStart:hits[0].start], '\n') + 1
		le := lineEndAt(data, hits[0].start)
		n := 0
		// A hit can start on the newline itself, ending this line
		for n < len(hits) && hits[n].start <= le {
			if hits[n].end > le {
				le = lineEndAt(data, hits[n].end)
			}
			n++
		}
		lineHits := make([]hit, n)
		for i, h := range hits[:n] {
			lineHits[i] = h.shift(ls)
		}
		hits = hits[n:]

		newLine, anyLeft := r.redactUnit(data[ls:le], isStructuredJSON(data[ls:le]), lineHits, res.counts, res.left)
		buf.Write(data[lineStart:ls])
		buf.Write(newLine)
		if anyLeft {
			leftLines[ls] = true
		}
		lineStart = le
	}
	buf.Write(data[lineStart:])
	res.out = buf.Bytes()
	res.skipped = len(leftLines)
}

// lineStartAt returns the offset just past the last newline before i, or 0.
func lineStartAt(data []byte, i int) int {
	return bytes.LastIndexByte(data[:i], '\n') + 1
}

// lineEndAt returns the offset of the first newline at or after i, or len(data).
func lineEndAt(data []byte, i int) int {
	if j := bytes.IndexByte(data[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(data)
}

// touchesJSONLine reports whether replacing h would change a line of valid JSON.
// Measured from h.end, this includes the line a final newline would join on.
func touchesJSONLine(data []byte, h hit) bool {
	for line := range bytes.SplitSeq(data[lineStartAt(data, h.start):lineEndAt(data, h.end)], []byte{'\n'}) {
		if isStructuredJSON(line) {
			return true
		}
	}
	return false
}

// redactUnit redacts a line or document, and isJSON says whether it is JSON to
// keep valid. A hit that would break that JSON, or JSON inside a string, stays.
// It returns the result, and whether anything was left in place.
func (r *replacer) redactUnit(unit []byte, isJSON bool, hits []hit, counts, left map[int]int) ([]byte, bool) {
	if !isJSON {
		return r.apply(unit, hits, counts), false
	}
	kept, dropped := r.keepNested(unit, hits)
	out := r.apply(unit, kept, map[int]int{})
	if !json.Valid(out) {
		var bad []hit
		kept, bad = r.keepValid(unit, kept)
		dropped = append(dropped, bad...)
		out = r.apply(unit, kept, map[int]int{})
		// Each fine alone, but not together
		if !json.Valid(out) {
			dropped, kept, out = append(dropped, kept...), nil, unit
		}
	}
	countHits(counts, kept)
	countHits(left, dropped)
	return out, len(dropped) > 0
}

// keepValid splits hits into those that leave unit valid JSON and those that do
// not. Halving keeps a few bad hits among many in a large document cheap.
func (r *replacer) keepValid(unit []byte, hits []hit) (kept, dropped []hit) {
	if json.Valid(r.apply(unit, hits, map[int]int{})) {
		return hits, nil
	}
	if len(hits) == 1 {
		return nil, hits
	}
	mid := len(hits) / 2
	k1, d1 := r.keepValid(unit, hits[:mid])
	k2, d2 := r.keepValid(unit, hits[mid:])
	return slices.Concat(k1, k2), slices.Concat(d1, d2)
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
