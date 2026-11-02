package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"

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
	joined     []int // other secrets inside this hit
	cont       bool  // a later part of an occurrence, counted at its first
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
		if !h.cont {
			counts[h.secret]++
		}
		for _, s := range h.joined {
			counts[s]++
		}
	}
}

// matches returns the occurrences in b, which can overlap. An occurrence right
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

// mergeHits sorts hits in place and returns them with the overlapping ones joined,
// leftmost first. Dropping the second of two that overlap would leave its tail in
// the file. Taking a joined hit apart again needs the sorted hits it came from.
func mergeHits(hits []hit) []hit {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end > hits[j].end
	})
	var out []hit
	for _, h := range hits {
		if len(out) == 0 || h.start >= out[len(out)-1].end {
			out = append(out, h)
			continue
		}
		last := &out[len(out)-1]
		last.end = max(last.end, h.end)
		if h.cont && h.secret != last.secret {
			h.secret = last.secret // nothing to count, so nothing to join
		}
		if h.secret == last.secret && !h.cont {
			last.cont = false
		}
		for _, s := range append([]int{h.secret}, h.joined...) {
			if s != last.secret && !slices.Contains(last.joined, s) {
				last.joined = append(last.joined, s)
			}
		}
	}
	return out
}

// occurrences returns every occurrence in data, however it is spelled, which can
// overlap. kind has to come from checkKind.
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
	if kind == kindJSONDoc {
		return func(int) bool { return true }
	}
	lastLine, lastValid := -1, false
	return func(at int) bool {
		if ls := lineStart(data, at); ls != lastLine {
			lastLine, lastValid = ls, json.Valid(data[ls:lineEnd(data, at)])
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
		if kind == kindText || !u.isValid() {
			hits = append(hits, r.findInBody(u.data, u.base)...)
			return
		}
		scanJSON(u.data, func(lit literal) {
			hits = append(hits, r.findInBody(u.data[lit.start+1:lit.end-1], u.base+lit.start+1)...)
		})
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
		for _, h := range r.matches(text, nil) {
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
	kindJSONDoc            // a single JSON document, valid once through checkKind
)

// checkKind settles kind now that data is at hand: JSON that holds together as one
// document is one, whatever the file is called, and anything else goes line by
// line. Lines of JSON fail this right after the first of them, so it costs little,
// and this one parse answers it for everything after.
func checkKind(data []byte, kind fileKind) fileKind {
	switch {
	case kind == kindText:
		return kindText
	case isStructuredJSON(data):
		return kindJSONDoc
	}
	return kindJSONLines
}

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
	kind = checkKind(data, kind)
	hits := r.occurrences(data, kind)
	if len(hits) == 0 {
		res.out = data
		return res
	}

	switch kind {
	case kindText:
		res.out = r.apply(data, mergeHits(hits), res.counts)
	case kindJSONDoc:
		var anyLeft bool
		res.out, anyLeft = r.redactUnit(data, 0, true, mergeHits(hits), hits, &res)
		if anyLeft {
			res.skipped = 1
		}
	default:
		r.redactLines(data, hits, &res)
	}
	return res
}

// redactLines redacts data line by line, for JSON lines and for a document too
// broken to treat as one. A hit across lines joins them, so it stays if it starts
// or ends on valid JSON, and goes around any such lines in between, which then
// count as left. It is taken out before hits are merged, so that what overlaps it
// on one line still goes.
func (r *replacer) redactLines(data []byte, occurrences []hit, res *redaction) {
	var single []hit
	leftLines := map[int]bool{}
	for _, h := range occurrences {
		if bytes.IndexByte(data[h.start:h.end], '\n') >= 0 && touchesJSONLine(data, h) {
			if parts, jsonLines := aroundJSONLines(data, h); parts != nil {
				single = append(single, parts...)
				countHits(res.left, []hit{h})
				for _, ls := range jsonLines {
					leftLines[ls] = true
				}
				continue
			}
			countHits(res.left, []hit{h})
			leftLines[lineStart(data, h.start)] = true
			continue
		}
		single = append(single, h)
	}
	hits := mergeHits(single)

	var buf bytes.Buffer
	buf.Grow(len(data))
	copied := 0
	for len(hits) > 0 {
		// The line holding the next hit, and those a hit runs on to
		ls := copied + bytes.LastIndexByte(data[copied:hits[0].start], '\n') + 1
		le := lineEnd(data, hits[0].start)
		n := 0
		// A hit can start on the newline itself, ending this line
		for n < len(hits) && hits[n].start <= le {
			if hits[n].end > le {
				le = lineEnd(data, hits[n].end)
			}
			n++
		}
		lineHits := make([]hit, n)
		for i, h := range hits[:n] {
			lineHits[i] = h.shift(ls)
		}
		hits = hits[n:]

		newLine, anyLeft := r.redactUnit(data[ls:le], ls, isStructuredJSON(data[ls:le]), lineHits, single, res)
		buf.Write(data[copied:ls])
		buf.Write(newLine)
		if anyLeft {
			leftLines[ls] = true
		}
		copied = le
	}
	buf.Write(data[copied:])
	res.out = buf.Bytes()
	res.skipped = len(leftLines)
}

// touchesJSONLine reports whether replacing h would change a line of valid JSON.
// Measured from h.end, this includes the line a final newline would join on.
func touchesJSONLine(data []byte, h hit) bool {
	for line := range bytes.SplitSeq(data[lineStart(data, h.start):lineEnd(data, h.end)], []byte{'\n'}) {
		if isStructuredJSON(line) {
			return true
		}
	}
	return false
}

// aroundJSONLines cuts h, which touches a line of valid JSON, into the parts between
// such lines, and returns where each of those lines starts. The parts are still one
// occurrence. It returns nil if h starts or ends on such a line, as replacing h would
// then change that line. Measured from h.end like touchesJSONLine.
func aroundJSONLines(data []byte, h hit) (parts []hit, jsonLines []int) {
	add := func(start, end int) {
		parts = append(parts, hit{start: start, end: end, secret: h.secret, cont: len(parts) > 0})
	}
	start := h.start
	for ls := lineStart(data, h.start); ; {
		le := lineEnd(data, ls)
		last := h.end <= le
		if isStructuredJSON(data[ls:le]) {
			if ls <= h.start || last {
				return nil, nil
			}
			if start < ls-1 {
				add(start, ls-1)
			}
			start = le + 1
			jsonLines = append(jsonLines, ls)
		}
		if last {
			break
		}
		ls = le + 1
	}
	if start < h.end {
		add(start, h.end)
	}
	return parts, jsonLines
}

// redactUnit redacts a line or document at offset base of the file, and isJSON
// says whether it is JSON to keep valid. A hit that would break that JSON, or JSON
// inside a string, stays. occurrences are the sorted hits of the file before they
// were joined. It returns the result, and whether anything was left in place.
func (r *replacer) redactUnit(unit []byte, base int, isJSON bool, hits, occurrences []hit, res *redaction) ([]byte, bool) {
	if !isJSON {
		return r.apply(unit, hits, res.counts), false
	}
	kept, dropped := r.keepNested(unit, hits)
	out := r.apply(unit, kept, map[int]int{})
	if len(dropped) > 0 || !json.Valid(out) {
		var bad []hit
		kept, bad = r.keepValid(unit, kept)
		kept, dropped = r.splitDropped(unit, base, occurrences, kept, append(dropped, bad...))
		out = r.apply(unit, kept, map[int]int{})
		// Each fine alone, but not together
		if !json.Valid(out) {
			dropped, kept, out = append(dropped, kept...), nil, unit
		}
	}
	countHits(res.counts, kept)
	countHits(res.left, dropped)
	return out, len(dropped) > 0
}

// allSafe reports whether every hit can go without breaking unit, a line or
// document of JSON, or JSON inside one of its strings.
func (r *replacer) allSafe(unit []byte, hits []hit) bool {
	kept, dropped := r.keepNested(unit, hits)
	return len(dropped) == 0 && json.Valid(r.apply(unit, kept, map[int]int{}))
}

// splitDropped takes apart the dropped hits that joined several secrets, as one
// that breaks the JSON would otherwise keep the others in the file too. A secret
// goes if all its occurrences in the hit can, along with those that went before
// it. Trying by secret keeps this cheap: each try parses the whole unit, and a
// secret overlapping itself can match at every byte of a long run.
func (r *replacer) splitDropped(unit []byte, base int, occurrences, kept, dropped []hit) (_, stay []hit) {
	for _, d := range dropped {
		if d.joined == nil {
			stay = append(stay, d)
			continue
		}
		first := sort.Search(len(occurrences), func(i int) bool { return occurrences[i].start >= d.start+base })
		var safe []hit
		for _, s := range append([]int{d.secret}, d.joined...) {
			var own []hit
			for _, o := range occurrences[first:] {
				if o.start >= d.end+base {
					break
				}
				if o.secret == s {
					own = append(own, o.shift(base))
				}
			}
			if try := mergeHits(slices.Concat(safe, own)); r.allSafe(unit, try) {
				safe = try
			} else {
				stay = append(stay, mergeHits(own)...)
			}
		}
		kept = append(kept, safe...)
	}
	// Nothing overlaps here, this only puts them back in order
	return mergeHits(kept), stay
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
