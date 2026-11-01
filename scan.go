package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDepth is how many levels of JSON inside JSON strings are looked through. A
// session reading an old transcript already holds JSON three levels down.
const maxDepth = 5

// literal is a JSON string literal; start and end are raw byte offsets
// including the quotes.
type literal struct {
	start, end int
	isKey      bool
	key        string // decoded key when this literal is the direct value of one
}

// scanJSON calls fn for every string literal in data, which may hold several
// JSON documents (JSONL). It does not validate the grammar; it only needs to
// tell strings apart from structure. It returns false if a string literal is
// left unterminated, in which case the caller should treat data as raw text.
func scanJSON(data []byte, fn func(lit literal)) bool {
	pendingKey := ""
	pendingAt := -1 // offset just past the colon following pendingKey
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(data) && data[j] != '"' {
			if data[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(data) {
			return false
		}
		end := j + 1

		k := end
		for k < len(data) && isJSONSpace(data[k]) {
			k++
		}
		isKey := k < len(data) && data[k] == ':'

		lit := literal{start: i, end: end, isKey: isKey}
		if !isKey && pendingAt >= 0 && onlySpace(data[pendingAt:i]) {
			lit.key = pendingKey
		}
		fn(lit)

		pendingAt = -1
		if isKey {
			pendingKey = decodeJSONString(data[i:end])
			pendingAt = k + 1
		}
		i = end - 1
	}
	return true
}

func isJSONSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func onlySpace(b []byte) bool {
	for _, c := range b {
		if !isJSONSpace(c) {
			return false
		}
	}
	return true
}

// looksLikeJSON reports whether data starts, after whitespace, like a JSON
// object or array.
func looksLikeJSON(data []byte) bool {
	for _, b := range data {
		if isJSONSpace(b) {
			continue
		}
		return b == '{' || b == '['
	}
	return false
}

// decodeJSONString decodes a raw JSON string literal, quotes included. Invalid
// escapes are kept as they are and lone surrogates become U+FFFD.
func decodeJSONString(raw []byte) string {
	return decodeBody(raw[1 : len(raw)-1])
}

// writeDecoded writes value, the decoded form of raw, followed by what further
// decoding reveals: JSON inside a JSON string can spell a value with an escape
// jsonEscape would not write, and the rules stop at the backslash.
func writeDecoded(sb *strings.Builder, raw []byte, value string) {
	sb.WriteString(value)
	sb.WriteByte('\n')
	// Such an escape in value is in raw too, so most literals stop here
	if !hasOtherEscape(raw) {
		return
	}
	cur := []byte(value)
	for range maxDepth - 1 {
		if !hasOtherEscape(cur) {
			return
		}
		next := decodeInto(cur, nil)
		if bytes.Equal(next, cur) {
			return
		}
		sb.Write(next)
		sb.WriteByte('\n')
		cur = next
	}
}

// writeRawUnit writes a unit that scanJSON cannot fully account for, as is and
// decoded: it may hold secrets outside any string it could read.
func writeRawUnit(sb *strings.Builder, unit []byte) {
	sb.Write(unit)
	sb.WriteByte('\n')
	if slices.Contains(unit, '\\') {
		writeDecoded(sb, unit, decodeBody(unit))
	}
}

// eachUnit calls fn with each part of data to parse on its own, and its offset.
// Strings in valid JSON cannot span lines, so apart from a valid document data
// goes line by line: a line cut short by a crash then only affects itself,
// instead of pairing up the quotes of every line after it the wrong way.
func eachUnit(data []byte, kind fileKind, fn func(unit []byte, base int)) {
	if kind == kindJSONDoc && json.Valid(data) {
		fn(data, 0)
		return
	}
	for start := 0; start < len(data); {
		end := len(data)
		if i := bytes.IndexByte(data[start:], '\n'); i >= 0 {
			end = start + i
		}
		if end > start {
			fn(data[start:end], start)
		}
		start = end + 1
	}
}

// decodeBody decodes the body of a JSON string, without its quotes.
func decodeBody(body []byte) string {
	if !slices.Contains(body, '\\') {
		return string(body)
	}
	return string(decodeInto(body, nil))
}

// decodeMapped decodes the body of a JSON string like decodeBody, and also
// returns where each decoded byte came from: offs[i] is the offset in body of
// the escape or byte that produced byte i, and offs[len(out)] is len(body).
// Offsets always fall on escape boundaries.
func decodeMapped(body []byte) (out []byte, offs []int) {
	offs = make([]int, 0, len(body)+1)
	out = decodeInto(body, &offs)
	return out, append(offs, len(body))
}

// decodeInto decodes body, and records the offsets of decodeMapped if asked.
func decodeInto(body []byte, offs *[]int) []byte {
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); {
		before, n := len(out), 1
		if body[i] == '\\' && i+1 < len(body) {
			out, n = appendEscape(out, body[i:])
		} else {
			out = append(out, body[i])
		}
		if offs != nil {
			for range len(out) - before {
				*offs = append(*offs, i)
			}
		}
		i += n
	}
	return out
}

// appendEscape decodes the escape at the start of b, which holds a backslash
// and at least one more byte. It returns dst with the result appended and the
// number of bytes consumed.
func appendEscape(dst, b []byte) ([]byte, int) {
	switch b[1] {
	case '"', '\\', '/':
		return append(dst, b[1]), 2
	case 'b':
		return append(dst, '\b'), 2
	case 'f':
		return append(dst, '\f'), 2
	case 'n':
		return append(dst, '\n'), 2
	case 'r':
		return append(dst, '\r'), 2
	case 't':
		return append(dst, '\t'), 2
	case 'u':
		if r, n := decodeUnicodeEscape(b); n > 0 {
			return utf8.AppendRune(dst, r), n
		}
	}
	return append(dst, b[0], b[1]), 2
}

// decodeUnicodeEscape decodes \uXXXX (and a following low surrogate) at the
// start of b. It returns the rune and the number of bytes consumed, or 0.
func decodeUnicodeEscape(b []byte) (rune, int) {
	r1, ok := hex4(b)
	if !ok {
		return 0, 0
	}
	if utf16.IsSurrogate(r1) {
		if len(b) >= 12 {
			if r2, ok := hex4(b[6:]); ok {
				if r := utf16.DecodeRune(r1, r2); r != utf8.RuneError {
					return r, 12
				}
			}
		}
		return utf8.RuneError, 6
	}
	return r1, 6
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
		return 0, false
	}
	var r rune
	for _, c := range b[2:6] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

// jsonEscape escapes s the way JavaScript's JSON.stringify does, without the
// surrounding quotes. Claude Code writes its files with JSON.stringify.
func jsonEscape(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				const hexDigits = "0123456789abcdef"
				sb.WriteString(`\u00`)
				sb.WriteByte(hexDigits[r>>4])
				sb.WriteByte(hexDigits[r&0xf])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}
