package main

import (
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

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
	body := raw[1 : len(raw)-1]
	if !slices.Contains(body, '\\') {
		return string(body)
	}
	var sb strings.Builder
	sb.Grow(len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' || i+1 >= len(body) {
			sb.WriteByte(c)
			continue
		}
		i++
		switch body[i] {
		case '"', '\\', '/':
			sb.WriteByte(body[i])
		case 'b':
			sb.WriteByte('\b')
		case 'f':
			sb.WriteByte('\f')
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case 'u':
			r, n := decodeUnicodeEscape(body[i-1:])
			if n == 0 {
				sb.WriteByte('\\')
				sb.WriteByte('u')
				continue
			}
			sb.WriteRune(r)
			i += n - 2
		default:
			sb.WriteByte('\\')
			sb.WriteByte(body[i])
		}
	}
	return sb.String()
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
