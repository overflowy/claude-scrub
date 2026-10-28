package main

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"unicode"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// Source priority: when one value is found by several sources, the label of
// the most trusted one wins.
const (
	prioKnown    = iota // the secrets file and --env-file
	prioName            // a value assigned to a secret-looking name
	prioPattern         // URL credentials, Authorization headers
	prioGitleaks        // gitleaks rules
)

type candidate struct {
	value string
	label string
	prio  int
}

// Names ending in one of these words hold secrets. Bare "key" and "auth" are
// left out: primary_key, sort_key and author are far more common than secrets.
const secretWords = `password|passwd|passphrase|secret|token|credentials?|dsn|apikey|` +
	`(?:api|access|secret|private|auth|account|storage|master|encryption|signing|` +
	`license|service|sas|subscription|app|client|webhook|deploy|session)[_\-.]?key`

// Every secret word contains one of these
var secretStems = []string{"pass", "secret", "token", "key", "cred", "dsn"}

var (
	// The whole string is a secret-looking name
	secretNameRe = regexp.MustCompile(`^(?:[A-Za-z0-9]+[_\-.]?)*?(?i:` + secretWords + `)$`)

	// What follows a secret-looking name in NAME = value, NAME: value,
	// "name": "value" or NAME => value. Spaces only: across a newline the
	// "value" is the next line of code (if token:\n    return ...) or a
	// nested YAML block.
	assignValueRe = regexp.MustCompile(`^\\*["'“”‘’]?[ \t]*(?:=>|:=|=|:)[ \t]*\\*["'“”‘’]?` +
		"([^\\s\"'“”‘’\\\\`<>(){}\\[\\],;&]{8,})")

	// scheme://user:password@host
	urlCredsRe = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@"'\\]*:([^\s@/"'\\]{6,})@`)

	// Authorization: Bearer xxx / Basic xxx
	authHeaderRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+([A-Za-z0-9\-_.~+/]{16,}=*)`)

	// The secret-looking name at the start of a gitleaks generic-api-key
	// match. Looser than secretWords: any *Auth, and key on its own or after
	// a separator (Key, X-Api-Key, but not valkey or monkey)
	matchNameRe = regexp.MustCompile(`^[^A-Za-z0-9]*((?:[A-Za-z0-9]+[_\-.]?)*?(?i:` + secretWords + `|auth)|(?:[A-Za-z0-9]+[_\-.])*(?i:key))` +
		`\\*["']?\s*(?:=>|:=|=|:)`)

	dateLikeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
	// Starts with member access (e.tokens.length-1, v.secret?.trim)
	memberRe     = regexp.MustCompile(`^[A-Za-z_$][\w$]{0,15}(?:\.[A-Za-z_$][\w$]{0,15})+(?:[^\w$.]|$)`)
	identPartRe  = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	camelBoundRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	nonLabelRe   = regexp.MustCompile(`[^a-z0-9]+`)

	stemTrie = ahocorasick.NewTrieBuilder().AddStrings(secretStems).Build()
)

// Values containing one of these are examples or already redacted
var placeholderWords = []string{
	"redacted", "example", "placeholder", "your_", "your-", "yourkey", "changeme",
	"xxxxxx", "******", "...", "…", "<", ">", "dummy", "lorem",
}

// Every match of the rules in scanLine has one of these on its line
var ownKeywords = append(slices.Clone(secretStems), "://", "bearer", "basic")

func init() {
	logging.Logger = zerolog.Nop()
}

// keywordLine is a line of text holding a keyword, widened for the few
// rules that match across lines.
type keywordLine struct {
	text  string
	lower string // text with ASCII letters lowercased, same offsets
	own   bool   // holds one of ownKeywords, so scanLine can match
}

func (l keywordLine) size() int { return len(l.text) }

// lineFinder picks the lines worth running regexes on. It is safe for
// concurrent use.
type lineFinder struct {
	keywords *ahocorasick.Trie
}

// newLineFinder indexes ownKeywords and, given a gitleaks detector, every
// keyword of its rules.
func newLineFinder(gl *detect.Detector) *lineFinder {
	keywords := slices.Clone(ownKeywords)
	if gl != nil {
		seen := map[string]bool{}
		for _, k := range ownKeywords {
			seen[k] = true
		}
		for _, r := range gl.Config.Rules {
			for _, k := range r.Keywords {
				if k = strings.ToLower(k); !seen[k] {
					seen[k] = true
					keywords = append(keywords, k)
				}
			}
		}
	}
	return &lineFinder{keywords: ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()}
}

// lines returns the lines of text holding a keyword, which is all the
// regexes need: every rule (gitleaks' too, bar one matching file names)
// requires one of its keywords in what it matches. On transcripts this drops
// most of the text before any regex runs. Lines are widened for the gitleaks
// rules that span lines (see widen).
func (f *lineFinder) lines(text string) []keywordLine {
	lower := []byte(text)
	for i, c := range lower {
		if 'A' <= c && c <= 'Z' {
			lower[i] = c + 'a' - 'A'
		}
	}
	type span struct {
		start, end int
		own        bool
	}
	var spans []span
	// Lines over maxSpan (minified bundles run to megabytes) are cut into
	// windows around each keyword: a regex on a whole one takes seconds and
	// holds up the run
	addWindow := func(ls, le, at, n int, own bool) {
		ws, we := max(ls, at-windowMargin), min(le, at+n+windowMargin)
		// Start on a token boundary, so the cut cannot make up a name
		for ws > ls && at-ws < windowMargin+128 && isNameByte(text[ws-1]) {
			ws--
		}
		if len(spans) > 0 {
			last := &spans[len(spans)-1]
			if ws <= last.end && we-last.start <= maxSpan {
				last.end, last.own = max(last.end, we), last.own || own
				return
			}
		}
		spans = append(spans, span{start: ws, end: we, own: own})
	}
	lineStartAt, lineEndAt := -1, -1 // the line of the last hit
	f.keywords.Walk(lower, func(end, n, pattern int64) bool {
		at := int(end - n + 1)
		own := pattern < int64(len(ownKeywords))
		if at < lineEndAt {
			if lineEndAt-lineStartAt > maxSpan {
				addWindow(lineStartAt, lineEndAt, at, int(n), own)
			} else {
				last := &spans[len(spans)-1]
				last.own = last.own || own
			}
			return true
		}
		lineStartAt, lineEndAt = lineStart(text, at), lineEnd(text, at)
		if lineEndAt-lineStartAt > maxSpan {
			addWindow(lineStartAt, lineEndAt, at, int(n), own)
			return true
		}
		ls, le := widen(text, lower, lineStartAt, lineEndAt)
		if len(spans) > 0 && ls <= spans[len(spans)-1].end {
			last := &spans[len(spans)-1]
			last.end, last.own = max(last.end, le), last.own || own
			return true
		}
		spans = append(spans, span{start: ls, end: le, own: own})
		return true
	})
	lowerText := string(lower)
	lines := make([]keywordLine, len(spans))
	for i, sp := range spans {
		lines[i] = keywordLine{text: text[sp.start:sp.end], lower: lowerText[sp.start:sp.end], own: sp.own}
	}
	return lines
}

const (
	maxKeyBlock = 16 * 1024
	maxSpan     = 64 * 1024
	// Text kept either side of a keyword in a long line; far more than any
	// match needs (values are capped at 512 bytes, gitleaks' at a few hundred)
	windowMargin = 4 * 1024
)

// widen grows the line [ls, le) to cover what the gitleaks rules that span
// lines can match from it: a private key block to its end, a curl command
// over the next 5 lines (curl-auth-user, curl-auth-header), and a Kubernetes
// Secret 300 bytes either way (kubernetes-secret-yaml).
func widen(text string, lower []byte, ls, le int) (int, int) {
	line := lower[ls:le]
	if b := bytes.Index(line, []byte("-----begin")); b >= 0 {
		// Key blocks are a few KB; without an end nearby this is not one
		if e := bytes.Index(lower[ls+b:min(len(lower), ls+b+maxKeyBlock)], []byte("-----end")); e >= 0 {
			le = max(le, lineEnd(text, ls+b+e))
		}
	}
	if bytes.Contains(line, []byte("curl")) {
		end := le
		for range 5 {
			if end >= len(text) {
				break
			}
			end = lineEnd(text, end+1)
		}
		le = max(le, end)
	}
	if bytes.Contains(line, []byte("kind:")) && bytes.Contains(line, []byte("secret")) {
		ls = lineStart(text, max(0, ls-300))
		le = max(le, lineEnd(text, min(len(text), le+300)))
	}
	return ls, le
}

func lineStart(text string, at int) int {
	return strings.LastIndexByte(text[:at], '\n') + 1
}

func lineEnd(text string, from int) int {
	if i := strings.IndexByte(text[from:], '\n'); i >= 0 {
		return from + i
	}
	return len(text)
}

// detector runs the rules over lines. It is not safe for concurrent use;
// create one per goroutine.
type detector struct {
	gl *detect.Detector // nil when gitleaks is disabled
}

func newDetector(useGitleaks bool) (*detector, error) {
	if !useGitleaks {
		return &detector{}, nil
	}
	gl, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, err
	}
	// Decoded base64 or hex secrets never appear verbatim in the file, so
	// they could not be redacted anyway
	gl.MaxDecodeDepth = 0
	return &detector{gl: gl}, nil
}

// scanLines runs the rules over each line. Line by line, gitleaks only tries
// the rules whose keywords the line holds.
func (d *detector) scanLines(lines []keywordLine, add func(candidate)) {
	for _, line := range lines {
		if line.own {
			scanLine(line, add)
		}
		if d.gl != nil {
			d.scanGitleaks(line.text, add)
		}
	}
}

// scan runs the rules over a whole text.
func (d *detector) scan(f *lineFinder, text string, add func(candidate)) {
	d.scanLines(f.lines(text), add)
}

func scanLine(line keywordLine, add func(candidate)) {
	scanAssignments(line, add)
	if strings.Contains(line.lower, "://") {
		for _, m := range urlCredsRe.FindAllStringSubmatch(line.text, -1) {
			if plausibleSecret(m[1]) {
				add(candidate{value: m[1], label: "url_password", prio: prioPattern})
			}
		}
	}
	if strings.Contains(line.lower, "bearer") || strings.Contains(line.lower, "basic") {
		for _, m := range authHeaderRe.FindAllStringSubmatch(line.text, -1) {
			if plausibleSecret(m[2]) {
				add(candidate{value: m[2], label: strings.ToLower(m[1]) + "_auth", prio: prioPattern})
			}
		}
	}
}

// scanAssignments finds values assigned to secret-looking names. It starts
// from each secret word in the line rather than running one big regex, which
// Go's engine would have to try at every byte: it takes the name around the
// word, checks the name ends in a secret word, then matches the delimiter
// and value right after it.
func scanAssignments(line keywordLine, add func(candidate)) {
	text := line.text
	nameEnd := -1
	stemTrie.Walk([]byte(line.lower), func(end, _, _ int64) bool {
		e := int(end) + 1
		for e < len(text) && isAlnum(text[e]) {
			e++
		}
		if e == nameEnd {
			return true // the same name, seen through another stem
		}
		nameEnd = e
		s := e
		for s > 0 && isNameByte(text[s-1]) {
			s--
		}
		// --password=... is a flag named password
		for s < e && !isAlnum(text[s]) {
			s++
		}
		name := text[s:e]
		if !secretNameRe.MatchString(name) {
			return true
		}
		m := assignValueRe.FindStringSubmatchIndex(text[e:])
		if m == nil {
			return true
		}
		vs, ve := e+m[2], e+m[3]
		value := strings.TrimRight(text[vs:ve], ".")
		// A function call: the value class stops at the parenthesis
		if called := ve < len(text) && text[ve] == '('; !called && plausibleSecret(value) {
			add(candidate{value: value, label: labelFor(name), prio: prioName})
		}
		return true
	})
}

// hasStem reports whether name holds a secret word stem; a cheap check
// before secretNameRe, as most JSON keys hold none.
func hasStem(name string) bool {
	var buf [64]byte
	if len(name) > len(buf) {
		return false
	}
	lower := buf[:len(name)]
	for i := range len(name) {
		c := name[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	for _, s := range secretStems {
		if bytes.Contains(lower, []byte(s)) {
			return true
		}
	}
	return false
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func isNameByte(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c == '.'
}

func (d *detector) scanGitleaks(text string, add func(candidate)) {
	for _, f := range d.gl.DetectString(text) {
		value := f.Secret
		if f.RuleID == "generic-api-key" {
			// The generic rule also fires on code (compileToken = t.x); hold
			// it to the same bar as the name rule
			if !plausibleSecret(value) {
				continue
			}
			// Without a name it fires on ids in URLs and image tags
			m := matchNameRe.FindStringSubmatch(f.Match)
			if m == nil {
				continue
			}
			add(candidate{value: value, label: labelFor(m[1]), prio: prioGitleaks})
			continue
		}
		if plausibleKnownSecret(value) {
			add(candidate{value: value, label: labelFor(f.RuleID), prio: prioGitleaks})
		}
	}
}

// scanPair checks a JSON key and its string value.
func scanPair(key, value string, add func(candidate)) {
	if hasStem(key) && secretNameRe.MatchString(key) && plausibleSecret(value) {
		add(candidate{value: value, label: labelFor(key), prio: prioName})
	}
}

// plausibleSecret filters values found next to a secret-looking name: long
// enough, varied enough, and not a path, URL, date, placeholder or code.
func plausibleSecret(v string) bool {
	if !plausibleKnownSecret(v) || len(v) > 512 {
		return false
	}
	for _, p := range []string{"/", "~/", "./", "%", "{", "@", "#"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	if strings.Contains(v, "://") || dateLikeRe.MatchString(v) || isDottedIdent(v) || looksLikeCode(v) {
		return false
	}
	c := charClasses(v)
	return c >= 3 || (c == 2 && len(v) >= 20 && hasDigit(v))
}

// looksLikeCode reports whether v is an expression rather than a value:
// minified JS (!x, a&&b, x?.y), shell ($VAR, $(cmd)) or a path in code
// (Foo::bar).
func looksLikeCode(v string) bool {
	if strings.HasPrefix(v, "!") || memberRe.MatchString(v) {
		return true
	}
	for _, op := range []string{"(", "$", "&&", "||", "=>", "==", "!=", "?.", "::"} {
		if strings.Contains(v, op) {
			return true
		}
	}
	// Base64 padding aside, = means an assignment
	return strings.Contains(strings.TrimRight(v, "="), "=")
}

// plausibleKnownSecret is the looser filter for values from a trusted source
// or a specific gitleaks rule.
func plausibleKnownSecret(v string) bool {
	return len(v) >= 8 && !isPlaceholder(v)
}

func isPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(lv, w) {
			return true
		}
	}
	return false
}

// isDottedIdent reports whether v looks like member access in code, such as
// process.env.TOKEN or settings.SECRET_KEY. Tokens split by dots (JWTs) have
// long parts full of digits; code rarely does.
func isDottedIdent(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	short := true
	for _, p := range parts {
		if !identPartRe.MatchString(p) {
			return false
		}
		short = short && len(p) <= 12
	}
	return short || !hasDigit(v)
}

func charClasses(v string) int {
	var lower, upper, digit, other bool
	for _, r := range v {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

func hasDigit(v string) bool {
	return strings.ContainsFunc(v, unicode.IsDigit)
}

// labelFor turns a name such as PAYMENTS_API_KEY, apiKey or aws-access-token
// into a snake_case label.
func labelFor(name string) string {
	s := camelBoundRe.ReplaceAllString(name, "${1}_${2}")
	s = nonLabelRe.ReplaceAllString(strings.ToLower(s), "_")
	s = strings.Trim(s, "_")
	if len(s) > 48 {
		s = strings.TrimRight(s[:48], "_")
	}
	if s == "" {
		return "secret"
	}
	return s
}
