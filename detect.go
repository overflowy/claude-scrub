package main

import (
	"bytes"
	"encoding/base64"
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
	urlCredsRe = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.\-]*)://([^\s:/@"'\\]*):([^\s@/"'\\]{6,})@`)

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

	// A reference to a value rather than the value itself. A password can start
	// with any of these characters too, so each form is kept narrow.
	referenceRe = regexp.MustCompile(strings.Join([]string{
		`^[!@#%][A-Za-z_$][A-Za-z_$./\-]*[0-9]*$`, // !isValid, @scope/pkg, #section: words, not noise
		`^#[0-9a-fA-F]{8}$`,                       // #rrggbbaa
		`^#!`,                                     // a shebang
		`^[%#@]\{`,                                // %{name}, #{name}
		`^%\w+%`,                                  // %APPDATA%
		`^%[-+#0-9.]*[a-zA-Z](?:[^A-Za-z0-9]|$)`,  // %s, %-5d, %Y-%m-%d
		`^\$[A-Za-z_]\w*(?:[/.:\-@]|$)`,           // $VAR, $HOME/.token
		`\$[A-Z_][A-Z0-9_]{2,}(?:[^A-Za-z0-9_]|$)`, // prefix-$VAR
	}, "|"))
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	// A letters-only value in a URL, or one with separators
	urlWordRe = regexp.MustCompile(`^[A-Za-z_\-]+$`)
	// The name and value in what kubernetes-secret-yaml captures
	kubernetesDataRe = regexp.MustCompile(`^[\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*["']?([A-Za-z0-9+/]+={0,3})["']?$`)

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
		lineStartAt, lineEndAt = lineStart(lower, at), lineEnd(lower, at)
		if lineEndAt-lineStartAt > maxSpan {
			addWindow(lineStartAt, lineEndAt, at, int(n), own)
			return true
		}
		ls, le := widen(lower, lineStartAt, lineEndAt)
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
func widen(lower []byte, ls, le int) (int, int) {
	line := lower[ls:le]
	if b := bytes.LastIndex(line, []byte("-----begin")); b >= 0 {
		// Key blocks are a few KB; without an end nearby this is not one. Nor with
		// another block starting first: this one was cut short, and running on
		// would swallow the header of the next.
		rest := lower[ls+b+1 : min(len(lower), ls+b+maxKeyBlock)]
		e, next := bytes.Index(rest, []byte("-----end")), bytes.Index(rest, []byte("-----begin"))
		if e >= 0 && (next < 0 || e < next) {
			le = max(le, lineEnd(lower, ls+b+1+e))
		}
	}
	if bytes.Contains(line, []byte("curl")) {
		end := le
		for range 5 {
			if end >= len(lower) {
				break
			}
			end = lineEnd(lower, end+1)
		}
		le = max(le, end)
	}
	if bytes.Contains(line, []byte("kind:")) && bytes.Contains(line, []byte("secret")) {
		ls = lineStart(lower, max(0, ls-300))
		le = max(le, lineEnd(lower, min(len(lower), le+300)))
	}
	return ls, le
}

// lineStart returns the offset just past the last newline before at, or 0.
func lineStart(data []byte, at int) int {
	return bytes.LastIndexByte(data[:at], '\n') + 1
}

// lineEnd returns the offset of the first newline at or after from, or len(data).
func lineEnd(data []byte, from int) int {
	if i := bytes.IndexByte(data[from:], '\n'); i >= 0 {
		return from + i
	}
	return len(data)
}

// detector runs the rules over lines. It is not safe for concurrent use;
// create one per goroutine.
type detector struct {
	gl    *detect.Detector // nil when gitleaks is disabled
	gated map[string]bool  // rules that gitleaks only runs on certain file names
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
	// A transcript holds YAML or Terraform under its own name, so a rule asking
	// for a file name would never fire on it. They run on everything, and
	// scanGitleaks makes up for what the file name told them.
	gated := map[string]bool{}
	for id, r := range gl.Config.Rules {
		if r.Regex != nil && r.Path != nil {
			r.Path = nil
			gl.Config.Rules[id] = r
			gated[id] = true
		}
	}
	return &detector{gl: gl, gated: gated}, nil
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
			if plausibleURLPassword(m[3], m[1], m[2]) {
				add(candidate{value: m[3], label: "url_password", prio: prioPattern})
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
		// A function call or ${...}: the value class stops at the bracket
		called := ve < len(text) && (text[ve] == '(' || text[ve] == '{' && text[ve-1] == '$')
		if !called && plausibleSecret(value) {
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
		if f.RuleID == "kubernetes-secret-yaml" {
			if value = kubernetesDataValue(value); value != "" {
				add(candidate{value: value, label: labelFor(f.RuleID), prio: prioGitleaks})
			}
			continue
		}
		if d.gated[f.RuleID] {
			// Without the file name these fire on any password = "..." in any
			// language, and on defaults the name rules would turn down
			if value = strings.Trim(value, `"`); plausibleSecret(value) {
				add(candidate{value: value, label: labelFor(f.RuleID), prio: prioGitleaks})
			}
			continue
		}
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

// kubernetesDataValue returns the value in what kubernetes-secret-yaml captures,
// name: value, so it is redacted wherever it appears, or "" if it is not one. The
// field holds base64 in a real Secret, and that is what tells it from other YAML.
func kubernetesDataValue(match string) string {
	m := kubernetesDataRe.FindStringSubmatch(match)
	if m == nil || !plausibleKnownSecret(m[1]) {
		return ""
	}
	if _, err := base64.StdEncoding.DecodeString(m[1]); err != nil {
		return ""
	}
	return m[1]
}

// plausibleSecret filters values found next to a secret-looking name: long
// enough, varied enough, and not a path, URL, date, placeholder or code.
func plausibleSecret(v string) bool {
	if !plausibleKnownSecret(v) || len(v) > 512 {
		return false
	}
	for _, p := range []string{"~/", "./", "{"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	if strings.HasPrefix(v, "/") && !isBase64Noise(v) {
		return false
	}
	if strings.Contains(v, "://") || dateLikeRe.MatchString(v) || isDottedIdent(v) || looksLikeCode(v) {
		return false
	}
	c := charClasses(v)
	return c >= 3 || (c == 2 && len(v) >= 20 && hasDigit(v))
}

// plausibleURLPassword filters the password in a URL. Its place marks it as one, so
// it needs no mix of characters. It still gets redacted everywhere it appears, which
// plain words rule out: postgres://postgres:postgres@db and
// mysql://root:MYSQL_PASSWORD@db would take those words out of every transcript.
func plausibleURLPassword(v, scheme, user string) bool {
	if !plausibleKnownSecret(v) || len(v) > 512 || strings.EqualFold(v, scheme) || strings.EqualFold(v, user) {
		return false
	}
	if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") || looksLikeCode(v) {
		return false
	}
	if !urlWordRe.MatchString(v) {
		return true
	}
	return len(v) >= 12 && !(strings.ContainsAny(v, "_-") && hasStem(v))
}

// isBase64Noise reports whether v, which starts with a slash, is base64 rather
// than a path; about 1 base64 key in 64 starts this way. Random text changes
// between lowercase, uppercase and digits at nearly two thirds of its characters,
// and a path at far fewer, even one holding a generated name.
func isBase64Noise(v string) bool {
	if len(v) < 16 || !base64Re.MatchString(v) {
		return false
	}
	class := func(c byte) byte {
		switch {
		case 'a' <= c && c <= 'z':
			return 'a'
		case 'A' <= c && c <= 'Z':
			return 'A'
		case '0' <= c && c <= '9':
			return '0'
		}
		return 0
	}
	pairs, changes := 0, 0
	for i := 1; i < len(v); i++ {
		a, b := class(v[i-1]), class(v[i])
		if a == 0 || b == 0 {
			continue
		}
		pairs++
		if a != b {
			changes++
		}
	}
	return changes*5 >= pairs*2
}

// looksLikeCode reports whether v is an expression rather than a value: minified
// JS (!x, a&&b, x?.y), a reference to a value ($VAR, $(cmd), %s) or a path in code
// (Foo::bar).
func looksLikeCode(v string) bool {
	if memberRe.MatchString(strings.TrimPrefix(v, "!")) || referenceRe.MatchString(v) {
		return true
	}
	for _, op := range []string{"(", "${", "&&", "||", "?.", "::"} {
		if strings.Contains(v, op) {
			return true
		}
	}
	// Base64 padding aside, = means an assignment or a comparison
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
