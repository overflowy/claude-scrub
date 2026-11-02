package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Fake secrets, shaped like real ones
const (
	fakePassword = "Wobbly-Teapot-Lantern-Quiver4"
	fakeAPIKey   = "6d0f3b1e-92ac-4c7e-b5a8-1f2e3d4c5b6a"
)

func detectAll(t *testing.T, text string) map[string]string {
	t.Helper()
	d, err := newDetector(false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	d.scan(newLineFinder(nil), text, func(c candidate) { got[c.value] = c.label })
	return got
}

func TestDetectAssignments(t *testing.T) {
	text := strings.Join([]string{
		`  - "DB_PASSWORD=` + fakePassword + `"`,
		`PAYMENTS_API_KEY: ` + fakeAPIKey,
		`{"clientSecret": "Zq8vN2mXk5LpR7tY"}`,
		`export GITHUB_TOKEN='ghp_Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z'`,
		`psql postgres://app:S3cr3t-Pa55word@db.local/app`,
		`curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"`,
		`BODY: {“token”: “f1a2e1f8-95bf-434b-9575-af6bba942100”}`,
		`basic_auth_password=QmFzZTY0UGFkZGVkVmFsdWU=`,
		`mysql -u root --password=Tq4-vB8-xN2m db`,
	}, "\n")
	got := detectAll(t, text)
	want := map[string]string{
		fakePassword:                           "db_password",
		fakeAPIKey:                             "payments_api_key",
		"Zq8vN2mXk5LpR7tY":                     "client_secret",
		"ghp_Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z": "github_token",
		"S3cr3t-Pa55word":                      "url_password",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl": "bearer_auth",
		"f1a2e1f8-95bf-434b-9575-af6bba942100":              "token",
		"QmFzZTY0UGFkZGVkVmFsdWU=":                          "basic_auth_password",
		"Tq4-vB8-xN2m":                                      "password",
	}
	for v, l := range want {
		if got[v] != l {
			t.Errorf("value %q: label %q, want %q", v, got[v], l)
		}
	}
}

func TestDetectIgnoresNonSecrets(t *testing.T) {
	text := strings.Join([]string{
		`MAX_OUTPUT_TOKENS=32000`,
		`TOKENS=Abc123-Def456-Ghi789`,
		`tokenCount: 123456789`,
		`SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.Xy12/Listeners`,
		`PWD=/Users/someone/Projects/App1`,
		`api_key = process.env.API_KEY`,
		`password: settings.DB_PASSWORD`,
		`token = getToken(user)`,
		`PASSWORD=changeme123`,
		`api_key: your_api_key_here`,
		`last_token: 2026-10-28T12:00:00Z`,
		`password: hunter2`,
		`DB_PASSWORD=[REDACTED:db_password]`,
		"if cont_token:\n    return AsyncLROPoller123",
		"auth:\n  existingSecret: gateway-creds",
		`e.resolvePassword=!this.state.Visible1`,
		`noLicenseKey:!e.licenseKey2&&"STANDALONE"`,
		`for(t=e.tokens.length-1;t>=0;t--)`,
		`const secret = v.secret?.trim1() || null`,
		`TOKEN=smoke-$(date +%s)`,
		`let token = ApiToken::generate2();`,
		`hasStoredSecret: Boolean1(stored)`,
	}, "\n")
	if got := detectAll(t, text); len(got) > 0 {
		t.Errorf("unexpected secrets: %v", got)
	}
}

func TestScanJSONKeys(t *testing.T) {
	data := []byte(`{"a":"x","password" : "p\"q","n":{"token":["t"]}}` + "\n" + `{"b":"y"}`)
	var lits []literal
	if !scanJSON(data, func(l literal) { lits = append(lits, l) }) {
		t.Fatal("scan failed")
	}
	var values []string
	for _, l := range lits {
		if !l.isKey {
			values = append(values, l.key+"="+decodeJSONString(data[l.start:l.end]))
		}
	}
	// "t" sits in an array, not directly under "token"
	want := []string{"a=x", `password=p"q`, "=t", "b=y"}
	if !slices.Equal(values, want) {
		t.Errorf("got %q, want %q", values, want)
	}
	if scanJSON([]byte(`{"a":"unterminated`), func(literal) {}) {
		t.Error("unterminated string should fail")
	}
}

func TestDecodeJSONString(t *testing.T) {
	cases := map[string]string{
		`"plain"`:         "plain",
		`"a\nb\t\"c\"\\"`: "a\nb\t\"c\"\\",
		`"é😀"`:            "é😀",
		`"\ud83d"`:        "�",
	}
	for raw, want := range cases {
		if got := decodeJSONString([]byte(raw)); got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}

func TestRedactEscapeBoundary(t *testing.T) {
	// "nabc12345XY" also appears as the tail of "\nabc12345XY" (a newline
	// then abc12345XY); cutting there would leave an invalid "\[" escape
	rep := newReplacer([]secret{{value: "nabc12345XY", label: "token"}})
	line := `{"a":"x\nabc12345XY","b":"nabc12345XY"}`
	red := rep.redact([]byte(line), kindJSONLines)
	want := `{"a":"x\nabc12345XY","b":"[REDACTED:token]"}`
	if string(red.out) != want {
		t.Errorf("got %s, want %s", red.out, want)
	}
}

func TestRedactEscapedForms(t *testing.T) {
	value := `pa"ss\word99`
	rep := newReplacer([]secret{{value: value, label: "password"}})
	once := jsonEscape(value)
	twice := jsonEscape(once)
	doc := `{"a":"` + once + `","b":"{\"c\":\"` + twice + `\"}"}`
	red := rep.redact([]byte(doc), kindJSONDoc)
	if strings.Contains(string(red.out), "word99") {
		t.Errorf("secret left in %s", red.out)
	}
	if !json.Valid(red.out) {
		t.Errorf("invalid JSON: %s", red.out)
	}
	if n := red.counts[0]; n != 2 {
		t.Errorf("redacted %d occurrences, want 2", n)
	}
}

func TestLabelFor(t *testing.T) {
	cases := map[string]string{
		"PAYMENTS_API_KEY": "payments_api_key",
		"clientSecret":     "client_secret",
		"aws-access-token": "aws_access_token",
		"--":               "secret",
	}
	for in, want := range cases {
		if got := labelFor(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dag.yaml")
	content := strings.Join([]string{
		`env:`,
		`  - "DB_HOST=10.0.0.5"`,
		`  - "DB_USER=app_user"`,
		`  - "DB_PASSWORD=` + fakePassword + `"`,
		`  - "PAYMENTS_API_KEY=` + fakeAPIKey + `"`,
		`  - "TRAVEL_DATE_DAYS_TO=90"`,
		`export SHORT_TOKEN=Ab1234`,
		`working_dir: /home/someone/app`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	col := newCollector()
	if err := loadEnvFile(path, col); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range col.secrets(&allowlist{}) {
		got[s.value] = s.label
	}
	want := map[string]string{fakePassword: "db_password", fakeAPIKey: "payments_api_key", "Ab1234": "short_token"}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for v, l := range want {
		if got[v] != l {
			t.Errorf("%q: label %q, want %q", v, got[v], l)
		}
	}
}

// writeTranscript builds a transcript where the password first shows up in a
// tool result next to its name, and later on its own in a command.
func writeTranscript(t *testing.T, root string) (string, time.Time) {
	t.Helper()
	dir := filepath.Join(root, "projects", "-tmp-app")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := []map[string]any{
		{"type": "user", "message": map[string]any{"content": []any{map[string]any{
			"type": "tool_result", "content": "env:\n  - \"DB_PASSWORD=" + fakePassword + "\"\n",
		}}}},
		{"type": "assistant", "message": map[string]any{"content": []any{map[string]any{
			"type": "tool_use", "input": map[string]any{"command": "PGPASSWORD='" + fakePassword + "' psql -h db"},
		}}}},
		{"type": "user", "message": map[string]any{"content": "nothing secret here"}},
	}
	var sb strings.Builder
	for _, l := range lines {
		b, _ := json.Marshal(l)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	path := filepath.Join(dir, "session.jsonl")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path, old
}

func testOptions(root string) options {
	return options{
		root: root, force: true, jobs: 2, minAge: 10 * time.Minute, quiet: true,
		secrets: filepath.Join(root, "none"), allow: filepath.Join(root, "none"),
	}
}

func TestScrubEndToEnd(t *testing.T) {
	root := t.TempDir()
	path, mtime := writeTranscript(t, root)

	o := testOptions(root)
	o.dryRun = true
	if err := scrub(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), fakePassword) {
		t.Fatal("dry run changed the file")
	}

	o.dryRun = false
	if err := scrub(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), fakePassword) {
		t.Errorf("password left in transcript:\n%s", b)
	}
	if n := strings.Count(string(b), "[REDACTED:db_password]"); n != 2 {
		t.Errorf("got %d placeholders, want 2:\n%s", n, b)
	}
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %s", i+1, line)
		}
	}
	info, _ := os.Stat(path)
	if !info.ModTime().Equal(mtime) {
		t.Errorf("mtime %v, want %v", info.ModTime(), mtime)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}

	// A second run finds nothing left
	before := string(b)
	if err := scrub(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); string(after) != before {
		t.Error("second run changed the file")
	}
}

func TestScrubSkipsRecentFiles(t *testing.T) {
	root := t.TempDir()
	path, _ := writeTranscript(t, root)
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatal(err)
	}
	if err := scrub(context.Background(), testOptions(root), nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), fakePassword) {
		t.Error("a file modified within --min-age was redacted")
	}
}

func TestHookPaths(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, "projects", "p", "abc.jsonl")
	if err := os.MkdirAll(filepath.Join(root, "projects", "p", "abc", "subagents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(transcript, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := strings.NewReader(`{"session_id":"abc","transcript_path":"` + transcript + `"}`)
	got, err := hookPaths(in, root)
	if err != nil {
		t.Fatal(err)
	}
	// history.jsonl does not exist, so it is left out
	want := []string{transcript, filepath.Join(root, "projects", "p", "abc")}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A session closed before the first message has no transcript on disk
func TestHookPathsNoTranscript(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, "projects", "p", "abc.jsonl")
	in := strings.NewReader(`{"session_id":"abc","transcript_path":"` + transcript + `"}`)
	got, err := hookPaths(in, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want no paths", got)
	}
}

// With nothing to redact, the hook must not fall back to the whole history
func TestHookNoTranscript(t *testing.T) {
	root := t.TempDir()
	other, _ := writeTranscript(t, root)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "projects", "-tmp-app", "empty.jsonl")
	if _, err := w.WriteString(`{"session_id":"empty","transcript_path":"` + missing + `"}`); err != nil {
		t.Fatal(err)
	}
	w.Close()
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin; r.Close() })

	o := testOptions(root)
	o.hook, o.minAge = true, 0
	if err := scrub(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(other); !strings.Contains(string(b), fakePassword) {
		t.Error("the hook redacted another session")
	}
}

func TestKeywordLines(t *testing.T) {
	d, err := newDetector(true)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join([]string{
		"nothing here",
		"DB_PASSWORD=" + fakePassword,
		"still nothing",
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEA",
		"-----END RSA PRIVATE KEY-----",
		"tail",
	}, "\n")
	var got []string
	for _, l := range newLineFinder(d.gl).lines(text) {
		got = append(got, l.text)
		if l.lower != strings.ToLower(l.text) || !l.own {
			t.Errorf("line %q: lower %q, own %v", l.text, l.lower, l.own)
		}
	}
	want := []string{
		"DB_PASSWORD=" + fakePassword,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestKeywordLinesWidenCurl(t *testing.T) {
	d, err := newDetector(true)
	if err != nil {
		t.Fatal(err)
	}
	text := "before\ncurl -X POST 'https://api.test/v1/orders' \\\n  -H 'Accept: application/json' \\\n" +
		"  -u 'shopuser:Mx7-pQ2-zK9w' \\\n  -d '{}'\nafter\nlater\nlast"
	lf := newLineFinder(d.gl)
	lines := lf.lines(text)
	if len(lines) != 1 || !strings.Contains(lines[0].text, "-u 'shopuser:") || strings.Contains(lines[0].text, "before") {
		t.Fatalf("got %+v", lines)
	}
	found := false
	d.scan(lf, text, func(c candidate) { found = found || c.label == "curl_auth_user" })
	if !found {
		t.Error("curl -u on a continuation line not detected")
	}
}

func TestDetectPrivateKeyBlock(t *testing.T) {
	d, err := newDetector(true)
	if err != nil {
		t.Fatal(err)
	}
	// Built at run time so the source holds no key block for scanners
	body := strings.Repeat("Q2xhdWRlU2NydWJUZXN0S2V5TWF0ZXJpYWw0Mg", 8)
	text := "log line\n-----BEGIN " + "RSA PRIVATE KEY-----\n" + body[:64] + "\n" + body[64:128] +
		"\n" + body[128:192] + "\n-----END " + "RSA PRIVATE KEY-----\nmore log"
	found := false
	d.scan(newLineFinder(d.gl), text, func(c candidate) {
		if c.label == "private_key" && strings.Contains(c.value, body[64:128]) {
			found = true
		}
	})
	if !found {
		t.Error("private key block not detected")
	}
}

func TestLongLineWindows(t *testing.T) {
	d, err := newDetector(true)
	if err != nil {
		t.Fatal(err)
	}
	lf := newLineFinder(d.gl)
	filler := strings.Repeat("var a=1;", 40*1024) // 320 KB of minified code
	text := filler + `config.dbPassword="` + fakePassword + `";` + filler + `var x="ghp_R7kq2NwX9vLm4TzP8sYb3HcJ6dFg1QaE5uVi";` + filler
	lines := lf.lines(text)
	for _, l := range lines {
		if len(l.text) > maxSpan+2*windowMargin {
			t.Errorf("window of %d bytes", len(l.text))
		}
	}
	got := map[string]string{}
	d.scan(lf, text, func(c candidate) { got[c.value] = c.label })
	if got[fakePassword] != "config_db_password" || got["ghp_R7kq2NwX9vLm4TzP8sYb3HcJ6dFg1QaE5uVi"] != "github_pat" {
		t.Errorf("got %v", got)
	}
}

func TestSummarizeKnownValues(t *testing.T) {
	secrets := []secret{
		{value: "listed-and-present", label: "a", prio: prioKnown},
		{value: "listed-and-absent", label: "b", prio: prioKnown},
		{value: "listed-and-left-alone", label: "c", prio: prioKnown},
		{value: "detected-unmatched", label: "d", prio: prioName},
	}
	s := summarize(secrets, []fileResult{{
		path:    "f",
		counts:  map[int]int{0: 2},
		left:    map[int]int{2: 1},
		skipped: 1,
	}})
	if s.found != 3 || s.occurrences != 2 {
		t.Errorf("found %d, occurrences %d; want 3, 2", s.found, s.occurrences)
	}
	var labels []string
	for _, l := range s.labels {
		labels = append(labels, l.label)
	}
	slices.Sort(labels)
	if want := []string{"a", "c", "d"}; !slices.Equal(labels, want) {
		t.Errorf("labels %v, want %v", labels, want)
	}
}

func TestRedactLeftAlone(t *testing.T) {
	// The value's closing quote is the one ending "a": replacing it would
	// leave that string unterminated
	rep := newReplacer([]secret{{value: `abcd1234"`, label: "token"}})
	line := `{"a":"abcd1234","b":"y"}`
	for _, kind := range []fileKind{kindJSONDoc, kindJSONLines} {
		red := rep.redact([]byte(line), kind)
		if string(red.out) != line {
			t.Errorf("kind %d: got %s", kind, red.out)
		}
		if red.skipped != 1 || red.left[0] != 1 || len(red.counts) != 0 {
			t.Errorf("kind %d: skipped %d, left %v, counts %v", kind, red.skipped, red.left, red.counts)
		}
	}
}

func TestPlural(t *testing.T) {
	if got := plural(1, "secret"); got != "1 secret" {
		t.Errorf("got %q", got)
	}
	if got := plural(0, "secret"); got != "0 secrets" {
		t.Errorf("got %q", got)
	}
}

func TestRedactDecodedForms(t *testing.T) {
	// Spelled "\\u..." so the file holds the escape and not the character
	const (
		lower  = "\\u00e4"
		upper  = "\\u00E4"
		pEsc   = "\\u0070"
		emoji  = "\\ud83d\\ude00"
		nested = "\\\\u00e4"
		tail   = "ssW0rd-Lantern-77"
		ph     = "[REDACTED:password]"
	)
	value := "pä" + tail
	cases := []struct {
		name, value, in, want string
		n                     int
	}{
		{"lowercase hex", value, `{"a":"p` + lower + tail + `"}`, `{"a":"` + ph + `"}`, 1},
		{"uppercase hex", value, `{"a":"p` + upper + tail + `"}`, `{"a":"` + ph + `"}`, 1},
		{"escaped ASCII", value, `{"a":"` + pEsc + lower + tail + `"}`, `{"a":"` + ph + `"}`, 1},
		{"escaped slash", "ab/cd+Ef12/gh", `{"a":"ab\/cd+Ef12\/gh"}`, `{"a":"` + ph + `"}`, 1},
		{"surrogate pair", "Key\U0001F600Lantern77", `{"a":"Key` + emoji + `Lantern77"}`, `{"a":"` + ph + `"}`, 1},
		{"text around it", value, `{"a":"x\np` + lower + tail + `\ty"}`, `{"a":"x\n` + ph + `\ty"}`, 1},
		{"JSON in JSON", value, `{"a":"{\"b\":\"p` + nested + tail + `\"}"}`, `{"a":"{\"b\":\"` + ph + `\"}"}`, 1},
		{"both spellings", value, `{"a":"p` + lower + tail + `","b":"` + value + `"}`, `{"a":"` + ph + `","b":"` + ph + `"}`, 2},
		{"key", value, `{"p` + lower + tail + `":"a"}`, `{"` + ph + `":"a"}`, 1},
		{"other value", value, `{"a":"p` + lower + `ssW0rd-Lantern-78"}`, `{"a":"p` + lower + `ssW0rd-Lantern-78"}`, 0},
		{"escape before it", "nabc12345XY", `{"a":"x\nabc12345XY` + lower + `"}`, `{"a":"x\nabc12345XY` + lower + `"}`, 0},
	}
	for _, c := range cases {
		rep := newReplacer([]secret{{value: c.value, label: "password"}})
		for _, kind := range []fileKind{kindJSONDoc, kindJSONLines} {
			red := rep.redact([]byte(c.in), kind)
			if string(red.out) != c.want {
				t.Errorf("%s, kind %d: got %s, want %s", c.name, kind, red.out, c.want)
			}
			if !json.Valid(red.out) {
				t.Errorf("%s, kind %d: invalid JSON: %s", c.name, kind, red.out)
			}
			if got := sumCounts(red.counts); got != c.n {
				t.Errorf("%s, kind %d: redacted %d occurrences, want %d", c.name, kind, got, c.n)
			}
		}
	}
}

func TestScrubEscapedValue(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "s.jsonl")
	in := `{"password":"p` + "\\u00e4" + `ssW0rd-Lantern-77"}` + "\n"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scrub(context.Background(), testOptions(root), []string{path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"password":"[REDACTED:password]"}` + "\n"; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestRedactFileVanished(t *testing.T) {
	rep := newReplacer([]secret{{value: fakePassword, label: "password"}})
	res := redactFile(rep, filepath.Join(t.TempDir(), "gone.jsonl"), true)
	if res.err != nil || len(res.counts) != 0 {
		t.Errorf("err %v, counts %v", res.err, res.counts)
	}
}

func TestWriteAtomicVanished(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("y"), info); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("got %v, want a not-exist error", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file came back: %v", err)
	}
}

func TestDiscoverMissingPaths(t *testing.T) {
	dir := t.TempDir()
	gone := filepath.Join(dir, "gone")
	if _, err := discoverPaths([]string{gone}, true); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("named path: got %v, want a not-exist error", err)
	}
	// A hook path or history path deleted after it was listed
	keep := filepath.Join(dir, "keep.jsonl")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := discoverPaths([]string{gone, keep}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.targets) != 1 || d.targets[0].path != keep {
		t.Errorf("targets %v", d.targets)
	}
}

func TestDecodeMapped(t *testing.T) {
	bs := "\\"
	for _, body := range []string{
		"plain", bs + "n", "a" + bs + "nb", bs, "a" + bs, bs + "x", bs + "u12", bs + "uZZZZ",
		bs + "u00e4x", bs + "ud83d", bs + "ud83dabc", bs + "ud83d" + bs + "n", bs + "ud83d" + bs + "ude00z",
		bs + bs + "u00e4", bs + "/" + bs + bs + bs + `"`,
	} {
		out, offs := decodeMapped([]byte(body))
		if want := decodeJSONString([]byte(`"` + body + `"`)); string(out) != want {
			t.Errorf("%s: got %q, want %q", body, out, want)
		}
		if len(offs) != len(out)+1 || offs[len(out)] != len(body) || !slices.IsSorted(offs) {
			t.Errorf("%s: bad offsets %v for %q", body, offs, out)
		}
	}
	out, offs := decodeMapped([]byte("a" + bs + "u00e4" + bs + "nb"))
	if want := []int{0, 1, 1, 7, 9, 10}; string(out) != "aä\nb" || !slices.Equal(offs, want) {
		t.Errorf("got %q %v, want offsets %v", out, offs, want)
	}
}

func TestRedactEveryCharEscaped(t *testing.T) {
	spell := func(v string) string {
		var sb strings.Builder
		for _, c := range utf16.Encode([]rune(v)) {
			fmt.Fprintf(&sb, "\\u%04x", c)
		}
		return sb.String()
	}
	for _, value := range []string{fakePassword, fakeAPIKey, `pa"ss\word99`, "tab\there/slash", "Käy\U0001F600Lantern77"} {
		rep := newReplacer([]secret{{value: value, label: "password"}})
		line := `{"a":"before ` + spell(value) + ` after","b":"x\ny"}`
		red := rep.redact([]byte(line), kindJSONLines)
		want := `{"a":"before [REDACTED:password] after","b":"x\ny"}`
		if string(red.out) != want {
			t.Errorf("%q: got %s", value, red.out)
		}
		if red.skipped != 0 || sumCounts(red.counts) != 1 {
			t.Errorf("%q: skipped %d, counts %v", value, red.skipped, red.counts)
		}
	}
}

func TestScrubNestedEscapedValue(t *testing.T) {
	const nested = "\\\\u00e4" // a backslash pair, as JSON in JSON writes it
	cases := []struct{ name, in, want string }{
		{
			"JSON in JSON",
			`{"a":"{\"password\":\"p` + nested + `ssW0rd-Lantern-77\"}"}`,
			`{"a":"{\"password\":\"[REDACTED:password]\"}"}`,
		},
		{
			"escaped slash",
			`{"a":"{\"token\":\"ab\\/cd+Ef12\\/ghIJ\"}"}`,
			`{"a":"{\"token\":\"[REDACTED:token]\"}"}`,
		},
		{
			"assignment in text",
			`{"a":"run with\nDB_PASSWORD=p` + nested + `ssW0rd-Lantern-77\nthen stop"}`,
			`{"a":"run with\nDB_PASSWORD=[REDACTED:db_password]\nthen stop"}`,
		},
		{
			"code stays",
			`{"a":"token = process.env.API_KEY\\u0021"}`,
			`{"a":"token = process.env.API_KEY\\u0021"}`,
		},
	}
	for _, c := range cases {
		root := t.TempDir()
		path := filepath.Join(root, "s.jsonl")
		if err := os.WriteFile(path, []byte(c.in+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		o := testOptions(root)
		if err := scrub(context.Background(), o, []string{path}); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want+"\n" {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestDecodeLiteralsNested(t *testing.T) {
	data := []byte(`{"a":"{\"b\":\"p` + "\\\\u00e4" + `ss\"}"}`)
	if got := decodeLiterals(data, kindJSONLines); !strings.Contains(got, `{"b":"päss"}`) {
		t.Errorf("nested form missing from %q", got)
	}
}

func explainOutput(t *testing.T, content string, secrets []secret, label string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := newReplacer(secrets)
	sum := summarize(secrets, []fileResult{redactFile(rep, path, false)})
	var out strings.Builder
	explain(&out, rep, sum, label)
	return out.String()
}

func TestExplainHidesEscapedSpellings(t *testing.T) {
	const tail = "ssW0rd-Lantern-77"
	in := `{"a":"{\"password\":\"p` + "\\\\u00e4" + tail + `\"}"}` + "\n"
	got := explainOutput(t, in, []secret{{value: "pä" + tail, label: "password"}}, "password")
	if strings.Contains(got, tail) {
		t.Errorf("secret shown: %s", got)
	}
	if !strings.Contains(got, "[REDACTED:password]") {
		t.Errorf("no placeholder: %s", got)
	}
}

func TestExplainHidesSecretAtWindowEdge(t *testing.T) {
	// The window reaches 80 bytes either side of the explained value, which
	// falls in the middle of each neighbour
	before, after := "Wobbly-Teapot-Lantern-Quiver4", "Fuzzy-Walnut-Harbor-Candle-Nine8"
	explained := "Zq8vN2mXk5LpR7tY"
	pad := strings.Repeat(" ", 66)
	in := `{"a":"` + before + pad + explained + pad + after + `"}` + "\n"
	secrets := []secret{
		{value: before, label: "first"},
		{value: explained, label: "middle"},
		{value: after, label: "last"},
	}
	got := explainOutput(t, in, secrets, "middle")
	for _, part := range []string{"Quiver4", "Lantern", "Fuzzy", "Walnut"} {
		if strings.Contains(got, part) {
			t.Errorf("fragment %q shown: %s", part, got)
		}
	}
	for _, label := range []string{"first", "last", "middle"} {
		if !strings.Contains(got, "[REDACTED:"+label+"]") {
			t.Errorf("no placeholder for %s: %s", label, got)
		}
	}
}

// Spellings of ä at growing depth, in bytes as they sit in the file
const (
	escOnce   = "\\u00e4"
	escTwice  = "\\\\u00e4"
	escThrice = "\\\\\\\\u00e4"
	testTail  = "ssW0rd-Lantern-77"
	testValue = "pä" + testTail
	testPH    = "[REDACTED:password]"
)

func passwordReplacer() *replacer {
	return newReplacer([]secret{{value: testValue, label: "password"}})
}

func TestRedactTornLines(t *testing.T) {
	good := `{"b":"before p` + escOnce + testTail + ` after"}`
	goodOut := `{"b":"before ` + testPH + ` after"}`
	cases := []struct{ name, in, want string }{
		{"torn line first", `{"a":"trunc` + "\n" + good + "\n", `{"a":"trunc` + "\n" + goodOut + "\n"},
		{"torn line between", good + "\n" + `{"a":"trunc` + "\n" + good, goodOut + "\n" + `{"a":"trunc` + "\n" + goodOut},
		{"secret in the torn line", `{"b":"before p` + escOnce + testTail + ` aft`, `{"b":"before ` + testPH + ` aft`},
	}
	rep := passwordReplacer()
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			if got := rep.redact([]byte(c.in), kind).out; string(got) != c.want {
				t.Errorf("%s, kind %d: got %s, want %s", c.name, kind, got, c.want)
			}
		}
	}
}

func scrubFile(t *testing.T, name, content string) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scrub(context.Background(), testOptions(root), []string{path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestDetectAroundTornLines(t *testing.T) {
	nested := `{"a":"{\"password\":\"p` + escTwice + testTail + `\"}"}`
	nestedOut := `{"a":"{\"password\":\"` + testPH + `\"}"}`
	cases := []struct{ name, file, in, want string }{
		{"nested, then torn", "s.jsonl", nested + "\n" + `{"a":"trunc`, nestedOut + "\n" + `{"a":"trunc`},
		{"torn, then nested", "s.jsonl", `{"a":"trunc` + "\n" + nested + "\n", `{"a":"trunc` + "\n" + nestedOut + "\n"},
		{"nested in the torn line", "s.jsonl", `{"a":"{\"password\":\"p` + escTwice + testTail + `\"`, `{"a":"{\"password\":\"` + testPH + `\"`},
		{"plain in a torn line", "s.jsonl", `{"a":"DB_PASSWORD=` + fakePassword + ` aft`, `{"a":"DB_PASSWORD=[REDACTED:db_password] aft`},
		{
			"outside strings in a broken file", "notes.txt",
			"[x]\nTOKEN=" + fakePassword + "\n\"unterminated\n",
			"[x]\nTOKEN=[REDACTED:token]\n\"unterminated\n",
		},
		{
			"pair across lines in a document", "c.json",
			"{\n  \"password\":\n    \"" + fakePassword + "\"\n}\n",
			"{\n  \"password\":\n    \"[REDACTED:password]\"\n}\n",
		},
	}
	for _, c := range cases {
		if got := scrubFile(t, c.file, c.in); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestRedactTextSpellings(t *testing.T) {
	cases := []struct{ name, value, in, want string }{
		{"escaped slash", "abcdefgh12/xyzQRS", `resp {"token":"abcdefgh12\/xyzQRS"} ok`, `resp {"token":"` + testPH + `"} ok`},
		{"unicode", testValue, "log: p" + escOnce + testTail + " done\nnext\n", "log: " + testPH + " done\nnext\n"},
		{"JSON in JSON", testValue, `log {"a":"p` + escTwice + testTail + `"}`, `log {"a":"` + testPH + `"}`},
		{"plain still works", testValue, "log: " + testValue, "log: " + testPH},
		{"other text stays", testValue, `path C:\users\me p` + escOnce + `ss`, `path C:\users\me p` + escOnce + `ss`},
	}
	for _, c := range cases {
		rep := newReplacer([]secret{{value: c.value, label: "password"}})
		if got := rep.redact([]byte(c.in), kindText).out; string(got) != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestRedactDeepNesting(t *testing.T) {
	rep := passwordReplacer()
	in := `{"a":"p` + escThrice + testTail + `"}`
	want := `{"a":"` + testPH + `"}`
	if got := rep.redact([]byte(in), kindJSONLines).out; string(got) != want {
		t.Errorf("third level: got %s, want %s", got, want)
	}
	// A value needing escapes, spelled the usual way three levels down
	value := `pa"ss\word99`
	spelled := jsonEscape(jsonEscape(jsonEscape(value)))
	rep = newReplacer([]secret{{value: value, label: "password"}})
	if got := rep.redact([]byte(`{"a":"`+spelled+`"}`), kindJSONLines).out; string(got) != want {
		t.Errorf("canonical third level: got %s, want %s", got, want)
	}
	// Decoding has to stop on an escape it cannot resolve
	stuck := `{"a":"C:\\users\\uZZZZ"}`
	if got := rep.redact([]byte(stuck), kindJSONLines).out; string(got) != stuck {
		t.Errorf("got %s", got)
	}
}

func TestDetectDeepNesting(t *testing.T) {
	// A transcript read into a session: JSON in JSON in JSON
	in := `{"a":"{\"b\":\"{\\\"password\\\":\\\"p` + escThrice + testTail + `\\\"}\"}"}` + "\n"
	want := `{"a":"{\"b\":\"{\\\"password\\\":\\\"` + testPH + `\\\"}\"}"}` + "\n"
	if got := scrubFile(t, "s.jsonl", in); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestRedactOverlappingSecrets(t *testing.T) {
	secrets := []secret{{value: "AAAAAAAABBBBBBBB", label: "one"}, {value: "BBBBBBBBCCCCCCCC", label: "two"}}
	rep := newReplacer(secrets)
	red := rep.redact([]byte("x AAAAAAAABBBBBBBBCCCCCCCC y"), kindText)
	if want := "x [REDACTED:one] y"; string(red.out) != want {
		t.Errorf("got %s, want %s", red.out, want)
	}
	if red.counts[0] != 1 || red.counts[1] != 1 {
		t.Errorf("counts %v, want one of each", red.counts)
	}
	got := explainOutput(t, `{"a":"x AAAAAAAABBBBBBBBCCCCCCCC y"}`+"\n", secrets, "two")
	if strings.Contains(got, "CCCC") {
		t.Errorf("fragment shown: %s", got)
	}
	// The same secret found twice over is one occurrence
	rep = passwordReplacer()
	red = rep.redact([]byte(`{"a":"`+testValue+`","b":"p`+escOnce+testTail+`"}`), kindJSONLines)
	if red.counts[0] != 2 {
		t.Errorf("counts %v, want 2", red.counts)
	}
}

func TestRedactNestedEscapes(t *testing.T) {
	const value = "nabc12345XY"
	ph := "[REDACTED:password]"
	cases := []struct {
		name, in, want string
		n, left        int
	}{
		// Not the secret: a newline in the inner JSON, then abc12345XY
		{"inner newline", `{"a":"{\"b\":\"line\\nabc12345XY\"}"}`, `{"a":"{\"b\":\"line\\nabc12345XY\"}"}`, 0, 1},
		{"inner newline, other escape", `{"a":"{\"b\":\"line\\nabc12345XY` + escTwice + `\"}"}`, `{"a":"{\"b\":\"line\\nabc12345XY` + escTwice + `\"}"}`, 0, 1},
		{"third level newline", `{"a":"{\"b\":\"{\\\"c\\\":\\\"line\\\\nabc12345XY\\\"}\"}"}`, `{"a":"{\"b\":\"{\\\"c\\\":\\\"line\\\\nabc12345XY\\\"}\"}"}`, 0, 1},
		// The real one beside it still goes
		{"real one beside it", `{"a":"{\"b\":\"line\\nabc12345XY\",\"c\":\"nabc12345XY\"}"}`, `{"a":"{\"b\":\"line\\nabc12345XY\",\"c\":\"` + ph + `\"}"}`, 1, 1},
		// A real backslash in the inner string: this is the secret
		{"inner path", `{"a":"{\"p\":\"C:\\\\nabc12345XY\"}"}`, `{"a":"{\"p\":\"C:\\\\` + ph + `\"}"}`, 1, 0},
		// Not JSON inside, so there is nothing to keep valid
		{"plain text path", `{"a":"path C:\\nabc12345XY here"}`, `{"a":"path C:\\` + ph + ` here"}`, 1, 0},
		{"plain nested value", `{"a":"{\"c\":\"nabc12345XY\"}"}`, `{"a":"{\"c\":\"` + ph + `\"}"}`, 1, 0},
	}
	rep := newReplacer([]secret{{value: value, label: "password"}})
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			red := rep.redact([]byte(c.in), kind)
			if string(red.out) != c.want {
				t.Errorf("%s, kind %d: got %s, want %s", c.name, kind, red.out, c.want)
			}
			if got := sumCounts(red.counts); got != c.n {
				t.Errorf("%s, kind %d: redacted %d, want %d", c.name, kind, got, c.n)
			}
			if got := sumCounts(red.left); got != c.left {
				t.Errorf("%s, kind %d: left %d, want %d", c.name, kind, got, c.left)
			}
			if (red.skipped > 0) != (c.left > 0) {
				t.Errorf("%s, kind %d: skipped %d with %d left", c.name, kind, red.skipped, c.left)
			}
		}
	}
}

func TestExplainMatchesWhatRedactDoes(t *testing.T) {
	// A text file: --explain and the rewrite have to agree on what goes
	root := t.TempDir()
	path := filepath.Join(root, "log.txt")
	in := `log: {"b":"p` + escOnce + testTail + `"}` + "\n"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := []secret{{value: testValue, label: "password"}}
	rep := newReplacer(secrets)
	red := redactFile(rep, path, false)
	if sumCounts(red.counts) != 1 {
		t.Fatalf("counts %v, want 1", red.counts)
	}
	var out strings.Builder
	explain(&out, rep, summarize(secrets, []fileResult{red}), "password")
	if got := out.String(); strings.Contains(got, testTail) || !strings.Contains(got, testPH) {
		t.Errorf("explain: %s", got)
	}
	if strings.Contains(out.String(), "no occurrence") {
		t.Errorf("explain missed it: %s", out.String())
	}
	if err := scrub(context.Background(), testOptions(root), []string{path}); err != nil {
		t.Fatal(err)
	}
	o := testOptions(root)
	o.secrets = filepath.Join(root, "secrets")
	if err := os.WriteFile(o.secrets, []byte("password="+testValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scrub(context.Background(), o, []string{path}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), testTail) {
		t.Errorf("explain showed a placeholder but the file holds the secret: %s", got)
	}
}

func validLines(lines []string) int {
	n := 0
	for _, l := range lines {
		if isStructuredJSON([]byte(l)) {
			n++
		}
	}
	return n
}

func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		`{"a":"pässW0rd-Lantern-77"}`,
		`{"a":"{\"b\":\"line\\nabc12345XY\\u00e4\"}"}`,
		`{"a":"trunc` + "\n" + `{"b":"nabc12345XY\/"}`,
		`{"a":"😀\ud83d\\\\\u"}`,
		`text \ \u \\u00e4 nabc12345XY`,
		"{\n\"password\"\n:\n\"nabc12345XY\",\n}\n\"torn\n",
		"[a \\nabc12345XY\n{\"pin\":12345,\"a\":\"nabc12345XY\"}\n12345\n",
	} {
		f.Add(s, "nabc12345XY")
		f.Add(s, "pä"+testTail)
		f.Add(s, `q"\/`)
	}
	f.Fuzz(func(t *testing.T, data, value string) {
		if len(value) < 3 {
			return
		}
		rep := newReplacer([]secret{{value: value, label: "x"}, {value: value + "tail", label: "y"}})
		for _, kind := range []fileKind{kindText, kindJSONLines, kindJSONDoc} {
			in := []byte(data)
			red := rep.redact(in, kind)
			if kind == kindJSONDoc && isStructuredJSON(in) && !json.Valid(red.out) {
				t.Fatalf("document went invalid: %s -> %s", in, red.out)
			}
			if kind == kindJSONLines {
				before, after := strings.Split(data, "\n"), strings.Split(string(red.out), "\n")
				if len(before) == len(after) {
					for i := range before {
						if isStructuredJSON([]byte(before[i])) && !json.Valid([]byte(after[i])) {
							t.Fatalf("line went invalid: %s -> %s", before[i], after[i])
						}
					}
				}
				if validLines(after) < validLines(before) {
					t.Fatalf("lost a valid line: %q -> %q", data, red.out)
				}
			}
			hits := rep.findAll([]byte(data), kindText)
			if len(data) > 0 {
				rep.snippet(data, hits, 0, len(data)/2, 80)
			}
		}
	})
}

func TestRedactSecretOnLineBreak(t *testing.T) {
	// Starts on the newline ending a line. Found by fuzzing: this used to loop
	// forever. None of these lines is JSON, so there is nothing to keep valid.
	rep := newReplacer([]secret{{value: "\n000", label: "x"}})
	in := "000\n000\nA\n000"
	want := "000[REDACTED:x]\nA[REDACTED:x]"
	if got := rep.redact([]byte(in), kindJSONLines).out; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	in = `{"a":1}` + "\n000\nA\n"
	if red := rep.redact([]byte(in), kindJSONLines); string(red.out) != in || red.left[0] != 1 {
		t.Errorf("got %q, left %v", red.out, red.left)
	}
}

func TestRedactScalarBodies(t *testing.T) {
	const ph = "[REDACTED:pin]"
	cases := []struct {
		name, in, want string
		n, left        int
	}{
		{"beside an escaped quote", `{"cmd":"echo \"hi\"","pin":"12345678"}`, `{"cmd":"echo \"hi\"","pin":"` + ph + `"}`, 1, 0},
		{"string in nested JSON", `{"c":"{\"pin\":\"12345678\"}"}`, `{"c":"{\"pin\":\"` + ph + `\"}"}`, 1, 0},
		{"nested JSON string", `{"c":"\"12345678\""}`, `{"c":"\"` + ph + `\""}`, 1, 0},
		// A bare number in nested JSON has no quotes to keep the placeholder valid
		{"number in nested JSON", `{"c":"{\"pin\":12345678}"}`, `{"c":"{\"pin\":12345678}"}`, 0, 1},
	}
	rep := newReplacer([]secret{{value: "12345678", label: "pin"}})
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			red := rep.redact([]byte(c.in), kind)
			if string(red.out) != c.want {
				t.Errorf("%s, kind %d: got %s, want %s", c.name, kind, red.out, c.want)
			}
			if sumCounts(red.counts) != c.n || sumCounts(red.left) != c.left {
				t.Errorf("%s, kind %d: counts %v, left %v", c.name, kind, red.counts, red.left)
			}
		}
	}
	// A JSON string in a string can still hold an escape to protect
	rep = newReplacer([]secret{{value: "nabc12345XY", label: "pin"}})
	in := `{"c":"\"line\\nabc12345XY\""}`
	if red := rep.redact([]byte(in), kindJSONLines); string(red.out) != in || sumCounts(red.left) != 1 {
		t.Errorf("got %s, left %v", red.out, red.left)
	}
}

func TestDetectInLinesThatAreNotJSON(t *testing.T) {
	assign := "export TOKEN=" + fakePassword
	done := "export TOKEN=[REDACTED:token]"
	cases := []struct{ name, file, in, want string }{
		{"log with a stray quote", "app.log", "[INFO] said \"hi\n[INFO] " + assign + "\n", "[INFO] said \"hi\n[INFO] " + done + "\n"},
		{"log with balanced quotes", "app.log", "[INFO] said \"hi\"\n[INFO] " + assign + "\n", "[INFO] said \"hi\"\n[INFO] " + done + "\n"},
		{"JSONL line that is not JSON", "s.jsonl", "{" + assign + "\n{\"a\":\"b\"}\n", "{" + done + "\n{\"a\":\"b\"}\n"},
		{"JSONL under another name", "s.ndjson", "{\"a\":\"b\"}\n{" + assign + "\n", "{\"a\":\"b\"}\n{" + done + "\n"},
		{"text after a document", "s.jsonl", "{\"a\":\"b\"} " + assign + "\n", "{\"a\":\"b\"} " + done + "\n"},
	}
	for _, c := range cases {
		if got := scrubFile(t, c.file, c.in); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestRedactSpellingInLinesThatAreNotJSON(t *testing.T) {
	spelled := "p" + escOnce + testTail
	cases := []struct{ name, in, want string }{
		{"no strings", "[INFO] pw=" + spelled + "\n", "[INFO] pw=" + testPH + "\n"},
		{"outside the strings", `[INFO] "said" pw=` + spelled + "\n", `[INFO] "said" pw=` + testPH + "\n"},
		{"after a document", `{"a":"b"} ` + spelled + "\n", `{"a":"b"} ` + testPH + "\n"},
		{"inside a string still", `{"a":"` + spelled + `",}` + "\n", `{"a":"` + testPH + `",}` + "\n"},
	}
	rep := passwordReplacer()
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			if got := rep.redact([]byte(c.in), kind).out; string(got) != c.want {
				t.Errorf("%s, kind %d: got %s, want %s", c.name, kind, got, c.want)
			}
		}
	}
	// --explain has to hide it as well
	got := explainOutput(t, cases[0].in, []secret{{value: testValue, label: "password"}}, "password")
	if strings.Contains(got, testTail) || !strings.Contains(got, testPH) {
		t.Errorf("explain: %s", got)
	}
}

func TestDetectPairAcrossLinesInBrokenFile(t *testing.T) {
	in := "{\n  \"password\":\n    \"" + fakePassword + "\",\n}\n"
	want := "{\n  \"password\":\n    \"[REDACTED:password]\",\n}\n"
	for _, file := range []string{"c.json", "c.jsonl"} {
		if got := scrubFile(t, file, in); got != want {
			t.Errorf("%s: got %s, want %s", file, got, want)
		}
	}
}

func TestRedactSecretsAcrossLines(t *testing.T) {
	one, two := "AAAAAAAABBBBBBBB", "BBBBBBBB\nCCCCCCCC"
	cases := []struct {
		name, one, two, in, want string
		counts, left             map[int]int
		skipped                  int
	}{
		{
			"overlapping, no JSON", one, two,
			"not json AAAAAAAABBBBBBBB\nCCCCCCCC tail\n",
			"not json [REDACTED:one] tail\n",
			map[int]int{0: 1, 1: 1}, map[int]int{}, 0,
		},
		{
			"alone, no JSON", "ZZZZZZZZ", two,
			"[x] BBBBBBBB\nCCCCCCCC tail\n{\"a\":1}\n",
			"[x] [REDACTED:two] tail\n{\"a\":1}\n",
			map[int]int{1: 1}, map[int]int{}, 0,
		},
		{
			"overlapping, ends a JSON line", one, `BBBBBBBB"}` + "\n" + `{"b":"CCCCCCCC`,
			`{"a":"AAAAAAAABBBBBBBB"}` + "\n" + `{"b":"CCCCCCCC"}` + "\n",
			`{"a":"[REDACTED:one]"}` + "\n" + `{"b":"CCCCCCCC"}` + "\n",
			map[int]int{0: 1}, map[int]int{1: 1}, 1,
		},
		{
			"alone, ends a JSON line", "ZZZZZZZZ", `x"}` + "\n" + `{"y`,
			`{"a":"x"}` + "\n" + `{"y":1}` + "\n",
			`{"a":"x"}` + "\n" + `{"y":1}` + "\n",
			map[int]int{}, map[int]int{1: 1}, 1,
		},
		{
			"one JSON line, one not", "ZZZZZZZZ", `x"}` + "\n" + `no`,
			`{"a":"x"}` + "\n" + `not json` + "\n",
			`{"a":"x"}` + "\n" + `not json` + "\n",
			map[int]int{}, map[int]int{1: 1}, 1,
		},
		// Taking the newline joins the next line on, so that line counts too
		{
			"ends on the newline, JSON after it", "12345678", "log line\n",
			"log line\n{\"a\":\"12345678\"}\n",
			"log line\n{\"a\":\"[REDACTED:one]\"}\n",
			map[int]int{0: 1}, map[int]int{1: 1}, 1,
		},
		{
			"ends on the newline, text after it", "12345678", "log line\n",
			"log line\nplain 12345678\n{\"a\":1}\n",
			"[REDACTED:two]plain [REDACTED:one]\n{\"a\":1}\n",
			map[int]int{0: 1, 1: 1}, map[int]int{}, 0,
		},
		{
			"starts on the newline after JSON", "ZZZZZZZZ", "\nlog line",
			"{\"a\":1}\nlog line\n",
			"{\"a\":1}\nlog line\n",
			map[int]int{}, map[int]int{1: 1}, 1,
		},
	}
	for _, c := range cases {
		rep := newReplacer([]secret{{value: c.one, label: "one"}, {value: c.two, label: "two"}})
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			red := rep.redact([]byte(c.in), kind)
			if string(red.out) != c.want {
				t.Errorf("%s, kind %d: got %q, want %q", c.name, kind, red.out, c.want)
			}
			if !maps.Equal(red.counts, c.counts) || !maps.Equal(red.left, c.left) || red.skipped != c.skipped {
				t.Errorf("%s, kind %d: counts %v, left %v, skipped %d", c.name, kind, red.counts, red.left, red.skipped)
			}
		}
	}
}

// A block of key text in a config file that happens to start like JSON
func TestRedactKeyBlockInBrokenDocument(t *testing.T) {
	block := "-----BEGIN KEY-----\nQ2xhdWRl\nU2NydWI0\n-----END KEY-----"
	rep := newReplacer([]secret{{value: block, label: "private_key"}})
	in := "[section]\nkey = " + block + "\nother = 1\n"
	want := "[section]\nkey = [REDACTED:private_key]\nother = 1\n"
	for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
		red := rep.redact([]byte(in), kind)
		if string(red.out) != want || red.counts[0] != 1 {
			t.Errorf("kind %d: got %q, counts %v", kind, red.out, red.counts)
		}
	}
}

func TestLeftAcrossLinesIsReported(t *testing.T) {
	secrets := []secret{{value: `x"}` + "\n" + `{"y`, label: "two", prio: prioKnown}}
	rep := newReplacer(secrets)
	path := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(path, []byte(`{"a":"x"}`+"\n"+`{"y":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := summarize(secrets, []fileResult{redactFile(rep, path, false)})
	if sum.found != 1 || sum.skipped != 1 || sum.occurrences != 0 {
		t.Errorf("found %d, skipped %d, occurrences %d", sum.found, sum.skipped, sum.occurrences)
	}
}

func TestRedactInvalidDocumentKeepsValidLines(t *testing.T) {
	rep := newReplacer([]secret{{value: "12345678", label: "pin"}})
	cases := []struct {
		name, in, want string
		n, left        int
	}{
		{"redaction would break it", `{"pin":12345678}` + "\n" + `{"b":1}` + "\n", `{"pin":12345678}` + "\n" + `{"b":1}` + "\n", 0, 1},
		{"other lines still go", `{"pin":12345678}` + "\n" + `{"b":"12345678"}` + "\n", `{"pin":12345678}` + "\n" + `{"b":"[REDACTED:pin]"}` + "\n", 1, 1},
		{"beside a broken line", `{"pin":12345678}` + "\n" + `oops 12345678` + "\n", `{"pin":12345678}` + "\n" + `oops [REDACTED:pin]` + "\n", 1, 1},
	}
	for _, c := range cases {
		red := rep.redact([]byte(c.in), kindJSONDoc)
		if string(red.out) != c.want {
			t.Errorf("%s: got %q, want %q", c.name, red.out, c.want)
		}
		if sumCounts(red.counts) != c.n || sumCounts(red.left) != c.left || red.skipped != c.left {
			t.Errorf("%s: counts %v, left %v, skipped %d", c.name, red.counts, red.left, red.skipped)
		}
	}
}

func TestJoinedSecretCountsInEveryKind(t *testing.T) {
	rep := newReplacer([]secret{{value: "AAAAAAAABBBBBBBB", label: "one"}, {value: "BBBBBBBBCCCCCCCC", label: "two"}})
	in := `{"a":"x AAAAAAAABBBBBBBBCCCCCCCC y"}`
	for _, kind := range []fileKind{kindText, kindJSONDoc, kindJSONLines} {
		red := rep.redact([]byte(in), kind)
		if want := `{"a":"x [REDACTED:one] y"}`; string(red.out) != want {
			t.Errorf("kind %d: got %s", kind, red.out)
		}
		if red.counts[0] != 1 || red.counts[1] != 1 {
			t.Errorf("kind %d: counts %v, want one of each", kind, red.counts)
		}
	}
}

func TestExplainJoinedSpelledSecret(t *testing.T) {
	secrets := []secret{{value: "AAAAAAAABBBBBBBB", label: "one"}, {value: "BBBBBBBBCCCC" + testValue, label: "two"}}
	// JSON gets decoded for --explain, so only a text file keeps the escape
	for _, in := range []string{
		"log x AAAAAAAABBBBBBBBCCCCp" + escOnce + testTail + " y\n",
		`{"a":"x AAAAAAAABBBBBBBBCCCCp` + escTwice + testTail + ` y"}` + "\n",
	} {
		got := explainOutput(t, in, secrets, "two")
		if strings.Contains(got, "no occurrence") || !strings.Contains(got, "[REDACTED:one]") {
			t.Errorf("not located: %s", got)
		}
		if strings.Contains(got, "CCCC") || strings.Contains(got, testTail) {
			t.Errorf("fragment shown: %s", got)
		}
	}
}

func TestExplainAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	const pad = "                                                                                                    "
	files := []struct{ name, content string }{
		{"a.jsonl", `{"a":"in a FirstValue-Lantern-77` + pad + `end a"}` + "\n"},
		{"b.jsonl", `{"a":"in b SecondValue-Lantern-77 and FirstValue-Lantern-77"}` + "\n"},
		{"c.jsonl", `{"a":"in c ThirdValue-Lantern-77"}` + "\n"},
	}
	secrets := []secret{
		{value: "FirstValue-Lantern-77", label: "pw"},
		{value: "SecondValue-Lantern-77", label: "pw"},
		{value: "ThirdValue-Lantern-77", label: "pw"},
		{value: "NeverSeen-Lantern-77", label: "pw", prio: prioName},
	}
	rep := newReplacer(secrets)
	var results []fileResult
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, []byte(f.content), 0o600); err != nil {
			t.Fatal(err)
		}
		results = append(results, redactFile(rep, path, false))
	}
	var out strings.Builder
	explain(&out, rep, summarize(secrets, results), "pw")
	got := out.String()
	for _, want := range []string{"1. " + displayPath(filepath.Join(dir, "a.jsonl")), "2. " + displayPath(filepath.Join(dir, "b.jsonl")), "3. " + displayPath(filepath.Join(dir, "c.jsonl")), "4. (no occurrence)"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %s", want, got)
		}
	}
	if strings.Contains(got, "Lantern") {
		t.Errorf("secret shown: %s", got)
	}
}

// detected returns the values the rules and pairs find in data.
func detected(t *testing.T, data string, kind fileKind) []string {
	t.Helper()
	d, err := newDetector(false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	add := func(c candidate) { got = append(got, c.value) }
	d.scanLines(keywordLinesIn(newLineFinder(nil), []byte(data), kind, add), add)
	return got
}

func TestTornValueStaysOnItsLine(t *testing.T) {
	start := `[INFO] "password":"` + fakePassword
	done := `[INFO] "password":"[REDACTED:password]`
	cases := []struct{ name, tail string }{
		{"text after it", "\nimportant log line one\nimportant two, said \"hi\" bye\n"},
		{"JSON after it", "\n" + `{"a":"b","c":"d"}` + "\n"},
	}
	for _, c := range cases {
		if got, want := scrubFile(t, "app.log", start+c.tail), done+c.tail; got != want {
			t.Errorf("%s: got %q, want %q", c.name, got, want)
		}
		for _, v := range detected(t, start+c.tail, kindJSONDoc) {
			if strings.Contains(v, "\n") {
				t.Errorf("%s: value across lines: %q", c.name, v)
			}
		}
	}
	// Spelled with an escape, the first line is all that can be told apart
	in := "{\n \"password\": \"p" + escOnce + "ss-Tea\npot-Lantern-77\",\n}\n"
	want := "{\n \"password\": \"[REDACTED:password]\npot-Lantern-77\",\n}\n"
	if got := scrubFile(t, "c.json", in); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDetectPairsSplitAcrossLines(t *testing.T) {
	v := `"` + fakePassword + `"`
	done := `"[REDACTED:password]"`
	cases := []struct{ name, in, want string }{
		{"after a torn line", "{\n \"note\": \"torn\n \"password\":\n   " + v + ",\n}\n", "{\n \"note\": \"torn\n \"password\":\n   " + done + ",\n}\n"},
		{"before a torn line", "{\n \"password\":\n   " + v + ",\n \"note\": \"torn\n}\n", "{\n \"password\":\n   " + done + ",\n \"note\": \"torn\n}\n"},
		{"colon on its own line", "{\n\"password\"\n:\n" + v + ",\n}\n", "{\n\"password\"\n:\n" + done + ",\n}\n"},
		{"blank lines between", "{\n\"password\":\n\n   \n" + v + ",\n}\n", "{\n\"password\":\n\n   \n" + done + ",\n}\n"},
		{"something in between", "{\n\"password\":\njunk " + v + ",\n}\n", "{\n\"password\":\njunk " + v + ",\n}\n"},
	}
	for _, c := range cases {
		if got := scrubFile(t, "c.json", c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRedactAfterBackslashOutsideJSON(t *testing.T) {
	rep := newReplacer([]secret{{value: fakePassword, label: "password"}})
	const ph = "[REDACTED:password]"
	cases := []struct{ name, in, want string }{
		{"log", `[INFO] path C:\` + fakePassword + "\n", `[INFO] path C:\` + ph + "\n"},
		{"not JSON after all", `{not json \` + fakePassword + "\n", `{not json \` + ph + "\n"},
		{"beside a JSON line", `{"a":1}` + "\n" + `oops \` + fakePassword + "\n", `{"a":1}` + "\n" + `oops \` + ph + "\n"},
	}
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			if got := rep.redact([]byte(c.in), kind).out; string(got) != c.want {
				t.Errorf("%s, kind %d: got %q, want %q", c.name, kind, got, c.want)
			}
		}
	}
	// In JSON that first byte belongs to an escape, whichever way the file is laid out
	rep = newReplacer([]secret{{value: "nabc12345XY", label: "password"}})
	for _, c := range []struct {
		in   string
		kind fileKind
	}{
		{`{"a":"x\nabc12345XY"}` + "\n" + `oops` + "\n", kindJSONLines},
		{`{"a":"x\nabc12345XY"}` + "\n" + `oops` + "\n", kindJSONDoc},
		{"{\n  \"a\": \"x\\nabc12345XY\"\n}\n", kindJSONDoc},
	} {
		if got := rep.redact([]byte(c.in), c.kind).out; string(got) != c.in {
			t.Errorf("kind %d: got %q", c.kind, got)
		}
	}
	if got, want := scrubFile(t, "app.log", `[log] TOKEN=\`+fakePassword+"\n"), `[log] TOKEN=\[REDACTED:token]`+"\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBareScalarLinesAreText(t *testing.T) {
	rep := newReplacer([]secret{{value: "BEGIN\n12345\nEND", label: "block"}, {value: "12345678", label: "pin"}})
	cases := []struct{ name, in, want string }{
		{"in a block", "[section]\nkey = BEGIN\n12345\nEND\nother\n", "[section]\nkey = [REDACTED:block]\nother\n"},
		{"a line of its own", "[log]\n12345678\nfoo 12345678\n", "[log]\n[REDACTED:pin]\nfoo [REDACTED:pin]\n"},
		{"beside JSON", `{"a":1}` + "\n12345678\n", `{"a":1}` + "\n[REDACTED:pin]\n"},
	}
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			red := rep.redact([]byte(c.in), kind)
			if string(red.out) != c.want || sumCounts(red.left) != 0 {
				t.Errorf("%s, kind %d: got %q, left %v", c.name, kind, red.out, red.left)
			}
		}
	}
}

func TestOneBadHitKeepsOnlyItself(t *testing.T) {
	rep := newReplacer([]secret{{value: "12345678", label: "pin"}, {value: fakePassword, label: "password"}})
	const ph = "[REDACTED:password]"
	cases := []struct {
		name, in, want string
		counts, left   map[int]int
	}{
		{
			"beside a string secret",
			`{"pin":12345678,"password":"` + fakePassword + `"}`,
			`{"pin":12345678,"password":"` + ph + `"}`,
			map[int]int{1: 1}, map[int]int{0: 1},
		},
		{
			"many of both",
			`{"p":12345678,"a":"12345678","b":"x ` + fakePassword + ` y","c":12345678,"d":"` + fakePassword + `"}`,
			`{"p":12345678,"a":"[REDACTED:pin]","b":"x ` + ph + ` y","c":12345678,"d":"` + ph + `"}`,
			map[int]int{0: 1, 1: 2}, map[int]int{0: 2},
		},
	}
	for _, c := range cases {
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			red := rep.redact([]byte(c.in), kind)
			if string(red.out) != c.want {
				t.Errorf("%s, kind %d: got %s, want %s", c.name, kind, red.out, c.want)
			}
			if !maps.Equal(red.counts, c.counts) || !maps.Equal(red.left, c.left) || red.skipped != 1 {
				t.Errorf("%s, kind %d: counts %v, left %v, skipped %d", c.name, kind, red.counts, red.left, red.skipped)
			}
		}
	}
}

func TestExplainFindsWhatWasLeft(t *testing.T) {
	across := `x"}` + "\n" + `{"y`
	cases := []struct {
		name, in string
		value    string
	}{
		{"across lines", `{"a":"x"}` + "\n" + `{"y":1}` + "\n", across},
		{"a bare number", `{"pin":12345678}` + "\n", "12345678"},
		{"breaking a string", `{"a":"abcd1234","b":"y"}` + "\n", `abcd1234"`},
	}
	for _, c := range cases {
		got := explainOutput(t, c.in, []secret{{value: c.value, label: "left"}}, "left")
		if strings.Contains(got, "no occurrence") || !strings.Contains(got, "[REDACTED:left]") {
			t.Errorf("%s: not located: %s", c.name, got)
		}
		if strings.Contains(got, strings.ReplaceAll(c.value, "\n", " ")) {
			t.Errorf("%s: secret shown: %s", c.name, got)
		}
	}

	// Redacted in one file for another value, left in the next for this one
	dir := t.TempDir()
	secrets := []secret{{value: "Other-Value-Lantern-77", label: "pw"}, {value: "12345678", label: "pw"}}
	rep := newReplacer(secrets)
	var results []fileResult
	for name, content := range map[string]string{"a.jsonl": `{"a":"Other-Value-Lantern-77"}` + "\n", "b.jsonl": `{"pin":12345678}` + "\n"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		results = append(results, redactFile(rep, path, false))
	}
	var out strings.Builder
	explain(&out, rep, summarize(secrets, results), "pw")
	if got := out.String(); strings.Contains(got, "no occurrence") || strings.Contains(got, "12345678") {
		t.Errorf("explain: %s", got)
	}
}

func TestExplainHidesSecretAcrossBrokenLines(t *testing.T) {
	in := `[a "x" BEGIN-Lantern` + "\n" + `END-Lantern "y" Other-Value-Lantern-77 \n` + "\n"
	secrets := []secret{{value: "BEGIN-Lantern\nEND-Lantern", label: "block"}, {value: "Other-Value-Lantern-77", label: "other"}}
	got := explainOutput(t, in, secrets, "other")
	if strings.Contains(got, "BEGIN-Lantern") || strings.Contains(got, "END-Lantern") {
		t.Errorf("fragment shown: %s", got)
	}
	if !strings.Contains(got, "[REDACTED:block]") || !strings.Contains(got, "[REDACTED:other]") {
		t.Errorf("no placeholder: %s", got)
	}
}

func TestSkippedCountsLines(t *testing.T) {
	cases := []struct {
		name    string
		values  []string
		in      string
		left    int
		skipped int
	}{
		{"overlapping across lines", []string{`x"}` + "\n" + `{"y`, `"}` + "\n" + `{"y`}, `{"a":"x"}` + "\n" + `{"y":1}` + "\n", 2, 1},
		{"across lines and on the line", []string{`x"}` + "\n" + `{"y`, "12345678"}, `{"p":12345678,"a":"x"}` + "\n" + `{"y":1}` + "\n", 2, 1},
		{"two lines", []string{"12345678"}, `{"p":12345678}` + "\n" + `{"q":12345678}` + "\n", 2, 2},
	}
	for _, c := range cases {
		var secrets []secret
		for _, v := range c.values {
			secrets = append(secrets, secret{value: v, label: "x"})
		}
		red := newReplacer(secrets).redact([]byte(c.in), kindJSONLines)
		if sumCounts(red.left) != c.left || red.skipped != c.skipped {
			t.Errorf("%s: left %v, skipped %d, want %d, %d", c.name, red.left, red.skipped, c.left, c.skipped)
		}
	}
}
