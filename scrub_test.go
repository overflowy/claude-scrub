package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		"{\"key\":\"nabc12345XY\n\n1234\nabc12345XY\",\"other\":\"val\"}\n",
		"{\n \"a\": \"line\\nabc12345XY\"\n}\n",
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
			// However a valid file was taken, it stays valid
			if kind != kindText && isStructuredJSON(in) && !json.Valid(red.out) {
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

// A private key block as it sits raw in a file, with extra lines before its body.
// Built at run time so the source holds no key block for scanners.
func fakeKeyBlock(header string, short string) string {
	body := strings.Repeat("Q2xhdWRlU2NydWJUZXN0S2V5TWF0ZXJpYWw0Mg", 8)
	return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + header + body[:64] + "\n" + body[64:128] + "\n" + short +
		body[128:192] + "\n-----END " + "RSA PRIVATE KEY-----"
}

func TestDetectKeyBlockInLinesThatAreNotJSON(t *testing.T) {
	const ph = "[REDACTED:private_key]"
	plain := fakeKeyBlock("", "")
	encrypted := fakeKeyBlock("Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n", "")
	cases := []struct{ name, in, want string }{
		{"strings after it on its last line", `{"key":"` + plain + `","other":"val"}` + "\n", `{"key":"` + ph + `","other":"val"}` + "\n"},
		{"strings before it on its first line", `{"other":"val","key":"` + plain + `"}` + "\n", `{"other":"val","key":"` + ph + `"}` + "\n"},
		{"a blank line in it", `{"a":1}` + "\n" + encrypted + "\n", `{"a":1}` + "\n" + ph + "\n"},
		{"blank line, after JSON with strings", `{"a":"b"}` + "\n" + encrypted + "\nmore\n", `{"a":"b"}` + "\n" + ph + "\nmore\n"},
		{"a short line of digits", `{"a":1}` + "\n" + fakeKeyBlock("", "1234\n") + "\n", `{"a":1}` + "\n" + ph + "\n"},
		{"a line that is a JSON word", "[x]\n" + fakeKeyBlock("", "true\n") + "\n", "[x]\n" + ph + "\n"},
		{"all of those", `{"key":"` + fakeKeyBlock("Proc-Type: 4,ENCRYPTED\n\n", "1234\n") + `","other":"val"}` + "\n", `{"key":"` + ph + `","other":"val"}` + "\n"},
	}
	for _, c := range cases {
		for _, file := range []string{"s.jsonl", "c.json"} {
			if got := scrubFile(t, file, c.in); got != c.want {
				t.Errorf("%s, %s: got %q, want %q", c.name, file, got, c.want)
			}
		}
	}
}

// What the rules see of lines that are not JSON has to be what the file holds, or
// a value spanning them will not match anything in the file.
func TestDetectorTextKeepsBrokenLines(t *testing.T) {
	const begin, end = "-----BEGIN KEY-----", "-----END KEY-----"
	cases := []struct{ name, in, want string }{
		{"as they are", begin + "\nabc\n\n1234\n  \n" + end + "\n", begin + "\nabc\n\n1234\n  \n" + end},
		{"strings do not get in between", begin + "\nx \"a\" y \"b\" z\n" + end + "\n", begin + "\nx \"a\" y \"b\" z\n" + end},
		{"JSON between them keeps them apart", "token curl x\nabc\n{\"n\":1}\ndef\n", "token curl x\nabc\n\ndef\n\n"},
	}
	for _, c := range cases {
		lines := keywordLinesIn(newLineFinder(nil), []byte(c.in), kindJSONLines, func(candidate) {})
		if len(lines) == 0 || lines[0].text != c.want {
			t.Errorf("%s: got %+v, want %q", c.name, lines, c.want)
		}
	}
}

func TestRedactBesideSecretThatWouldBreakJSON(t *testing.T) {
	const one, two = "[REDACTED:one]", "[REDACTED:two]"
	cases := []struct {
		name          string
		first, second string
		in, want      string
		counts, left  map[int]int
		skipped       int
		only          fileKind // 0 for both JSON kinds
	}{
		{
			"overlapping", "abcdefgh", `efgh","b`,
			`{"k":"abcdefgh","b":1}`, `{"k":"` + one + `","b":1}`,
			map[int]int{0: 1}, map[int]int{1: 1}, 1, 0,
		},
		{
			"inside the one that breaks it", "pass1234", `pass1234"`,
			`{"k":"pass1234"}`, `{"k":"` + one + `"}`,
			map[int]int{0: 1}, map[int]int{1: 1}, 1, 0,
		},
		{
			"on a later line", "abcdefgh", `efgh","b`,
			`{"z":"y"}` + "\n" + `{"k":"abcdefgh","b":1}` + "\n", `{"z":"y"}` + "\n" + `{"k":"` + one + `","b":1}` + "\n",
			map[int]int{0: 1}, map[int]int{1: 1}, 1, 0,
		},
		{
			"across a document", "abcdefgh", `efgh","b`,
			"{\n \"k\": \"abcdefgh\",\"b\":1\n}\n", "{\n \"k\": \"" + one + "\",\"b\":1\n}\n",
			map[int]int{0: 1}, map[int]int{1: 1}, 1, kindJSONDoc,
		},
		{
			"breaking nested JSON", "abc12345XY", "nabc12345XY",
			`{"a":"{\"b\":\"line\\nabc12345XY\"}"}`, `{"a":"{\"b\":\"line\\n` + one + `\"}"}`,
			map[int]int{0: 1}, map[int]int{1: 1}, 1, 0,
		},
		{
			"beside others that are fine", "abcdefgh", `efgh","b`,
			`{"k":"abcdefgh","b":"abcdefgh"}`, `{"k":"` + one + `","b":"` + one + `"}`,
			map[int]int{0: 2}, map[int]int{1: 1}, 1, 0,
		},
		{
			"both fine, one inside the other", "AAAABBBB", "BBBB",
			`{"k":"x AAAABBBB y"}`, `{"k":"x ` + one + ` y"}`,
			map[int]int{0: 1, 1: 1}, map[int]int{}, 0, 0,
		},
		{
			"the longer one alone is fine", "BBBB", "AAAABBBB",
			`{"k":"x AAAABBBB y"}`, `{"k":"x ` + two + ` y"}`,
			map[int]int{0: 1, 1: 1}, map[int]int{}, 0, 0,
		},
	}
	for _, c := range cases {
		rep := newReplacer([]secret{{value: c.first, label: "one"}, {value: c.second, label: "two"}})
		for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
			if c.only != 0 && kind != c.only {
				continue
			}
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

func TestMergeHits(t *testing.T) {
	// The same secret found twice over is still one hit
	hits := []hit{{start: 2, end: 6, secret: 0}, {start: 2, end: 6, secret: 0}}
	if got := mergeHits(hits); len(got) != 1 || got[0].joined != nil {
		t.Errorf("got %+v", got)
	}
	hits = []hit{{start: 3, end: 4, secret: 2}, {start: 0, end: 4, secret: 0}, {start: 2, end: 6, secret: 1}, {start: 2, end: 6, secret: 1}}
	got := mergeHits(hits)
	if len(got) != 1 || got[0].end != 6 || !slices.Equal(got[0].joined, []int{1, 2}) {
		t.Errorf("got %+v", got)
	}
	// What went in stays, in order, for taking a joined hit apart
	if len(hits) != 4 || hits[0].secret != 0 || hits[3].secret != 2 {
		t.Errorf("occurrences %+v", hits)
	}
}

// A secret that overlaps itself matches at every byte of a long run of it
func TestRedactLongRunsOfOverlaps(t *testing.T) {
	rep := newReplacer([]secret{{value: "00000000", label: "pin"}})
	run := strings.Repeat("0", 1<<20)
	done := make(chan struct{})
	go func() {
		defer close(done)
		red := rep.redact([]byte(`{"a":"`+run+`"}`), kindJSONLines)
		if want := `{"a":"[REDACTED:pin]"}`; string(red.out) != want || red.counts[0] != 1 {
			t.Errorf("in a string: got %d bytes, counts %v", len(red.out), red.counts)
		}
		// None of it can go, and trying each match would parse the line a million times
		in := `{"a":1` + run + `}`
		red = rep.redact([]byte(in), kindJSONLines)
		if string(red.out) != in || len(red.counts) != 0 || red.skipped != 1 {
			t.Errorf("in a number: got %d bytes, counts %v, skipped %d", len(red.out), red.counts, red.skipped)
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("too slow")
	}
}

// fakeOtherKeyBlock is a complete key to tell apart from fakeKeyBlock's.
func fakeOtherKeyBlock() string {
	return strings.ReplaceAll(fakeKeyBlock("", ""), "Q2xhdWRl", "RmFrZUtl")
}

func TestDetectKeyAfterTornBlock(t *testing.T) {
	block := fakeKeyBlock("", "")
	torn := block[:strings.LastIndex(block, "\n")]
	key := fakeOtherKeyBlock()
	cases := []struct{ name, file, in string }{
		{"then a valid line holding it", "s.jsonl", `{"a":1}` + "\n" + torn + "\n" + `{"note":"` + jsonEscape(key) + `"}` + "\n"},
		{"then it, raw", "s.jsonl", torn + "\n" + key + "\n"},
		{"then it, in a document", "c.json", `{"a":1}` + "\n" + torn + "\n" + key + "\n"},
		{"in a text file", "app.log", "log\n" + torn + "\nmore\n" + key + "\n"},
		{"only a header in the string before", "s.jsonl", `{"a":"` + block[:strings.Index(block, "\n")] + `"}` + "\n" + `{"note":"` + jsonEscape(key) + `"}` + "\n"},
	}
	for _, c := range cases {
		if got := scrubFile(t, c.file, c.in); strings.Contains(got, "RmFrZUtl") {
			t.Errorf("%s: key left: %q", c.name, got)
		}
	}
}

func TestValidDocumentStaysValidInAnyFile(t *testing.T) {
	rep := newReplacer([]secret{{value: "nabc12345XY", label: "x"}})
	in := "{\n \"a\": \"line\\nabc12345XY\"\n}\n"
	for _, kind := range []fileKind{kindJSONLines, kindJSONDoc} {
		if red := rep.redact([]byte(in), kind); string(red.out) != in {
			t.Errorf("kind %d: got %q", kind, red.out)
		}
	}
	rep = newReplacer([]secret{{value: "nabc12345XY", label: "x"}, {value: testValue, label: "password"}})
	in = "{\n \"a\": \"p" + escOnce + testTail + "\",\n \"b\": \"ok\"\n}\n"
	want := "{\n \"a\": \"" + testPH + "\",\n \"b\": \"ok\"\n}\n"
	if red := rep.redact([]byte(in), kindJSONLines); string(red.out) != want {
		t.Errorf("got %q, want %q", red.out, want)
	}
}

func TestJSONFileWithBadFirstLine(t *testing.T) {
	spelled := `{"password":"p` + escOnce + testTail + `"}`
	for _, file := range []string{"s.jsonl", "history.jsonl.bak", "c.json"} {
		// Decoded for the rules, even though it starts like text
		in, want := "torn\n"+spelled+"\n", "torn\n"+`{"password":"`+testPH+`"}`+"\n"
		if got := scrubFile(t, file, in); got != want {
			t.Errorf("%s: got %q, want %q", file, got, want)
		}
		// And its valid lines are protected
		path := filepath.Join(t.TempDir(), file)
		line := "torn\n" + `{"k":"abcdefgh","b":1}` + "\n"
		if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		rep := newReplacer([]secret{{value: `efgh","b`, label: "x"}})
		if res := redactFile(rep, path, true); res.err != nil || res.skipped != 1 {
			t.Errorf("%s: err %v, skipped %d", file, res.err, res.skipped)
		}
		if got, _ := os.ReadFile(path); string(got) != line {
			t.Errorf("%s: got %q", file, got)
		}
	}
	// Anything else still goes by how it starts
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("torn\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, kind, _, err := readTarget(path); err != nil || kind != kindText {
		t.Errorf("kind %d, err %v", kind, err)
	}
}

// Every match but the last can go, so each is tried and succeeds
func TestRedactLongRunBeforeSecretThatBreaksJSON(t *testing.T) {
	rep := newReplacer([]secret{{value: "00000000", label: "pin"}, {value: `00","b`, label: "x"}})
	in := []byte(`{"a":"` + strings.Repeat("0", 1<<20) + `","b":1}`)
	done := make(chan redaction, 1)
	go func() { done <- rep.redact(in, kindJSONLines) }()
	select {
	case red := <-done:
		if want := `{"a":"[REDACTED:pin]","b":1}`; string(red.out) != want || red.counts[0] != 1 || red.left[1] != 1 {
			t.Errorf("got %d bytes, counts %v, left %v", len(red.out), red.counts, red.left)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("too slow")
	}
}

// Wherever a complete key sits among other lines, it has to go.
func FuzzDetectKeyBlock(f *testing.F) {
	block := fakeKeyBlock("", "")
	torn := block[:strings.LastIndex(block, "\n")]
	header := block[:strings.Index(block, "\n")]
	for _, s := range []string{
		"", `{"a":1}`, `{"a":"b"}`, torn, header, `{"a":"` + header + `"}`, `{"a":"torn`, "\n\n1234\ntrue", block, `{"a":"` + jsonEscape(block) + `"}`,
	} {
		f.Add(s, "")
		f.Add("", s)
		f.Add(s, s)
	}
	d, err := newDetector(true)
	if err != nil {
		f.Fatal(err)
	}
	finder := newLineFinder(d.gl)
	key := fakeOtherKeyBlock()
	lines := strings.Split(key, "\n")
	split := strings.Join(slices.Insert(lines, 2, `{"n":1}`), "\n")
	f.Fuzz(func(t *testing.T, before, after string) {
		if strings.Contains(before+after, "RmFrZUtl") {
			return
		}
		for _, k := range []string{key, split} {
			data := []byte(before + "\n" + k + "\n" + after)
			for _, kind := range []fileKind{kindText, kindJSONLines} {
				col := newCollector()
				d.scanLines(keywordLinesIn(finder, data, kind, col.add), col.add)
				red := newReplacer(col.secrets(&allowlist{})).redact(data, kind)
				if bytes.Contains(red.out, []byte("RmFrZUtl")) {
					t.Fatalf("kind %d: key left in %q", kind, data)
				}
			}
		}
	})
}

func TestKeyBlockAroundJSONLines(t *testing.T) {
	const ph = "[REDACTED:private_key]"
	block := strings.Split(fakeKeyBlock("", ""), "\n")
	withLine := func(lines ...string) string {
		return strings.Join(slices.Concat(block[:2], lines, block[2:]), "\n")
	}
	cases := []struct{ name, in, want string }{
		{"an object", `{"a":1}` + "\n" + withLine(`{"n":1}`) + "\n", `{"a":1}` + "\n" + ph + "\n" + `{"n":1}` + "\n" + ph + "\n"},
		{"at the start of the file", withLine(`{"n":1}`) + "\n", ph + "\n" + `{"n":1}` + "\n" + ph + "\n"},
		{"a string", `{"a":1}` + "\n" + withLine(`"ab"`) + "\n", `{"a":1}` + "\n" + ph + "\n" + `"ab"` + "\n" + ph + "\n"},
		{"two in a row", withLine(`{"n":1}`, `{"m":"v"}`) + "\nmore\n", ph + "\n" + `{"n":1}` + "\n" + `{"m":"v"}` + "\n" + ph + "\nmore\n"},
		{"two apart", strings.Join([]string{block[0], block[1], `{"n":1}`, block[2], `{"m":2}`, block[3], block[4]}, "\n") + "\n",
			ph + "\n" + `{"n":1}` + "\n" + ph + "\n" + `{"m":2}` + "\n" + ph + "\n"},
	}
	for _, c := range cases {
		for _, file := range []string{"s.jsonl", "c.json"} {
			if got := scrubFile(t, file, c.in); got != c.want {
				t.Errorf("%s, %s: got %q, want %q", c.name, file, got, c.want)
			}
		}
	}
	// Starting or ending on a line of JSON, it would change that line, so it stays
	rep := newReplacer([]secret{{value: `x"}` + "\nmid\n" + `{"y`, label: "x"}})
	in := `{"a":"x"}` + "\nmid\n" + `{"y":1}` + "\n"
	if red := rep.redact([]byte(in), kindJSONLines); string(red.out) != in || red.left[0] != 1 {
		t.Errorf("got %q, left %v", red.out, red.left)
	}
}

func TestDetectorTextHoldsJSONOnlyInsideKeyBlocks(t *testing.T) {
	text := func(in string) string {
		var all []string
		for _, l := range keywordLinesIn(newLineFinder(nil), []byte(in), kindJSONLines, func(candidate) {}) {
			all = append(all, l.text)
		}
		return strings.Join(all, "|")
	}
	const begin, end = "-----BEGIN KEY-----", "-----END KEY-----"
	if got, want := text(begin+"\nabc\n{\"n\":1}\ndef\n"+end+"\n"), begin+"\nabc\n{\"n\":1}\ndef\n"+end; got != want {
		t.Errorf("inside a block: got %q, want %q", got, want)
	}
	// Past its end, and past where a block could end, JSON is read as JSON again
	line := `{"n":"` + strings.Repeat("x", 1024) + `"}` + "\n"
	for _, in := range []string{begin + "\nabc\n" + end + "\n" + line, begin + "\n" + strings.Repeat(line, 20)} {
		if got := text(in + `{"note":"secret"}` + "\n"); strings.Contains(got, `{"note"`) {
			t.Errorf("JSON kept raw: %.200q", got)
		}
	}
}

func TestRedactEndingRightAfterJSONLine(t *testing.T) {
	rep := newReplacer([]secret{{value: "abcdefgh\n" + `{"n":1}` + "\n", label: "x"}})
	in := "x abcdefgh\n" + `{"n":1}` + "\ny\n"
	want := "x [REDACTED:x]\n" + `{"n":1}` + "\ny\n"
	if red := rep.redact([]byte(in), kindJSONLines); string(red.out) != want {
		t.Errorf("got %q, want %q", red.out, want)
	}
}

// Finding values next to a name, whatever characters they start with or hold
func TestDetectSecretsThatLookLikeCode(t *testing.T) {
	cases := map[string]string{
		`Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==`:    "dXNlcjpwYXNzd29yZDEyMw==",
		`DB_PASSWORD=c3VwZXJzZWNyZXR2YWx1ZTEyMzQ1Ng==`:     "c3VwZXJzZWNyZXR2YWx1ZTEyMzQ1Ng==",
		`{"password": "c3VwZXJzZWNyZXR2YWx1ZTEyMzQ1Ng=="}`: "c3VwZXJzZWNyZXR2YWx1ZTEyMzQ1Ng==",
		`DB_PASSWORD=Pa$$w0rd!2024`:                        "Pa$$w0rd!2024",
		`DB_PASSWORD=Hunter2$Pass`:                         "Hunter2$Pass",
		`DB_PASSWORD=Hunter2Pass$`:                         "Hunter2Pass$",
		`password: $2b$12$KIXxPfnK9Lq0vWb2NcD8eO`:          "$2b$12$KIXxPfnK9Lq0vWb2NcD8eO",
		`SECRET_KEY=/9aZk3LmQ1xYtR7vWb2NcD8eFg`:            "/9aZk3LmQ1xYtR7vWb2NcD8eFg",
		`SECRET_KEY=/9j/4AAQSkZJRgABAQ/x7Gh2KpL+m3Qz==`:    "/9j/4AAQSkZJRgABAQ/x7Gh2KpL+m3Qz==",
		`API_TOKEN=!Zk3LmQ1xYtR7`:                          "!Zk3LmQ1xYtR7",
		`API_TOKEN=@Zk3LmQ1xYtR7`:                          "@Zk3LmQ1xYtR7",
		`API_TOKEN=#Zk3LmQ1xYtR7`:                          "#Zk3LmQ1xYtR7",
		`API_TOKEN=%Zk3LmQ1xYtR7`:                          "%Zk3LmQ1xYtR7",
	}
	for text, want := range cases {
		if got := detectAll(t, text); got[want] == "" {
			t.Errorf("%s: got %v, want %q", text, got, want)
		}
	}
}

// What those secrets must not be confused with
func TestDetectIgnoresReferencesAndPaths(t *testing.T) {
	for _, text := range []string{
		`token=a==Bcdefgh1`,
		`token == Bcdefgh12`,
		`password=$DB_PASSWORD`,
		`password=$dbPassword1`,
		`"token": "$API_TOKEN_1"`,
		`"token": "${API_TOKEN_1}"`,
		`"token": "prefix-${Token1}-Suffix"`,
		`token = Abc12345-${suffix}`,
		`TOKEN=Abc-$SOME_VAR`,
		`TOKEN=$HOME/.Token1`,
		`secret: /Users/someone/Projects/App1`,
		`secret: /private/tmp/com.apple.launchd.Xy12/Listeners`,
		`token: /api/V1/token`,
		`private_key: /etc/ssl/Private2/server.key`,
		`secret: /opt/ReallyLongDirectoryName2/Config`,
		`secret: ~/Projects/App1`,
		`secret: ./Projects/App1`,
		`token=!isValid2`,
		`token=!this.state.Visible1`,
		`secret: @scope/Package1`,
		`secret: @Autowired1`,
		`secret: #mainContainer1`,
		`secret: #ff00AA11`,
		`secret: #!/usr/bin/python3`,
		`password=%DB_Password1%`,
		`password=%s-Suffix1`,
		`password=%Y-%m-%d1A`,
		`"password": "%{Db_Password1}"`,
	} {
		if got := detectAll(t, text); len(got) > 0 {
			t.Errorf("%s: unexpected %v", text, got)
		}
	}
}

func TestDetectURLPasswords(t *testing.T) {
	found := map[string]string{
		`postgres://admin:hunter2hunter@db.internal/app`: "hunter2hunter",
		`postgres://admin:Hunter2Hunter@db.internal/app`: "Hunter2Hunter",
		`redis://:supersecretpassword@cache:6379`:        "supersecretpassword",
		`https://me:correct-horse-battery@host/x`:        "correct-horse-battery",
		`mysql://root:p%40ssw0rd99@db/app`:               "p%40ssw0rd99",
		`amqp://bob:Abc12345@rabbit`:                     "Abc12345",
	}
	for text, want := range found {
		if got := detectAll(t, text); got[want] != "url_password" {
			t.Errorf("%s: got %v, want %q", text, got, want)
		}
	}
	// Each of these would otherwise be redacted everywhere it appears
	for _, text := range []string{
		`postgres://postgres:postgres@localhost/app`,
		`postgres://app:postgres@localhost/app`,
		`mysql://appuser1:appuser1@db`,
		`postgres://user:password@localhost/app`,
		`postgres://user:Password@localhost/app`,
		`postgres://app:development@localhost/app`,
		`postgres://user:DB_PASSWORD@localhost/app`,
		`mysql://root:MYSQL_ROOT_PASSWORD@db/app`,
		`postgres://user:db-password-here@db`,
		`postgres://user:$PASSWORD@db`,
		`postgres://user:${DB_PASS}@db`,
		`postgres://user:{password}@db`,
		`postgres://user:[password]@db`,
		`postgres://user:<password>@db`,
		`postgres://user:your_password@db`,
		`postgres://user:%s%s%s%s@db`,
		`amqp://bob:12345678@rabbit`,
		`redis://:123456789012@cache`,
	} {
		if got := detectAll(t, text); len(got) > 0 {
			t.Errorf("%s: unexpected %v", text, got)
		}
	}
}

func TestEnvValue(t *testing.T) {
	cases := map[string]string{
		`abc123XYZ789`:         "abc123XYZ789",
		`abc123XYZ789 # prod`:  "abc123XYZ789",
		"abc123XYZ789\t# prod": "abc123XYZ789",
		`abc#123XYZ789`:        "abc#123XYZ789",
		`"Abc123XYZ" # c`:      "Abc123XYZ",
		`'Abc123XYZ' # c`:      "Abc123XYZ",
		`"Abc 123 # XYZ"`:      "Abc 123 # XYZ",
		`"Abc 123 # XYZ" # c`:  "Abc 123 # XYZ",
		`"Abc\"123" # c`:       `Abc\"123`,
		`'Abc\' # c`:           `Abc\`,
		`Abc123XYZ" # c`:       "Abc123XYZ",
		`Abc123XYZ"`:           "Abc123XYZ",
		`# nothing set`:        "",
		``:                     "",
		`"Abc123"XYZ`:          `"Abc123"XYZ`,
	}
	for in, want := range cases {
		if got := envValue(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestLoadEnvFileComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		`API_TOKEN=abc123XYZ789 # prod`,
		`DB_PASSWORD="Abc123XYZ" # c`,
		`  - "SIGNING_KEY=Qw3rTy6UiOp" # yaml`,
		`SESSION_SECRET= # not set here`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	col := newCollector()
	if err := loadEnvFile(path, col); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range col.secrets(&allowlist{}) {
		got = append(got, s.value)
	}
	slices.Sort(got)
	want := []string{"Abc123XYZ", "Qw3rTy6UiOp", "abc123XYZ789"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func detectGitleaks(t *testing.T, text string) map[string]string {
	t.Helper()
	d, err := newDetector(true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	d.scan(newLineFinder(d.gl), text, func(c candidate) { got[c.value] = c.label })
	return got
}

// A transcript holds these files under its own name
func TestDetectRulesGatedByFileName(t *testing.T) {
	yaml := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  foo: c3VwZXJzZWNyZXQxMjM=\n"
	if got := detectGitleaks(t, yaml); got["c3VwZXJzZWNyZXQxMjM="] != "kubernetes_secret_yaml" {
		t.Errorf("Kubernetes Secret: got %v", got)
	}
	nuget := `<add key="ClearTextPassword" value="Qw3rTy6UiOp!" />`
	if got := detectGitleaks(t, nuget); got["Qw3rTy6UiOp!"] != "nuget_config_password" {
		t.Errorf("NuGet: got %v", got)
	}
	// The name rule finds this first, under its better label
	tf := `administrator_login_password = "Qw3rTy6UiOp1"`
	if got := detectGitleaks(t, tf); got["Qw3rTy6UiOp1"] == "" {
		t.Errorf("Terraform: got %v", got)
	}

	// Without the file name to go on, these say nothing
	for _, text := range []string{
		`password = "postgres"`,
		`password = "development"`,
		"kind: Secret\ndata:\n  environment: development\n",
		"kind: Secret\ndata:\n  foo: {{ .Values.foo }}\n",
		"kind: ConfigMap\ndata:\n  environment: ZGV2ZWxvcG1lbnQx\n",
		`<add key="Password" value="%NUGET_PASSWORD%" />`,
	} {
		if got := detectGitleaks(t, text); len(got) > 0 {
			t.Errorf("%q: unexpected %v", text, got)
		}
	}
}

// A secret spread over a line of JSON it can't touch is one occurrence, part of
// which stays
func TestAroundJSONLinesCountsOnce(t *testing.T) {
	block := fakeKeyBlock("", "")
	lines := strings.Split(block, "\n")
	in := strings.Join(slices.Concat(lines[:2], []string{`{"n":1}`}, lines[2:3], []string{`{"m":2}`}, lines[3:]), "\n") + "\n"
	value := strings.TrimSuffix(in, "\n")
	rep := newReplacer([]secret{{value: value, label: "private_key"}})
	red := rep.redact([]byte(in), kindJSONLines)
	if n := strings.Count(string(red.out), "[REDACTED:private_key]"); n != 3 {
		t.Errorf("got %d placeholders in %q, want 3", n, red.out)
	}
	if red.counts[0] != 1 || red.left[0] != 1 || red.skipped != 2 {
		t.Errorf("counts %v, left %v, skipped %d", red.counts, red.left, red.skipped)
	}
}

// Another secret overlapping a later part still counts, and the part does not
func TestAroundJSONLinesOverlap(t *testing.T) {
	long := "AAAAAAAA\n" + `{"n":1}` + "\nBBBBBBBB"
	cases := []struct {
		name, other string
		counts      map[int]int
	}{
		{"another secret", "BBBBBBBBCC", map[int]int{0: 1, 1: 1}},
		{"same line, same text", "BBBB", map[int]int{0: 1, 1: 1}},
	}
	for _, c := range cases {
		rep := newReplacer([]secret{{value: long, label: "x"}, {value: c.other, label: "y"}})
		red := rep.redact([]byte(long+"CC\n"), kindJSONLines)
		if !maps.Equal(red.counts, c.counts) {
			t.Errorf("%s: counts %v, want %v, out %q", c.name, red.counts, c.counts, red.out)
		}
	}
}

func TestMergeHitsCont(t *testing.T) {
	cases := []struct {
		name   string
		hits   []hit
		counts map[int]int
	}{
		{"part first", []hit{{start: 0, end: 5, secret: 0, cont: true}, {start: 2, end: 8, secret: 1}}, map[int]int{1: 1}},
		{"part second", []hit{{start: 0, end: 5, secret: 1}, {start: 2, end: 8, secret: 0, cont: true}}, map[int]int{1: 1}},
		{"same secret, part first", []hit{{start: 0, end: 5, secret: 0, cont: true}, {start: 2, end: 8, secret: 0}}, map[int]int{0: 1}},
		{"same secret, part second", []hit{{start: 0, end: 5, secret: 0}, {start: 2, end: 8, secret: 0, cont: true}}, map[int]int{0: 1}},
		{"apart", []hit{{start: 0, end: 5, secret: 0}, {start: 6, end: 8, secret: 0, cont: true}}, map[int]int{0: 1}},
	}
	for _, c := range cases {
		counts := map[int]int{}
		countHits(counts, mergeHits(c.hits))
		if !maps.Equal(counts, c.counts) {
			t.Errorf("%s: got %v, want %v", c.name, counts, c.counts)
		}
	}
}

// captureStderr returns what fn wrote to stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = stderr }()
	fn()
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func setStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	w.Close()
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin; r.Close() })
}

// The hook prints no report, but a match it left must not pass in silence
func TestHookReportsLeftMatches(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "p")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(root, "secrets")
	if err := os.WriteFile(secrets, []byte("label=nabc12345XY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(dir, "s.jsonl")
	// A match on the n of \n, the only one there is: nothing redacted, one left
	in := `{"a":"{\"b\":\"x\\nabc12345XY\"}"}` + "\n"
	if err := os.WriteFile(transcript, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	setStdin(t, `{"transcript_path":"`+transcript+`"}`)
	o := testOptions(root)
	o.hook, o.noGitleaks, o.secrets = true, true, secrets
	var err error
	out := captureStderr(t, func() { err = scrub(context.Background(), o, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Left matches in 1 JSON line") {
		t.Errorf("stderr %q", out)
	}
	if b, _ := os.ReadFile(transcript); string(b) != in {
		t.Errorf("file changed: %s", b)
	}
}

func TestUnreadableFileFailsTheRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	good, _ := writeTranscript(t, root)
	bad := filepath.Join(filepath.Dir(good), "locked.jsonl")
	if err := os.WriteFile(bad, []byte("{}\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(bad, 0o600) })

	for _, dryRun := range []bool{true, false} {
		o := testOptions(root)
		o.noGitleaks, o.dryRun, o.minAge = true, dryRun, 0
		var err error
		out := captureStderr(t, func() { err = scrub(context.Background(), o, nil) })
		if err == nil || !strings.Contains(err.Error(), "could not scan 1 file") {
			t.Errorf("dry run %v: err %v", dryRun, err)
		}
		if !strings.Contains(out, "locked.jsonl") {
			t.Errorf("dry run %v: stderr %q", dryRun, out)
		}
	}
	// The rest still went
	if b, _ := os.ReadFile(good); strings.Contains(string(b), fakePassword) {
		t.Error("the readable file was not redacted")
	}

	// And with nothing else to find, it still must not look clean
	empty := t.TempDir()
	locked := filepath.Join(empty, "locked.jsonl")
	if err := os.WriteFile(locked, []byte("{}\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o600) })
	o := testOptions(empty)
	o.noGitleaks, o.quiet = true, false
	var err error
	out := captureStderr(t, func() { err = scrub(context.Background(), o, []string{locked}) })
	if err == nil {
		t.Error("no error for a run that read nothing")
	}
	if strings.Contains(out, "Nothing to redact.\n") {
		t.Errorf("stderr %q", out)
	}
}

// A file that turns unreadable between the two passes
func TestNoteReadErrors(t *testing.T) {
	first, second := errors.New("first"), errors.New("second")
	unreadable := map[string]error{"a": first}
	noteReadErrors(unreadable, []fileResult{{path: "b", err: second}, {path: "c"}})
	if len(unreadable) != 2 || unreadable["a"] != first || unreadable["b"] != second {
		t.Errorf("got %v", unreadable)
	}
}

func TestDiscoverPathsOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	d, err := discoverPaths([]string{dir, path, path, "s.jsonl", "./s.jsonl", "."}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.targets) != 1 {
		t.Errorf("targets %v", d.targets)
	}
}

// Nothing dedupes here, so go test -race would catch two workers sharing a slot
func TestRedactAllKeepsEveryResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(path, []byte(fakePassword), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := newReplacer([]secret{{value: fakePassword, label: "password"}})
	for _, r := range redactAll(context.Background(), rep, []target{{path: path}, {path: path}, {path: path}}, 3, false) {
		if r.path != path || r.counts[0] != 1 {
			t.Errorf("result %+v", r)
		}
	}
}

func TestHookTranscriptWithoutSuffix(t *testing.T) {
	root := t.TempDir()
	transcript := filepath.Join(root, "transcript")
	if err := os.WriteFile(transcript, []byte(`{"a":"DB_PASSWORD=`+fakePassword+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setStdin(t, `{"transcript_path":"`+transcript+`"}`)
	o := testOptions(root)
	o.hook, o.noGitleaks = true, true
	var err error
	out := captureStderr(t, func() { err = scrub(context.Background(), o, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1 occurrence in 1 file") {
		t.Errorf("stderr %q", out)
	}
}

// replacedFile replaces path the way writeAtomic does, up to
// and including the rename, and returns the old file still open.
func replacedFile(t *testing.T, path string, data []byte) *os.File {
	t.Helper()
	old, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { old.Close() })
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	return old
}

// A line that reached the old file after the check is copied to the new one
func TestCopyAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.jsonl")
	before := `{"a":"` + fakePassword + `"}` + "\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	old := replacedFile(t, path, []byte(`{"a":"x"}`+"\n"))
	if _, err := old.WriteAt([]byte(`{"b":1}`+"\n"), int64(len(before))); err != nil {
		t.Fatal(err)
	}
	n, err := copyAppended(old, path, int64(len(before)))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := `{"a":"x"}` + "\n" + `{"b":1}` + "\n"
	if string(b) != want || n != 8 {
		t.Errorf("got %q (%d copied), want %q", b, n, want)
	}
}

// One that arrives just after the rename, from a writer already in flight
func TestCopyAppendedLateWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.jsonl")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := replacedFile(t, path, []byte("new\n"))
	go func() {
		time.Sleep(appendGrace / 4)
		old.WriteAt([]byte("late\n"), 4)
	}()
	if _, err := copyAppended(old, path, 4); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new\nlate\n" {
		t.Errorf("got %q", b)
	}
}

func TestCopyAppendedNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.jsonl")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := replacedFile(t, path, []byte("new\n"))
	if n, err := copyAppended(old, path, 4); n != 0 || err != nil {
		t.Errorf("copied %d, err %v", n, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new\n" {
		t.Errorf("got %q", b)
	}
}

func TestWriteAtomicNoticesReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Same size and time, but another file: another scrub got there first
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, time.Time{}, info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("z"), info); !errors.Is(err, errChanged) {
		t.Errorf("got %v, want errChanged", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "y" {
		t.Errorf("file overwritten: %q", b)
	}
}

func TestWriteAtomicKeepsModTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("y"), info); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(old) || after.Mode().Perm() != 0o640 {
		t.Errorf("mtime %v, mode %v", after.ModTime(), after.Mode().Perm())
	}
}
