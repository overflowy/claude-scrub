package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
