# claude-scrub

<img width="790" height="602" alt="demo" src="https://github.com/user-attachments/assets/23841ac2-dc29-4714-b7d2-4da3c275fede" />

Claude Code keeps everything you and the model saw in plain text under
`~/.claude`. That includes every `cat .env`, every config file it read and
every token you pasted into a prompt. claude-scrub finds the secrets in that
history and replaces each one with a label:

```
DB_PASSWORD=[REDACTED:db_password]
```

It covers session transcripts (subagents and tool results included), prompt
history, the paste cache, file history and shell snapshots. It leaves
settings, plugins and live session state alone.

## Install

### Prebuilt binary

Download the file for your platform from the
[releases page](https://github.com/overflowy/claude-scrub/releases/latest),
make it executable, and put it on your `PATH`. With the GitHub CLI, on an
Apple Silicon Mac:

```sh
gh release download -R overflowy/claude-scrub -p '*darwin_arm64'
chmod +x claude-scrub_*_darwin_arm64
mv claude-scrub_*_darwin_arm64 ~/.local/bin/claude-scrub
```

The other builds are `darwin_amd64`, `linux_amd64`, `linux_arm64`,
`windows_amd64.exe` and `windows_arm64.exe`. `checksums.txt` has their
SHA-256 sums. The macOS binaries aren't signed, so if macOS refuses to run
one, clear the quarantine flag with
`xattr -d com.apple.quarantine ~/.local/bin/claude-scrub`.

### With Go

Needs Go 1.26 or newer.

```sh
go install github.com/overflowy/claude-scrub@latest
```

This puts the binary in `$(go env GOPATH)/bin`, usually `~/go/bin`.

### From source

Needs Go 1.26 or newer and [Task](https://taskfile.dev).

```sh
git clone https://github.com/overflowy/claude-scrub
cd claude-scrub
task install   # builds ~/.local/bin/claude-scrub
```

`task --list` shows the other tasks. `task check` runs gofmt, go fix, go vet
and the tests without changing anything.

## Usage

Start with a dry run. It prints a table of labels with how many values and
occurrences it found, and changes nothing.

```sh
claude-scrub --dry-run
```

To see why something was flagged, ask for the text around each value of a
label. The snippet is redacted too.

```sh
claude-scrub -n --explain token
```

When the report looks right, run it for real. It asks before writing.

```sh
claude-scrub
```

Without a terminal to confirm on, it refuses to write unless you pass
`--force`.

It skips files modified in the last 10 minutes, so it won't rewrite a session
that's still running. Change that with `--min-age`. Paths given as arguments
are scanned whatever their age.

### After every session

Add a SessionEnd hook to `~/.claude/settings.json` and each session gets
scrubbed when it ends. Use the path you installed the binary to:

```json
{
  "hooks": {
    "SessionEnd": [
      { "hooks": [{ "type": "command", "command": "~/.local/bin/claude-scrub --hook" }] }
    ]
  }
}
```

The hook redacts that session's transcript, its subagent and tool result
files, and `history.jsonl`. It prints nothing unless it redacted something
or failed.

### Your own secrets and false positives

Put values that must always go in `~/.config/claude-scrub/secrets`, one
`label=value` per line. You can also point `--env-file` at a `.env`, shell or
YAML file and it picks out the secrets in it.

Put false positives in `~/.config/claude-scrub/allow`, one value per line.
`label:NAME` skips a whole label.

## How it finds secrets

There are four sources, from most to least trusted:

1. Your secrets file and any `--env-file`.
2. Values assigned to secret-looking names, such as `DB_PASSWORD=...`,
   `"apiKey": "..."` or `--password=...`. The value has to look like a secret:
   at least 8 characters, a mix of character types, and not a path, date,
   placeholder or piece of code.
3. Passwords in URLs (`postgres://user:pass@host`) and `Authorization: Bearer`
   or `Basic` headers.
4. The [gitleaks](https://github.com/gitleaks/gitleaks) rules, which know about
   200+ token formats (AWS, GitHub, Slack, OpenAI, private keys and more).

Every value found anywhere gets redacted everywhere. If a password shows up
once as `DB_PASSWORD=...` and later on its own in a `psql` command, both go.

## How it rewrites files

Transcripts are JSON lines, and the same secret can sit in them as is,
escaped once, or escaped twice when a tool returned JSON. claude-scrub looks
for all three forms and only cuts where the cut can't break an escape
sequence. Any line that would stop being valid JSON is left alone and
reported.

Every other byte stays the same. Each file is written to a temporary file and
renamed into place, keeping its mode and modification time. If a running
session appends to a file while it's being rewritten, claude-scrub notices
and tries again.

## Speed

A dry run over 1.3 GB of history takes about 5 seconds on an 18-core M5
Pro. Most lines contain none of the keywords any rule needs, so they're
dropped before a regex runs. Very long lines, like a minified bundle a tool
printed, are cut into windows around each keyword.

## Limits

- Detection is best effort. A password that never appears next to a
  secret-looking name is missed unless it's in your secrets file. The same
  goes for derived values, like a base64-encoded `id:key`.
- `--explain` and `--peek` print text from your history. Everything found is
  redacted in it, but anything the detectors missed shows as is.
- Redaction is permanent. There is no backup, since a backup would hold the
  secrets.
