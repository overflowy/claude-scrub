// Command claude-scrub redacts secrets from Claude Code history.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
)

// Set by release builds with -ldflags "-X main.version=..."
var version = ""

// buildVersion is the release version, else the module version go install
// recorded (v1.0.1, or a pseudo-version for a commit), else "dev".
func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

const usageHead = `Redact secrets from Claude Code history.

Finds secrets in transcripts, prompt history, paste cache, file history and
shell snapshots, and replaces them with [REDACTED:label]. A value found once
(say after DB_PASSWORD=) is redacted everywhere it appears.

Usage:
  claude-scrub [flags] [path...]

With no paths it scans the history under --root, skipping files modified
within --min-age (sessions still running). Paths are scanned whatever their
age.

Examples:
  claude-scrub --dry-run              # report what would be redacted
  claude-scrub                        # redact, after confirming
  claude-scrub -n -v --peek           # list files and masked values
  claude-scrub -n --explain token     # show where "token" values sit
  claude-scrub --hook                 # as a SessionEnd hook (JSON on stdin)

Flags:
`

const usageTail = `
Files:
  ~/.config/claude-scrub/secrets   label=value lines, always redacted
  ~/.config/claude-scrub/allow     values never redacted; label:NAME skips a label
`

type options struct {
	dryRun     bool
	force      bool
	root       string
	secrets    string
	secretsSet bool // given explicitly, so it must exist
	envFiles   []string
	allow      string
	allowSet   bool
	minAge     time.Duration
	noGitleaks bool
	jsonOut    bool
	peek       bool
	explain    []string
	verbose    bool
	jobs       int
	hook       bool
	quiet      bool // no progress or report on stderr
	version    bool
}

func main() {
	os.Exit(run())
}

func run() int {
	opts, paths, err := parseFlags()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "claude-scrub: %v\nRun 'claude-scrub --help' for usage.\n", err)
		return 2
	}
	if opts.version {
		fmt.Println("claude-scrub", buildVersion())
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := scrub(ctx, opts, paths); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "claude-scrub: interrupted; files already written stay redacted")
			return 130
		}
		fmt.Fprintf(os.Stderr, "claude-scrub: %v\n", err)
		return 1
	}
	return 0
}

func parseFlags() (options, []string, error) {
	var o options
	home, _ := os.UserHomeDir()
	defaultRoot := os.Getenv("CLAUDE_CONFIG_DIR")
	if defaultRoot == "" {
		defaultRoot = filepath.Join(home, ".claude")
	}
	cfg := filepath.Join(home, ".config", "claude-scrub")

	fs := flag.NewFlagSet("claude-scrub", flag.ContinueOnError)
	fs.SortFlags = false
	fs.BoolVarP(&o.dryRun, "dry-run", "n", false, "report what would be redacted, change nothing")
	fs.BoolVarP(&o.force, "force", "f", false, "redact without asking (required when not on a terminal)")
	fs.StringVar(&o.root, "root", defaultRoot, "Claude config dir to scan ($CLAUDE_CONFIG_DIR)")
	fs.DurationVar(&o.minAge, "min-age", 10*time.Minute, "skip history files modified more recently than this")
	fs.StringVar(&o.secrets, "secrets", filepath.Join(cfg, "secrets"), "file of label=value secrets to always redact")
	fs.StringArrayVar(&o.envFiles, "env-file", nil, "also redact the secrets in this .env/shell/YAML file (repeatable)")
	fs.StringVar(&o.allow, "allow", filepath.Join(cfg, "allow"), "file of values never to redact")
	fs.BoolVar(&o.noGitleaks, "no-gitleaks", false, "skip the gitleaks rules (faster, finds fewer token formats)")
	fs.BoolVar(&o.hook, "hook", false, "run as a SessionEnd hook: redact the session on stdin, and history.jsonl")
	fs.BoolVar(&o.jsonOut, "json", false, "print the report as JSON on stdout")
	fs.BoolVar(&o.peek, "peek", false, "show masked values (first and last 2 characters) in the report")
	fs.StringArrayVar(&o.explain, "explain", nil, "show where a label's values were found, redacted (repeatable)")
	fs.BoolVarP(&o.verbose, "verbose", "v", false, "list every file with redactions")
	fs.IntVarP(&o.jobs, "jobs", "j", runtime.NumCPU(), "files to process in parallel")
	fs.BoolVar(&o.version, "version", false, "print the version")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usageHead)
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, usageTail)
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		return o, nil, err
	}
	o.secretsSet = fs.Changed("secrets")
	o.allowSet = fs.Changed("allow")
	if o.hook && fs.NArg() > 0 {
		return o, nil, errors.New("--hook takes the session from stdin, not from paths")
	}
	if o.jobs < 1 {
		o.jobs = 1
	}
	return o, fs.Args(), nil
}
