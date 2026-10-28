package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Lines handed to a detector at a time
const batchBytes = 256 * 1024

type fileResult struct {
	path    string
	counts  map[int]int // secret index -> occurrences
	skipped int         // JSON lines left alone to keep them valid
	err     error
}

func scrub(ctx context.Context, o options, paths []string) error {
	start := time.Now()
	write := !o.dryRun

	if o.hook {
		var err error
		if paths, err = hookPaths(os.Stdin, o.root); err != nil {
			return err
		}
		// Ending a session is the consent; stay quiet unless something
		// was redacted or went wrong
		o.force, o.quiet = true, true
	}
	logf := func(format string, args ...any) {
		if !o.quiet {
			fmt.Fprintf(os.Stderr, format, args...)
		}
	}
	if write && !o.force && !interactive() {
		return errors.New("refusing to modify files without a terminal to confirm; pass --force, or --dry-run to only report")
	}

	allow, err := loadAllowlist(o.allow, o.allowSet)
	if err != nil {
		return err
	}
	col := newCollector()
	if err := loadSecretsFile(o.secrets, o.secretsSet, col); err != nil {
		return err
	}
	for _, f := range o.envFiles {
		if err := loadEnvFile(f, col); err != nil {
			return err
		}
	}

	var disc discovery
	if len(paths) > 0 {
		disc, err = discoverPaths(paths)
	} else {
		disc, err = discoverHistory(o.root, o.minAge, time.Now())
	}
	if err != nil {
		return err
	}
	// Biggest first, so one large transcript does not finish last on its own
	sort.Slice(disc.targets, func(i, j int) bool { return disc.targets[i].size > disc.targets[j].size })
	var total int64
	for _, t := range disc.targets {
		total += t.size
	}
	logf("Scanning %d files (%s)", len(disc.targets), humanBytes(total))
	if disc.recent > 0 {
		logf(", skipping %d modified in the last %s", disc.recent, o.minAge)
	}
	logf("\n")

	// Pass 1: find the secrets. Readers pick the lines worth scanning and
	// hand them over in batches, so a few large transcripts are spread over
	// every detector instead of each keeping one busy to the end.
	detectors := make([]*detector, o.jobs)
	for i := range detectors {
		// Built one at a time: gitleaks loads its config through a global
		if detectors[i], err = newDetector(!o.noGitleaks); err != nil {
			return fmt.Errorf("load gitleaks rules: %w", err)
		}
	}
	finder := newLineFinder(detectors[0].gl)
	batches := make(chan []keywordLine, 2*o.jobs)
	var scanners sync.WaitGroup
	for _, d := range detectors {
		scanners.Go(func() {
			for b := range batches {
				d.scanLines(b, col.add)
			}
		})
	}
	var unreadable []string
	var mu sync.Mutex
	forEach(ctx, disc.targets, o.jobs, func(_ int, t target) {
		data, kind, _, err := readTarget(t.path)
		if err != nil {
			mu.Lock()
			unreadable = append(unreadable, fmt.Sprintf("  %s: %v", displayPath(t.path), err))
			mu.Unlock()
			return
		}
		if data == nil {
			return
		}
		lines := keywordLinesIn(finder, data, kind, col.add)
		for len(lines) > 0 {
			n, size := 0, 0
			for n < len(lines) && size < batchBytes {
				size += lines[n].size()
				n++
			}
			batches <- lines[:n]
			lines = lines[n:]
		}
	})
	close(batches)
	scanners.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	secrets := col.secrets(allow)
	rep := newReplacer(secrets)
	logf("Found %d secrets in %s\n", len(secrets), time.Since(start).Round(100*time.Millisecond))

	// Pass 2: count, then redact once confirmed
	results := redactAll(ctx, rep, disc.targets, o.jobs, false)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	sum := summarize(secrets, results)

	if o.jsonOut {
		if err := printJSON(os.Stdout, sum, o, len(disc.targets)); err != nil {
			return err
		}
	} else if !o.quiet {
		printReport(os.Stderr, sum, o)
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		fmt.Fprintf(os.Stderr, "Could not read %d files:\n%s\n", len(unreadable), strings.Join(unreadable, "\n"))
	}
	for _, label := range o.explain {
		explain(os.Stderr, rep, sum, labelFor(label))
	}

	if sum.occurrences == 0 {
		logf("Nothing to redact.\n")
		return nil
	}
	if !write {
		logf("\nWould redact %d occurrences in %d files. Run without --dry-run to apply.\n", sum.occurrences, len(sum.files))
		return nil
	}
	if !o.force && !confirm(fmt.Sprintf("Redact %d occurrences in %d files? This cannot be undone. [y/N] ", sum.occurrences, len(sum.files))) {
		logf("Nothing changed.\n")
		return nil
	}

	var todo []target
	for _, f := range sum.files {
		todo = append(todo, target{path: f.path})
	}
	written := redactAll(ctx, rep, todo, o.jobs, true)
	var done, occurrences int
	var failed []string
	for _, r := range written {
		if r.err != nil {
			failed = append(failed, fmt.Sprintf("  %s: %v", r.path, r.err))
			continue
		}
		if n := sumCounts(r.counts); n > 0 {
			done++
			occurrences += n
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if o.hook && (done > 0 || len(failed) > 0) {
		fmt.Fprintf(os.Stderr, "claude-scrub: redacted %d occurrences in %d files\n", occurrences, done)
	}
	logf("Redacted %d occurrences in %d files.\n", occurrences, done)
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("could not redact %d files:\n%s", len(failed), strings.Join(failed, "\n"))
	}
	return nil
}

// hookPaths reads the SessionEnd hook input and returns the session's
// transcript, its subagent and tool result directory, and history.jsonl.
func hookPaths(r io.Reader, root string) ([]string, error) {
	var in struct {
		TranscriptPath string `json:"transcript_path"`
	}
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("read hook input: %w", err)
	}
	if in.TranscriptPath == "" {
		return nil, errors.New("hook input has no transcript_path")
	}
	paths := []string{in.TranscriptPath}
	for _, p := range []string{strings.TrimSuffix(in.TranscriptPath, ".jsonl"), filepath.Join(root, "history.jsonl")} {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

func redactAll(ctx context.Context, rep *replacer, targets []target, jobs int, write bool) []fileResult {
	results := make([]fileResult, len(targets))
	idx := map[string]int{}
	for i, t := range targets {
		idx[t.path] = i
	}
	forEach(ctx, targets, jobs, func(_ int, t target) {
		results[idx[t.path]] = redactFile(rep, t.path, write)
	})
	return results
}

// redactFile redacts one file, retrying when a running session appends to it
// while it is being rewritten.
func redactFile(rep *replacer, path string, write bool) fileResult {
	res := fileResult{path: path}
	for range 3 {
		data, kind, info, err := readTarget(path)
		if err != nil || data == nil {
			res.err = err
			return res
		}
		red := rep.redact(data, kind)
		res.counts, res.skipped = red.counts, red.skipped
		if !write || len(red.counts) == 0 {
			return res
		}
		if res.err = writeAtomic(path, red.out, info); !errors.Is(res.err, errChanged) {
			return res
		}
	}
	return res
}

func forEach(ctx context.Context, targets []target, jobs int, fn func(worker int, t target)) {
	ch := make(chan target)
	var wg sync.WaitGroup
	for w := range jobs {
		wg.Go(func() {
			for t := range ch {
				fn(w, t)
			}
		})
	}
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		ch <- t
	}
	close(ch)
	wg.Wait()
}

type labelSummary struct {
	label       string
	values      []string
	occurrences int
	files       map[string]bool
}

type fileSummary struct {
	path        string
	occurrences int
	labels      map[string]int
	skipped     int
}

type summary struct {
	labels      []*labelSummary
	files       []fileSummary
	occurrences int
	skipped     int // JSON lines left alone
}

func summarize(secrets []secret, results []fileResult) summary {
	var s summary
	byLabel := map[string]*labelSummary{}
	for _, sec := range secrets {
		l := byLabel[sec.label]
		if l == nil {
			l = &labelSummary{label: sec.label, files: map[string]bool{}}
			byLabel[sec.label] = l
		}
		l.values = append(l.values, sec.value)
	}
	for _, r := range results {
		s.skipped += r.skipped
		if len(r.counts) == 0 {
			continue
		}
		f := fileSummary{path: r.path, labels: map[string]int{}, skipped: r.skipped}
		for i, n := range r.counts {
			label := secrets[i].label
			f.labels[label] += n
			f.occurrences += n
			byLabel[label].occurrences += n
			byLabel[label].files[r.path] = true
		}
		s.occurrences += f.occurrences
		s.files = append(s.files, f)
	}
	for _, l := range byLabel {
		s.labels = append(s.labels, l)
	}
	sort.Slice(s.labels, func(i, j int) bool {
		if s.labels[i].occurrences != s.labels[j].occurrences {
			return s.labels[i].occurrences > s.labels[j].occurrences
		}
		return s.labels[i].label < s.labels[j].label
	})
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].path < s.files[j].path })
	return s
}

func printReport(w io.Writer, s summary, o options) {
	if len(s.labels) == 0 {
		return
	}
	width := len("LABEL")
	for _, l := range s.labels {
		width = max(width, len(l.label))
	}
	fmt.Fprintf(w, "\n%-*s  %6s  %11s  %5s\n", width, "LABEL", "VALUES", "OCCURRENCES", "FILES")
	for _, l := range s.labels {
		fmt.Fprintf(w, "%-*s  %6d  %11d  %5d\n", width, l.label, len(l.values), l.occurrences, len(l.files))
		if o.peek {
			for _, v := range l.values {
				fmt.Fprintf(w, "    %s\n", mask(v))
			}
		}
	}
	if o.verbose && len(s.files) > 0 {
		fmt.Fprintln(w)
		for _, f := range s.files {
			fmt.Fprintf(w, "%5d  %s  (%s)\n", f.occurrences, displayPath(f.path), labelList(f.labels))
		}
	}
	if s.skipped > 0 {
		fmt.Fprintf(w, "\nLeft %d JSON lines alone: redacting them would have broken the JSON.\n", s.skipped)
	}
}

func printJSON(w io.Writer, s summary, o options, scanned int) error {
	type jsonLabel struct {
		Label       string   `json:"label"`
		Values      int      `json:"values"`
		Masked      []string `json:"masked,omitempty"`
		Occurrences int      `json:"occurrences"`
		Files       int      `json:"files"`
	}
	type jsonFile struct {
		Path        string         `json:"path"`
		Occurrences int            `json:"occurrences"`
		Labels      map[string]int `json:"labels"`
		Skipped     int            `json:"skipped_lines,omitempty"`
	}
	out := struct {
		DryRun       bool        `json:"dry_run"`
		FilesScanned int         `json:"files_scanned"`
		Occurrences  int         `json:"occurrences"`
		SkippedLines int         `json:"skipped_lines"`
		Labels       []jsonLabel `json:"labels"`
		Files        []jsonFile  `json:"files"`
	}{DryRun: o.dryRun, FilesScanned: scanned, Occurrences: s.occurrences, SkippedLines: s.skipped}
	for _, l := range s.labels {
		jl := jsonLabel{Label: l.label, Values: len(l.values), Occurrences: l.occurrences, Files: len(l.files)}
		if o.peek {
			for _, v := range l.values {
				jl.Masked = append(jl.Masked, mask(v))
			}
		}
		out.Labels = append(out.Labels, jl)
	}
	for _, f := range s.files {
		out.Files = append(out.Files, jsonFile{Path: f.path, Occurrences: f.occurrences, Labels: f.labels, Skipped: f.skipped})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// explain prints, for each value of label, the text around its first
// occurrence with every secret in it redacted.
func explain(w io.Writer, rep *replacer, s summary, label string) {
	const around = 80
	fmt.Fprintf(w, "\n%s:\n", label)
	found := false
	for _, l := range s.labels {
		if l.label != label {
			continue
		}
		found = true
		for i, v := range l.values {
			snippet := "(no occurrence)"
			for _, f := range s.files {
				if f.labels[label] == 0 {
					continue
				}
				data, kind, _, err := readTarget(f.path)
				if err != nil || data == nil {
					continue
				}
				text := string(data)
				if kind != kindText {
					text = decodeLiterals(data)
				}
				at := strings.Index(text, v)
				if at < 0 {
					continue
				}
				lo, hi := max(0, at-around), min(len(text), at+len(v)+around)
				red := rep.redact([]byte(strings.ToValidUTF8(text[lo:hi], "")), kindText)
				snippet = fmt.Sprintf("%s\n      %s", displayPath(f.path), strings.Join(strings.Fields(string(red.out)), " "))
				break
			}
			fmt.Fprintf(w, "  %d. %s\n", i+1, snippet)
		}
	}
	if !found {
		fmt.Fprintln(w, "  no such label")
	}
}

// decodeLiterals joins the decoded string literals of a JSON file.
func decodeLiterals(data []byte) string {
	var sb strings.Builder
	scanJSON(data, func(lit literal) {
		if lit.key != "" {
			sb.WriteString(lit.key + ": ")
		}
		sb.WriteString(decodeJSONString(data[lit.start:lit.end]))
		sb.WriteByte('\n')
	})
	return sb.String()
}

// mask shows a value's first and last two characters and its length.
func mask(v string) string {
	r := []rune(v)
	if len(r) < 12 {
		return fmt.Sprintf("%s… (%d chars)", string(r[:1]), len(r))
	}
	return fmt.Sprintf("%s…%s (%d chars)", string(r[:2]), string(r[len(r)-2:]), len(r))
}

func labelList(labels map[string]int) string {
	var parts []string
	for l, n := range labels {
		parts = append(parts, fmt.Sprintf("%s×%d", l, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func displayPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rel, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
			return "~/" + rel
		}
	}
	return p
}

func sumCounts(m map[int]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
