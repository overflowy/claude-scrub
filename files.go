package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Parts of the Claude config dir that hold history. Config (settings.json,
// plugins, skills, hooks) and live session state (sessions/) are left alone.
var historyDirs = []string{
	"projects", "paste-cache", "file-history", "shell-snapshots", "backups",
	"telemetry", "todos", "debug",
}

const tempPrefix = ".claude-scrub-"

type target struct {
	path string
	size int64
}

type discovery struct {
	targets []target
	recent  int // skipped: modified within --min-age
}

// discoverHistory lists the history files under root.
func discoverHistory(root string, minAge time.Duration, now time.Time) (discovery, error) {
	var d discovery
	entries, err := os.ReadDir(root)
	if err != nil {
		return d, err
	}
	var starts []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir() && (slices.Contains(historyDirs, name) || strings.HasPrefix(name, "backup-rename-")):
			starts = append(starts, filepath.Join(root, name))
		case e.Type().IsRegular() && strings.HasPrefix(name, "history.jsonl"):
			starts = append(starts, filepath.Join(root, name))
		}
	}
	for _, s := range starts {
		if err := walkFiles(s, false, func(t target, info fs.FileInfo) {
			if minAge > 0 && now.Sub(info.ModTime()) < minAge {
				d.recent++
				return
			}
			d.targets = append(d.targets, t)
		}); err != nil {
			return d, err
		}
	}
	return d, nil
}

// discoverPaths lists the given files, and every file under the given
// directories, whatever their age. A missing path is an error if required.
func discoverPaths(paths []string, required bool) (discovery, error) {
	var d discovery
	for _, p := range paths {
		if err := walkFiles(p, required, func(t target, _ fs.FileInfo) {
			d.targets = append(d.targets, t)
		}); err != nil {
			return d, err
		}
	}
	return d, nil
}

// walkFiles calls fn for each regular file under root. Files deleted along the
// way are skipped, and so is root unless it was required: only a path the user
// named has to exist.
func walkFiles(root string, rootRequired bool, fn func(target, fs.FileInfo)) error {
	return filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && (path != root || !rootRequired) {
			return nil
		}
		if err != nil {
			return err
		}
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), tempPrefix) {
			return nil
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		fn(target{path: path, size: info.Size()}, info)
		return nil
	})
}

// readTarget reads a file and tells how its content is laid out. It returns
// nil data for binary files.
func readTarget(path string) ([]byte, fileKind, fs.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, nil, err
	}
	head := data[:min(len(data), 8192)]
	if bytes.IndexByte(head, 0) >= 0 && !utf8.Valid(data) {
		return nil, 0, info, nil
	}
	// Named as JSON a file stays JSON, even if a crash left junk on its first line;
	// history.jsonl backups keep the extension in the middle. Anything else goes by
	// its first byte, as redaction keeps JSON valid line by line whatever the file
	// holds. checkKind then tells a single document from lines.
	kind := kindText
	name := filepath.Base(path)
	if looksLikeJSON(data) || strings.Contains(name, ".jsonl") || filepath.Ext(name) == ".json" {
		kind = kindJSONLines
	}
	return data, kind, info, nil
}

// keywordLinesIn returns the lines of a file worth running the rules on.
// JSON is decoded first, and each key/value pair is written as
// "key": "value" so the name rules see both; pairs are also checked here
// directly, through add. Lines that are not JSON are written as they are and in
// order, so a value running across them still matches the file. What can be
// decoded from them follows each run of such lines, and a blank line ends the
// run: a line of JSON between two of them holds them apart in the file. The
// exception is inside a private key block, whose value would include that line.
func keywordLinesIn(f *lineFinder, data []byte, kind fileKind, add func(candidate)) []keywordLine {
	if kind == kindText {
		return f.lines(string(data))
	}
	var sb, decoded strings.Builder
	inRun := false
	endRun := func() {
		if inRun {
			sb.WriteByte('\n')
			sb.WriteString(decoded.String())
			decoded.Reset()
			inRun = false
		}
	}
	var keys keyCarry
	blockEnd := 0 // where a key block opened in a run has to have ended
	eachUnit(data, checkKind(data, kind), func(u unit) {
		valid, out := u.isValid(), &sb
		if valid && u.base >= blockEnd {
			endRun()
		} else {
			sb.Write(u.data)
			sb.WriteByte('\n')
			inRun = true
			out = &decoded
			blockEnd = keyBlockEnd(u.data, u.base, blockEnd)
		}
		keys.scan(u.data, func(lit literal) {
			if lit.isKey {
				return
			}
			raw := u.data[lit.start:lit.end]
			// Images and other blobs: long and without whitespace
			if len(raw) > 32*1024 && !bytes.ContainsAny(raw, " \\") {
				return
			}
			value := decodeJSONString(raw)
			if lit.key != "" {
				scanPair(lit.key, value, add)
				out.WriteString(`"` + lit.key + `": "`)
			}
			writeDecoded(out, raw, value)
		})
		// A secret can sit outside the strings it could read
		if !valid && bytes.IndexByte(u.data, '\\') >= 0 {
			writeDecoded(out, u.data, decodeBody(u.data))
		}
	})
	endRun()
	return f.lines(sb.String())
}

// keyBlockEnd returns blockEnd after a line at offset base: past the longest block
// if the line opens one, or 0 if it closes one.
func keyBlockEnd(line []byte, base, blockEnd int) int {
	if !bytes.Contains(line, []byte("-----")) {
		return blockEnd
	}
	lower := bytes.ToLower(line)
	begin, end := bytes.LastIndex(lower, []byte("-----begin")), bytes.LastIndex(lower, []byte("-----end"))
	switch {
	case begin > end:
		return base + maxKeyBlock
	case end >= 0:
		return 0
	}
	return blockEnd
}

var errChanged = errors.New("file changed while it was being redacted")

// writeAtomic replaces path with data, keeping its mode and modification time.
// It gives up with errChanged if the file no longer matches orig, so lines a
// running session appended in the meantime are never lost.
func writeAtomic(path string, data []byte, orig fs.FileInfo) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), tempPrefix+"*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(orig.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	cur, err := os.Stat(path)
	if err != nil {
		return err
	}
	if cur.Size() != orig.Size() || !cur.ModTime().Equal(orig.ModTime()) {
		return errChanged
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	// Session pickers sort by modification time
	return os.Chtimes(path, time.Time{}, orig.ModTime())
}
