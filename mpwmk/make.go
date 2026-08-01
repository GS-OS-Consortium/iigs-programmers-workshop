package mpwmk

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Rule is one makefile dependency rule.
type Rule struct {
	Targets []string
	Deps    []string
	Cmds    []string
	Line    int
}

// Makefile is a parsed MPW makefile.
type Makefile struct {
	Rules []*Rule
	Vars  map[string]string
	byTgt map[string]*Rule // lowercased expanded target -> rule
	// suffix rules: ".oii ƒ .aii" supplies the recipe for any target whose
	// name ends in .oii built from the matching .aii
	suffix []*Rule
}

// suffixPair reports the target and dependency suffixes of a rule like
// ".oii ƒ .aii", or ok=false if it is an ordinary rule.
func suffixPair(r *Rule) (tgt, dep string, ok bool) {
	if len(r.Targets) != 1 || len(r.Deps) != 1 {
		return "", "", false
	}
	t, d := r.Targets[0], r.Deps[0]
	if !strings.HasPrefix(t, ".") || !strings.HasPrefix(d, ".") {
		return "", "", false
	}
	if strings.ContainsAny(t[1:], ".:/ ") || strings.ContainsAny(d[1:], ".:/ ") {
		return "", "", false
	}
	return t, d, true
}

// ParseMakefile parses MPW Make syntax: "target ƒ deps" rule lines, tab-
// indented command lines, NAME = value assignments, ∂ continuations and #
// comments.
func ParseMakefile(text string) (*Makefile, error) {
	mf := &Makefile{Vars: map[string]string{}, byTgt: map[string]*Rule{}}
	// Comments are per physical line and must be removed BEFORE continuation
	// joining, or a trailing "# note ∂" swallows the rest of the command.
	raw := strings.Split(text, "\n")
	for i, l := range raw {
		if c := stripComment(l); c != l {
			raw[i] = strings.TrimRight(c, " \t")
			if strings.HasSuffix(strings.TrimRight(l, " \t"), string(RuneContinue)) {
				raw[i] += string(RuneContinue)
			}
		}
	}
	lines := joinContinuations(raw)
	var cur *Rule
	for _, ln := range lines {
		raw := ln.text
		if s := strings.TrimSpace(raw); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		indented := raw[0] == '\t' || raw[0] == ' '
		body := strings.TrimSpace(raw)
		if body == "" {
			continue
		}
		if depIdx := indexDep(body); depIdx >= 0 && !indented {
			tgt, deps := body[:depIdx], body[depIdx:]
			// skip the operator runes (ƒ or ƒƒ)
			deps = strings.TrimLeft(deps, string(RuneDep))
			cur = &Rule{
				Targets: splitFields(tgt),
				Deps:    splitFields(deps),
				Line:    ln.no,
			}
			mf.Rules = append(mf.Rules, cur)
			continue
		}
		if !indented {
			if i := strings.Index(body, "="); i > 0 {
				name := strings.TrimSpace(body[:i])
				if !strings.ContainsAny(name, " \t") {
					mf.Vars[strings.ToLower(name)] = strings.TrimSpace(body[i+1:])
					cur = nil
					continue
				}
			}
		}
		if cur != nil {
			cur.Cmds = append(cur.Cmds, body)
			continue
		}
		return nil, fmt.Errorf("line %d: unexpected text %q", ln.no, body)
	}
	return mf, nil
}

type numbered struct {
	text string
	no   int
}

// joinContinuations merges lines ending with the ∂ escape.
func joinContinuations(lines []string) []numbered {
	var out []numbered
	var acc string
	start := 0
	for i, l := range lines {
		trimmed := strings.TrimRight(l, " \t")
		if strings.HasSuffix(trimmed, string(RuneContinue)) {
			if acc == "" {
				start = i + 1
			}
			acc += strings.TrimSuffix(trimmed, string(RuneContinue)) + " "
			continue
		}
		if acc != "" {
			out = append(out, numbered{acc + strings.TrimSpace(l), start})
			acc = ""
			continue
		}
		out = append(out, numbered{l, i + 1})
	}
	if acc != "" {
		out = append(out, numbered{acc, start})
	}
	return out
}

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inS = !inS
		case '"':
			inD = !inD
		case '#':
			if !inS && !inD {
				return s[:i]
			}
		}
	}
	return s
}

// indexDep finds the byte offset of the ƒ dependency operator outside quotes.
func indexDep(s string) int {
	inS, inD := false, false
	for i, r := range s {
		switch r {
		case '\'':
			inS = !inS
		case '"':
			inD = !inD
		case RuneDep:
			if !inS && !inD {
				return i
			}
		}
	}
	return -1
}

// splitFields splits a rule's target/dependency list, honoring MPW quoting
// (file names in this corpus contain spaces, e.g. 'SCSI Driver main').
func splitFields(s string) []string {
	var out []string
	for _, f := range Tokenize(s) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Builder drives an MPW make: it resolves targets, decides what is out of
// date by modification time, and runs (or prints) the rule commands.
type Builder struct {
	Env  *Env
	MF   *Makefile
	Made map[string]bool
}

// NewBuilder prepares a build; makefile variables are seeded into the env
// (shell/exported variables already present win, matching MPW, where the
// makefile's own assignments are defaults for undefined names).
func NewBuilder(env *Env, mf *Makefile) *Builder {
	for k, v := range mf.Vars {
		if env.Get(k) == "" {
			env.Set(k, v)
		}
	}
	b := &Builder{Env: env, MF: mf, Made: map[string]bool{}}
	for _, r := range mf.Rules {
		if _, _, ok := suffixPair(r); ok {
			mf.suffix = append(mf.suffix, r)
			continue
		}
		for _, t := range r.Targets {
			b.MF.byTgt[strings.ToLower(env.HostPath(t))] = r
		}
	}
	return b
}

// DefaultTarget is the first target of the first rule.
func (b *Builder) DefaultTarget() string {
	if len(b.MF.Rules) == 0 || len(b.MF.Rules[0].Targets) == 0 {
		return ""
	}
	return b.MF.Rules[0].Targets[0]
}

// Build brings one target up to date, recursively.
func (b *Builder) Build(target string) error {
	host := b.Env.HostPath(target)
	key := strings.ToLower(host)
	if b.Made[key] {
		return nil
	}
	b.Made[key] = true

	rule := b.MF.byTgt[key]
	// An explicit rule may name the dependency but leave the recipe to a
	// suffix rule (".oii ƒ .aii"), so fall back whenever no commands apply.
	var sfx *Rule
	var sfxDep string
	if rule == nil || len(rule.Cmds) == 0 {
		sfx, sfxDep = b.matchSuffix(host)
	}
	if rule == nil && sfx == nil {
		if _, err := os.Stat(host); err != nil {
			return fmt.Errorf("no rule to make %q (%s)", target, host)
		}
		return nil // an existing source file
	}
	var newest time.Time
	if sfx != nil {
		if err := b.Build(sfxDep); err != nil {
			return err
		}
		if fi, err := os.Stat(b.Env.HostPath(sfxDep)); err == nil {
			newest = fi.ModTime()
		}
	}
	if rule == nil {
		rule = &Rule{}
	}
	for _, d := range rule.Deps {
		// A dependency that is nothing but a variable reference may hold a
		// whole list of files -- make.os builds the loader from "{Files}".
		// Only that form is re-split: MPW file names contain spaces, so
		// splitting an ordinary dependency would tear one name into pieces.
		deps := []string{d}
		if t := strings.TrimSpace(d); strings.HasPrefix(t, "{") &&
			strings.HasSuffix(t, "}") && !strings.Contains(t[:len(t)-1], "}") {
			deps = splitFields(b.Env.Expand(t))
		}
		for _, dep := range deps {
			if err := b.Build(dep); err != nil {
				return err
			}
			if fi, err := os.Stat(b.Env.HostPath(dep)); err == nil {
				if fi.ModTime().After(newest) {
					newest = fi.ModTime()
				}
			}
		}
	}
	if fi, err := os.Stat(host); err == nil && !fi.ModTime().Before(newest) {
		return nil // up to date
	}
	if b.Env.Verbose {
		fmt.Fprintf(b.Env.Out, "  %s\n", target)
	}
	cmds := rule.Cmds
	if len(cmds) == 0 && sfx != nil {
		// {Default} is the base name shared by target and dependency;
		// {TargDir} and {DepDir} are their directories.
		saved := map[string]string{}
		for _, k := range []string{"default", "targdir", "depdir"} {
			saved[k] = b.Env.Get(k)
		}
		b.Env.Set("Default", baseNoExt(host))
		b.Env.Set("TargDir", dirWithSlash(host))
		b.Env.Set("DepDir", dirWithSlash(b.Env.HostPath(sfxDep)))
		defer func() {
			for k, v := range saved {
				b.Env.Set(k, v)
			}
		}()
		cmds = sfx.Cmds
	}
	if err := b.Env.RunBlock(cmds); err != nil {
		return fmt.Errorf("%s: %w", target, err)
	}
	return nil
}

// matchSuffix finds a suffix rule producing host, returning it and the host
// path of the implied dependency.
func (b *Builder) matchSuffix(host string) (*Rule, string) {
	for _, r := range b.MF.suffix {
		tgtSfx, depSfx, _ := suffixPair(r)
		if !strings.EqualFold(filepath.Ext(host), tgtSfx) {
			continue
		}
		dep := strings.TrimSuffix(host, filepath.Ext(host)) + depSfx
		if _, err := os.Stat(dep); err != nil {
			// MPW file names are case-insensitive; the makefiles are not
			// consistent about it.
			if alt, ok := findCaseInsensitive(dep); ok {
				dep = alt
			} else {
				continue
			}
		}
		return r, dep
	}
	return nil, ""
}

func findCaseInsensitive(path string) (string, bool) {
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return "", false
	}
	want := strings.ToLower(filepath.Base(path))
	for _, e := range ents {
		if strings.ToLower(e.Name()) == want {
			return filepath.Join(filepath.Dir(path), e.Name()), true
		}
	}
	return "", false
}

func baseNoExt(p string) string {
	b := filepath.Base(p)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

func dirWithSlash(p string) string { return filepath.Dir(p) + "/" }

// Targets lists all rule targets in file order (for -list).
func (b *Builder) Targets() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range b.MF.Rules {
		for _, t := range r.Targets {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// LoadVariables executes an MPW variables script (a file of "set NAME value"
// / "export NAME" lines, optionally separated by ';').
func (e *Env) LoadVariables(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(DecodeText(data), "\n") {
		for _, stmt := range strings.Split(stripComment(line), ";") {
			w := Tokenize(stmt)
			if len(w) >= 3 && strings.EqualFold(w[0], "set") {
				e.Set(w[1], e.Expand(strings.Join(w[2:], " ")))
			}
		}
	}
	return nil
}

// SortedVars returns variable names in order (for diagnostics).
func (e *Env) SortedVars() []string {
	var ks []string
	for k := range e.Vars {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
