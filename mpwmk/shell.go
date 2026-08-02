// Package mpwmk implements enough of the MPW Shell and MPW Make to run the
// Apple GS/OS build files unmodified: {variable} expansion, MPW ':' path
// syntax, the built-in commands the makefiles use, and the Make dialect with
// its MacRoman metacharacters (ƒ dependency, ∂ continuation).
package mpwmk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// MPW metacharacters, accepted both as UTF-8 runes (normalized sources) and
// as raw MacRoman bytes (pristine upstream files).
const (
	RuneDep      = 'ƒ' // 0xC4 dependency operator
	RuneContinue = '∂' // 0xB6 escape / line continuation
	RuneGE       = '≥' // 0xB3 stderr redirect
	RuneApprox   = '≈' // 0xC5 wildcard
)

// DecodeText reads MPW source text: UTF-8 if valid, else MacRoman, with CR
// line endings normalized to LF.
func DecodeText(b []byte) string {
	var s string
	if utf8.Valid(b) {
		s = string(b)
	} else {
		d, err := charmap.Macintosh.NewDecoder().Bytes(b)
		if err != nil {
			s = string(b)
		} else {
			s = string(d)
		}
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// Env holds shell variables and the working directory.
type Env struct {
	Vars    map[string]string
	Dir     string // host working directory
	Out     io.Writer
	Verbose bool
	DryRun  bool
	// Root maps the MPW volume/prefix of the project to a host directory so
	// that absolute-looking MPW paths resolve.
	Root string
}

func NewEnv(dir string) *Env {
	return &Env{Vars: map[string]string{}, Dir: dir, Out: os.Stdout}
}

func (e *Env) Get(name string) string {
	if v, ok := e.Vars[strings.ToLower(name)]; ok {
		return v
	}
	return ""
}

func (e *Env) Set(name, val string) { e.Vars[strings.ToLower(name)] = val }

func (e *Env) Unset(name string) { delete(e.Vars, strings.ToLower(name)) }

// Expand replaces {name} references (recursively, depth-limited).
func (e *Env) Expand(s string) string {
	for i := 0; i < 16; i++ {
		out, changed := e.expandOnce(s)
		if !changed {
			return out
		}
		s = out
	}
	return s
}

func (e *Env) expandOnce(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '{' {
			if j := strings.IndexByte(s[i:], '}'); j > 0 {
				name := s[i+1 : i+j]
				if !strings.ContainsAny(name, "{ \t") {
					b.WriteString(e.Get(name))
					i += j + 1
					changed = true
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed
}

// HostPath converts an MPW path to a host path, relative to the env's
// working directory.
//
//	:foo:bar   -> ./foo/bar        (leading colon = relative)
//	::foo      -> ../foo           (each extra leading colon = one level up)
//	foo:bar:   -> foo/bar          (interior colons are separators)
//	foo        -> foo              (no colon = plain name)
func (e *Env) HostPath(p string) string {
	p = strings.TrimSpace(e.Expand(p))
	if p == "" {
		return ""
	}
	// MPW quotes protect spaces in names; they are not part of the path.
	p = strings.ReplaceAll(p, "\"", "")
	if strings.HasPrefix(p, "/") { // already a host path
		// MPW directory values keep a trailing ':' and may use ':' separators
		p = strings.TrimSuffix(p, ":")
		return filepath.Clean(strings.ReplaceAll(p, ":", "/"))
	}
	if !strings.Contains(p, ":") {
		return filepath.Join(e.Dir, p)
	}
	// A single trailing ':' just marks the name as a directory.
	p = strings.TrimSuffix(p, ":")
	base := e.Dir
	for strings.HasPrefix(p, ":") {
		if strings.HasPrefix(p, "::") {
			base = filepath.Dir(base)
			p = p[1:]
			continue
		}
		p = p[1:]
		break
	}
	// interior "::" also means parent
	parts := strings.Split(p, ":")
	out := base
	for _, seg := range parts {
		switch seg {
		case "":
			// "::" inside a path: go up
			out = filepath.Dir(out)
		default:
			out = filepath.Join(out, hostName(out, seg))
		}
	}
	return filepath.Clean(out)
}

// hostName maps one MPW path component to the name it has on disk. '/' is an
// ordinary character in a Mac filename (":" is the separator there), so names
// like "SCSI Get Vol/Disk" cannot survive extraction intact; this source tree
// carries them with '_' in its place.
func hostName(dir, seg string) string {
	if !strings.Contains(seg, "/") {
		return seg
	}
	if alt := strings.ReplaceAll(seg, "/", "_"); fileExists(filepath.Join(dir, alt)) {
		return alt
	}
	return seg
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Tokenize splits a command line into words, honoring single and double
// quotes and the ∂ escape, and stripping trailing comments.
func Tokenize(line string) []string {
	var words []string
	var cur strings.Builder
	has := false
	inS, inD := false, false
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == RuneContinue && i+1 < len(rs):
			i++
			cur.WriteRune(rs[i])
			has = true
		case c == '\'' && !inD:
			inS = !inS
			has = true
		case c == '"' && !inS:
			inD = !inD
			has = true
		case c == '#' && !inS && !inD && !has:
			return words // comment starts a word: rest of line is comment
		case (c == ' ' || c == '\t') && !inS && !inD:
			if has {
				words = append(words, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
			has = true
		}
	}
	if has {
		words = append(words, cur.String())
	}
	return words
}

// RunBlock executes a sequence of command lines with MPW Shell control
// flow (if / else if / else / end), splitting ';'-separated statements.
func (e *Env) RunBlock(cmds []string) error {
	var stmts []string
	for _, c := range cmds {
		stmts = append(stmts, splitStatements(c)...)
	}
	type frame struct{ active, taken, parent bool }
	var stack []frame
	active := func() bool {
		for _, f := range stack {
			if !f.active {
				return false
			}
		}
		return true
	}
	for _, st := range stmts {
		w := Tokenize(e.Expand(st))
		if len(w) == 0 {
			continue
		}
		switch strings.ToLower(w[0]) {
		case "if":
			if !active() {
				stack = append(stack, frame{})
				continue
			}
			v := e.condition(w[1:])
			stack = append(stack, frame{active: v, taken: v, parent: true})
			continue
		case "else":
			if len(stack) == 0 {
				return fmt.Errorf("else without if")
			}
			f := &stack[len(stack)-1]
			if !f.parent {
				continue
			}
			// "else if cond"
			if len(w) > 1 && strings.EqualFold(w[1], "if") {
				if f.taken {
					f.active = false
				} else {
					v := e.condition(w[2:])
					f.active, f.taken = v, v
				}
				continue
			}
			f.active = !f.taken
			f.taken = true
			continue
		case "end":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if !active() {
			continue
		}
		if err := e.RunCommand(st); err != nil {
			return err
		}
	}
	return nil
}

// condition evaluates an MPW Shell test, including || and && between terms.
func (e *Env) condition(w []string) bool {
	for i, t := range w {
		if t == "||" {
			return e.condition(w[:i]) || e.condition(w[i+1:])
		}
	}
	for i, t := range w {
		if t == "&&" {
			return e.condition(w[:i]) && e.condition(w[i+1:])
		}
	}
	return e.conditionTerm(w)
}

// conditionTerm evaluates a single test: a lone word is true when non-empty
// and not "0"; comparisons use == != =~ !~.
func (e *Env) conditionTerm(w []string) bool {
	switch len(w) {
	case 0:
		return false
	case 1:
		v := strings.TrimSpace(w[0])
		return v != "" && v != "0"
	}
	if len(w) >= 3 {
		l, op, r := w[0], w[1], strings.Join(w[2:], " ")
		switch op {
		case "==", "=":
			return strings.EqualFold(l, r)
		case "!=", "<>":
			return !strings.EqualFold(l, r)
		case "=~":
			return strings.Contains(strings.ToLower(l), strings.ToLower(strings.Trim(r, "/≈")))
		case "!~":
			return !strings.Contains(strings.ToLower(l), strings.ToLower(strings.Trim(r, "/≈")))
		}
	}
	return strings.TrimSpace(w[0]) != ""
}

// splitStatements splits a line on ';' outside quotes.
func splitStatements(line string) []string {
	var out []string
	depth := 0
	inS, inD := false, false
	start := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			inS = !inS
		case '"':
			inD = !inD
		case '(':
			depth++
		case ')':
			depth--
		case ';':
			if !inS && !inD && depth == 0 {
				out = append(out, line[start:i])
				start = i + 1
			}
		}
	}
	return append(out, line[start:])
}

// RunCommand executes one expanded command line (builtins first, then the
// IIgs tools). Returns the command's status.
func (e *Env) RunCommand(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	// strip redirections we do not need to honor for object-producing builds
	line, outFile, appendOut := splitRedirect(line)
	line = e.substBackquotes(line)
	words := Tokenize(e.Expand(line))
	if len(words) == 0 {
		return nil
	}
	if e.Verbose {
		fmt.Fprintln(e.Out, "    "+strings.Join(words, " "))
	}
	if e.DryRun {
		return nil
	}
	name := strings.ToLower(words[0])
	args := words[1:]
	var stdout strings.Builder
	sink := io.Writer(e.Out)
	if outFile != "" {
		sink = &stdout
	}
	err := e.dispatch(name, args, sink)
	if outFile != "" && err == nil {
		p := e.HostPath(outFile)
		if appendOut {
			f, ferr := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if ferr != nil {
				return ferr
			}
			defer f.Close()
			_, err = f.WriteString(stdout.String())
		} else {
			err = os.WriteFile(p, []byte(stdout.String()), 0644)
		}
	}
	return err
}

// substBackquotes replaces `command` spans with the command's output, the
// MPW shell's command substitution. It works inside double quotes (that is
// how make.as.fst saves the working directory: Set YeOldeDirectory
// "`Directory`") but not inside single ones, and the substituted output has
// surrounding whitespace trimmed.
func (e *Env) substBackquotes(line string) string {
	if !strings.Contains(line, "`") {
		return line
	}
	var b strings.Builder
	inS := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' {
			inS = !inS
		}
		if c != '`' || inS {
			b.WriteByte(c)
			continue
		}
		j := strings.IndexByte(line[i+1:], '`')
		if j < 0 {
			b.WriteByte(c)
			continue
		}
		inner := line[i+1 : i+1+j]
		i += j + 1
		words := Tokenize(e.Expand(inner))
		if len(words) == 0 {
			continue
		}
		var out strings.Builder
		if err := e.dispatch(strings.ToLower(words[0]), words[1:], &out); err != nil {
			fmt.Fprintf(e.Out, "mpwmk: `%s`: %v\n", inner, err)
			continue
		}
		b.WriteString(strings.TrimSpace(out.String()))
	}
	return b.String()
}

// splitRedirect removes a trailing "> file" / ">> file" and any stderr
// redirect (≥, ≥≥) which the build uses only to silence diagnostics.
func splitRedirect(line string) (rest, outFile string, appendOut bool) {
	rest = line
	// stderr redirects: drop entirely
	for _, tok := range []string{"≥≥", "≥"} {
		for {
			i := strings.Index(rest, tok)
			if i < 0 {
				break
			}
			after := strings.TrimSpace(rest[i+len(tok):])
			f := after
			if j := strings.IndexAny(after, " \t"); j >= 0 {
				f = after[:j]
				after = after[j:]
			} else {
				after = ""
			}
			_ = f
			rest = strings.TrimSpace(rest[:i]) + " " + after
		}
	}
	if i := strings.Index(rest, ">>"); i >= 0 {
		outFile = strings.TrimSpace(rest[i+2:])
		return strings.TrimSpace(rest[:i]), firstWord(outFile), true
	}
	if i := strings.Index(rest, ">"); i >= 0 {
		outFile = strings.TrimSpace(rest[i+1:])
		return strings.TrimSpace(rest[:i]), firstWord(outFile), false
	}
	return rest, "", false
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}
