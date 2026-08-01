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
	if strings.HasPrefix(p, "/") { // already a host path
		return filepath.Clean(p)
	}
	if !strings.Contains(p, ":") {
		return filepath.Join(e.Dir, p)
	}
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
			out = filepath.Join(out, seg)
		}
	}
	return filepath.Clean(out)
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

// RunCommand executes one expanded command line (builtins first, then the
// IIgs tools). Returns the command's status.
func (e *Env) RunCommand(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	// strip redirections we do not need to honor for object-producing builds
	line, outFile, appendOut := splitRedirect(line)
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
