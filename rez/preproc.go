package rez

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// preproc expands #include/#define/#if into a flat token stream. Rez's
// preprocessor is C-like but small: TypesIIGS.r only branches on
// "#if !defined(_mybase_)", "#if DeRezIIGS==1" and "#if RezIIGS == 1", and
// defines are object-like (no function macros anywhere in this corpus).
type preproc struct {
	incDirs []string
	defs    map[string][]token
	out     []token
	depth   int
	seen    map[string]bool
}

// RezIIGS/DeRezIIGS are the switches TypesIIGS.r keys its DeRez-only
// formatting off; we are RezIIGS.
func newPreproc(incDirs []string) *preproc {
	p := &preproc{
		incDirs: incDirs,
		defs:    map[string][]token{},
		seen:    map[string]bool{},
	}
	// Rez's preprocessor is case-insensitive like the rest of the language
	// (the Installer writes "resource rPstring" against "#define rPString"),
	// so define names are keyed lowercased everywhere.
	p.defs["reziigs"] = []token{{kind: tNumber, num: 1, text: "1"}}
	p.defs["dereziigs"] = []token{{kind: tNumber, num: 0, text: "0"}}
	return p
}

// readSource loads a file and normalizes it to UTF-8 with \n line endings.
// The sources are classic-Mac text: CR-terminated and MacRoman-encoded (the
// GS/OS tree carries UTF-8/LF working copies, so accept both).
func readSource(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var text string
	if utf8.Valid(data) {
		text = string(data)
	} else if d, derr := charmap.Macintosh.NewDecoder().Bytes(data); derr == nil {
		text = string(d)
	} else {
		text = string(data)
	}
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"), nil
}

// findInclude resolves an #include spec. MPW file names are case-insensitive
// and the sources are inconsistent about it (typesiigs.r / TypesIIGS.r /
// TypesIIgs.r all appear), so match case-insensitively.
func (p *preproc) findInclude(spec, fromFile string) (string, error) {
	base := spec
	if i := strings.LastIndexAny(base, ":/"); i >= 0 {
		base = base[i+1:]
	}
	dirs := append([]string{filepath.Dir(fromFile)}, p.incDirs...)
	for _, d := range dirs {
		if d == "" {
			continue
		}
		cand := filepath.Join(d, base)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if strings.EqualFold(e.Name(), base) {
				return filepath.Join(d, e.Name()), nil
			}
		}
	}
	return "", fmt.Errorf("cannot find include %q", spec)
}

func (p *preproc) file(path string) error {
	if p.depth > 32 {
		return fmt.Errorf("#include nested too deeply at %s", path)
	}
	src, err := readSource(path)
	if err != nil {
		return err
	}
	return p.text(src, path)
}

func (p *preproc) text(src, path string) error {
	p.depth++
	defer func() { p.depth-- }()
	l := newLexer(src, path)

	// active tracks the #if stack; a false entry suppresses output.
	type frame struct{ active, taken, parentActive bool }
	var stack []frame
	active := func() bool {
		for _, f := range stack {
			if !f.active {
				return false
			}
		}
		return true
	}

	for {
		atHash := false
		l.skipSpace()
		if l.atLineStartHash() {
			atHash = true
		}
		t, err := l.next()
		if err != nil {
			return err
		}
		if t.kind == tEOF {
			break
		}
		if !atHash || !t.is("#") {
			if !active() {
				continue
			}
			if err := p.emit(t, l); err != nil {
				return err
			}
			continue
		}

		// a preprocessor directive: read its name and the rest of the line
		d, err := l.next()
		if err != nil {
			return err
		}
		name := strings.ToLower(d.text)
		line, err := p.restOfLine(l)
		if err != nil {
			return err
		}

		switch name {
		case "if":
			v, err := p.evalCond(line)
			if err != nil {
				return fmt.Errorf("%s:%d: #if: %w", path, d.line, err)
			}
			on := active() && v
			stack = append(stack, frame{active: on, taken: on, parentActive: active()})
		case "ifdef", "ifndef":
			ok := len(line) > 0 && p.defined(line[0].text)
			if name == "ifndef" {
				ok = !ok
			}
			on := active() && ok
			stack = append(stack, frame{active: on, taken: on, parentActive: active()})
		case "elif":
			if len(stack) == 0 {
				return fmt.Errorf("%s:%d: #elif without #if", path, d.line)
			}
			f := &stack[len(stack)-1]
			if f.taken || !f.parentActive {
				f.active = false
			} else {
				v, err := p.evalCond(line)
				if err != nil {
					return err
				}
				f.active, f.taken = v, v
			}
		case "else":
			if len(stack) == 0 {
				return fmt.Errorf("%s:%d: #else without #if", path, d.line)
			}
			f := &stack[len(stack)-1]
			f.active = f.parentActive && !f.taken
			f.taken = true
		case "endif":
			if len(stack) == 0 {
				return fmt.Errorf("%s:%d: #endif without #if", path, d.line)
			}
			stack = stack[:len(stack)-1]
		case "define":
			if !active() || len(line) == 0 {
				break
			}
			p.defs[strings.ToLower(line[0].text)] = append([]token(nil), line[1:]...)
		case "undef":
			if active() && len(line) > 0 {
				delete(p.defs, strings.ToLower(line[0].text))
			}
		case "include":
			if !active() {
				break
			}
			if len(line) == 0 {
				return fmt.Errorf("%s:%d: #include needs a file", path, d.line)
			}
			spec := line[0].text
			inc, err := p.findInclude(spec, path)
			if err != nil {
				return fmt.Errorf("%s:%d: %w", path, d.line, err)
			}
			if err := p.file(inc); err != nil {
				return err
			}
		case "printf", "pragma":
			// diagnostics only; no effect on the resource file
		default:
			return fmt.Errorf("%s:%d: unknown directive #%s", path, d.line, d.text)
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("%s: unterminated #if", path)
	}
	return nil
}

// emit appends a token, expanding object-like macros.
func (p *preproc) emit(t token, l *lexer) error {
	if t.kind == tIdent {
		key := strings.ToLower(t.text)
		if body, ok := p.defs[key]; ok && !p.seen[key] {
			p.seen[key] = true
			defer delete(p.seen, key)
			for _, b := range body {
				b.file, b.line = t.file, t.line
				if err := p.emit(b, l); err != nil {
					return err
				}
			}
			return nil
		}
	}
	p.out = append(p.out, t)
	return nil
}

// restOfLine collects the tokens of a directive's operand: everything up to
// the end of the logical line. A trailing comment ends it -- getting this
// wrong silently pulls the FOLLOWING lines into the macro body, which is how
// a "#define rWString $8022 /* comment */" once swallowed the type
// declaration after it.
func (p *preproc) restOfLine(l *lexer) ([]token, error) {
	var out []token
	for l.skipInline() {
		t, err := l.next()
		if err != nil {
			return nil, err
		}
		if t.kind == tEOF {
			break
		}
		out = append(out, t)
	}
	return out, nil
}

func (p *preproc) defined(name string) bool {
	_, ok := p.defs[strings.ToLower(name)]
	return ok
}

// evalCond evaluates a #if expression. Only what the corpus uses is
// supported: defined(), !, ==, !=, integer literals and macro names.
func (p *preproc) evalCond(line []token) (bool, error) {
	toks, err := p.expandCond(line, 0)
	if err != nil {
		return false, err
	}
	v, rest, err := condOr(toks)
	if err != nil {
		return false, err
	}
	if len(rest) != 0 {
		return false, fmt.Errorf("trailing %s", rest[0])
	}
	return v != 0, nil
}

// expandCond resolves defined(X) before macro expansion (so the name is not
// itself expanded), then expands the rest; an undefined name becomes 0, as C
// does.
func (p *preproc) expandCond(line []token, depth int) ([]token, error) {
	if depth > 32 {
		return nil, fmt.Errorf("macro recursion in #if")
	}
	var out []token
	for i := 0; i < len(line); i++ {
		t := line[i]
		if t.kind == tIdent && strings.EqualFold(t.text, "defined") {
			j := i + 1
			paren := false
			if j < len(line) && line[j].is("(") {
				paren, j = true, j+1
			}
			if j >= len(line) {
				return nil, fmt.Errorf("defined() needs a name")
			}
			v := int64(0)
			if p.defined(line[j].text) {
				v = 1
			}
			out = append(out, token{kind: tNumber, num: v})
			j++
			if paren {
				if j >= len(line) || !line[j].is(")") {
					return nil, fmt.Errorf("defined(: missing )")
				}
				j++
			}
			i = j - 1
			continue
		}
		if t.kind == tIdent {
			if body, ok := p.defs[strings.ToLower(t.text)]; ok {
				sub, err := p.expandCond(body, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, sub...)
				continue
			}
			// an undefined identifier is 0
			out = append(out, token{kind: tNumber, num: 0})
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func condOr(ts []token) (int64, []token, error) {
	l, rest, err := condAnd(ts)
	if err != nil {
		return 0, nil, err
	}
	for len(rest) > 0 && rest[0].is("||") {
		r, rr, err := condAnd(rest[1:])
		if err != nil {
			return 0, nil, err
		}
		if l != 0 || r != 0 {
			l = 1
		} else {
			l = 0
		}
		rest = rr
	}
	return l, rest, nil
}

func condAnd(ts []token) (int64, []token, error) {
	l, rest, err := condCmp(ts)
	if err != nil {
		return 0, nil, err
	}
	for len(rest) > 0 && rest[0].is("&&") {
		r, rr, err := condCmp(rest[1:])
		if err != nil {
			return 0, nil, err
		}
		if l != 0 && r != 0 {
			l = 1
		} else {
			l = 0
		}
		rest = rr
	}
	return l, rest, nil
}

func condCmp(ts []token) (int64, []token, error) {
	l, rest, err := condUnary(ts)
	if err != nil {
		return 0, nil, err
	}
	for len(rest) > 0 {
		op := rest[0]
		if !(op.is("==") || op.is("!=") || op.is("<") || op.is(">") ||
			op.is("<=") || op.is(">=")) {
			break
		}
		r, rr, err := condUnary(rest[1:])
		if err != nil {
			return 0, nil, err
		}
		var b bool
		switch op.text {
		case "==":
			b = l == r
		case "!=":
			b = l != r
		case "<":
			b = l < r
		case ">":
			b = l > r
		case "<=":
			b = l <= r
		case ">=":
			b = l >= r
		}
		l = 0
		if b {
			l = 1
		}
		rest = rr
	}
	return l, rest, nil
}

func condUnary(ts []token) (int64, []token, error) {
	if len(ts) == 0 {
		return 0, nil, fmt.Errorf("expression expected")
	}
	t := ts[0]
	switch {
	case t.is("!"):
		v, rest, err := condUnary(ts[1:])
		if err != nil {
			return 0, nil, err
		}
		if v == 0 {
			return 1, rest, nil
		}
		return 0, rest, nil
	case t.is("-"):
		v, rest, err := condUnary(ts[1:])
		return -v, rest, err
	case t.is("("):
		v, rest, err := condOr(ts[1:])
		if err != nil {
			return 0, nil, err
		}
		if len(rest) == 0 || !rest[0].is(")") {
			return 0, nil, fmt.Errorf("missing )")
		}
		return v, rest[1:], nil
	case t.kind == tNumber:
		return t.num, ts[1:], nil
	}
	return 0, nil, fmt.Errorf("unexpected %s in #if", t)
}
