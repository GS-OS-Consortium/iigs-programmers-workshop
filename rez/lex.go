// Package rez reimplements the Apple MPW IIGS resource compiler (RezIIGS):
// it reads Rez source (type templates plus resource statements) and writes an
// Apple IIgs resource file. Behavior is developed by byte-diffing against the
// original RezIIGS running under emulation, the same way the assembler and
// linker were.
//
// The resource file layout is documented in Apple's own source, in
// GSToolbox/ResourceMgr/Resource.a: a 12-byte header plus a 128-byte memo,
// then the map (whose fields Resource.a lists as mapNext/mapFlag/mapOffset/
// mapSize/mapToIndex/mapFileNum/mapID/mapIndexSize/mapIndexUsed, a free list
// of 8-byte BLOCK records, and the index), then the resource data.
package rez

import (
	"fmt"
	"strings"
)

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tNumber
	tString    // "..." -- a character string
	tHexString // $"00FF..." -- raw bytes
	tPunct
)

type token struct {
	kind tokKind
	text string // identifier/punctuator spelling, or the decoded string body
	num  int64
	raw  []byte // decoded bytes for tString/tHexString
	file string
	line int
}

func (t token) String() string {
	switch t.kind {
	case tEOF:
		return "end of file"
	case tString:
		return fmt.Sprintf("string %q", t.text)
	case tHexString:
		return fmt.Sprintf("hex string (%d bytes)", len(t.raw))
	case tNumber:
		return fmt.Sprintf("number %d", t.num)
	}
	return fmt.Sprintf("%q", t.text)
}

func (t token) is(s string) bool {
	return (t.kind == tPunct || t.kind == tIdent) && strings.EqualFold(t.text, s)
}

// lexer turns one file's text into tokens. Comments (both /* */ and //) and
// line continuations are removed here; the preprocessor works on the token
// stream, so a macro body is just a token slice.
type lexer struct {
	src  string
	pos  int
	file string
	line int
}

func newLexer(src, file string) *lexer {
	return &lexer{src: src, file: file, line: 1}
}

func (l *lexer) errf(format string, a ...any) error {
	return fmt.Errorf("%s:%d: %s", l.file, l.line, fmt.Sprintf(format, a...))
}

// A '$' never starts an identifier: it introduces a hex number, a hex string
// or a "$$builtin", all of which next() picks off before this is consulted.
func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9' || c == '.'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// skipSpace consumes whitespace and comments, tracking line numbers.
func (l *lexer) skipSpace() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			l.pos++
		case c == '\\' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n':
			// backslash-newline continues a line; keep the line count honest
			l.pos += 2
			l.line++
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			l.pos += 2
			for l.pos < len(l.src) {
				if l.src[l.pos] == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
					l.pos += 2
					break
				}
				if l.src[l.pos] == '\n' {
					l.line++
				}
				l.pos++
			}
		default:
			return
		}
	}
}

// skipInline consumes whitespace and comments within one LOGICAL line: a
// backslash-newline continues the line, a bare newline ends it. It reports
// whether there is more content on the line. Directives use this to bound
// their operand -- TypesIIGS.r's "#define Region verUS, verFrance, ..." runs
// over a dozen backslash-continued lines and must be read as one.
func (l *lexer) skipInline() bool {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			l.pos++
		case c == '\\' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n':
			l.pos += 2
			l.line++
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			save, saveLine := l.pos, l.line
			l.pos += 2
			for l.pos < len(l.src) {
				if l.src[l.pos] == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
					l.pos += 2
					break
				}
				if l.src[l.pos] == '\n' {
					l.line++
				}
				l.pos++
			}
			if l.line != saveLine {
				// the comment itself spanned lines; the directive ends here
				l.pos, l.line = save, saveLine
				return false
			}
		default:
			return c != '\n'
		}
	}
	return false
}

// atLineStartHash reports whether the next token begins a preprocessor
// directive (a '#' that is the first non-blank on its line).
func (l *lexer) atLineStartHash() bool {
	if l.pos >= len(l.src) || l.src[l.pos] != '#' {
		return false
	}
	for i := l.pos - 1; i >= 0; i-- {
		switch l.src[i] {
		case ' ', '\t', '\r':
			continue
		case '\n':
			return true
		default:
			return false
		}
	}
	return true
}

// next returns the next token. Preprocessor directives are returned as a
// punct "#" followed by the directive name so the preprocessor can act on
// them; everything else is ordinary source.
func (l *lexer) next() (token, error) {
	l.skipSpace()
	t := token{file: l.file, line: l.line}
	if l.pos >= len(l.src) {
		t.kind = tEOF
		return t, nil
	}
	c := l.src[l.pos]

	switch {
	case isIdentStart(c):
		start := l.pos
		for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
			l.pos++
		}
		t.kind, t.text = tIdent, l.src[start:l.pos]
		return t, nil

	case c == '"':
		return l.lexString()

	case c == '$' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '"':
		return l.lexHexString()

	case c == '$' && l.pos+1 < len(l.src) && isHexDigit(l.src[l.pos+1]):
		l.pos++
		start := l.pos
		for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) {
			l.pos++
		}
		n, err := parseUint(l.src[start:l.pos], 16)
		if err != nil {
			return t, l.errf("bad hex number %q", l.src[start:l.pos])
		}
		t.kind, t.num, t.text = tNumber, n, "$"+l.src[start:l.pos]
		return t, nil

	case isDigit(c):
		return l.lexNumber()

	case c == '$' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '$':
		// "$$Word(...)" and friends -- a builtin function call
		l.pos += 2
		start := l.pos
		for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
			l.pos++
		}
		t.kind, t.text = tIdent, "$$"+l.src[start:l.pos]
		return t, nil
	}

	// punctuation, longest match first
	for _, p := range []string{"<<", ">>", "<=", ">=", "==", "!=", "&&", "||"} {
		if strings.HasPrefix(l.src[l.pos:], p) {
			l.pos += len(p)
			t.kind, t.text = tPunct, p
			return t, nil
		}
	}
	l.pos++
	t.kind, t.text = tPunct, string(c)
	return t, nil
}

func (l *lexer) lexNumber() (token, error) {
	t := token{file: l.file, line: l.line, kind: tNumber}
	start := l.pos
	base := 10
	if l.src[l.pos] == '0' && l.pos+1 < len(l.src) {
		switch l.src[l.pos+1] {
		case 'x', 'X':
			base, l.pos = 16, l.pos+2
			start = l.pos
		case 'b', 'B':
			// 0b0000000000001111 -- binary, used for menu/control flag words
			base, l.pos = 2, l.pos+2
			start = l.pos
		}
	}
	for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) {
		l.pos++
	}
	n, err := parseUint(l.src[start:l.pos], base)
	if err != nil {
		return t, l.errf("bad number %q", l.src[start:l.pos])
	}
	t.num, t.text = n, l.src[start:l.pos]
	return t, nil
}

func parseUint(s string, base int) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	var n int64
	for i := 0; i < len(s); i++ {
		var d int64
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad digit %q", string(c))
		}
		if d >= int64(base) {
			return 0, fmt.Errorf("digit %q out of range for base %d", string(c), base)
		}
		n = n*int64(base) + d
	}
	return n, nil
}

// lexString reads a "..." literal. The source is MacRoman-decoded before it
// reaches us, so the bytes are re-encoded on the way out (see macRomanBytes).
func (l *lexer) lexString() (token, error) {
	t := token{file: l.file, line: l.line, kind: tString}
	l.pos++ // opening quote
	var sb strings.Builder
	for {
		if l.pos >= len(l.src) {
			return t, l.errf("unterminated string")
		}
		c := l.src[l.pos]
		if c == '"' {
			l.pos++
			break
		}
		if c == '\n' {
			return t, l.errf("newline in string")
		}
		if c == '\\' {
			b, err := l.escape()
			if err != nil {
				return t, err
			}
			sb.WriteByte(b)
			continue
		}
		sb.WriteByte(c)
		l.pos++
	}
	t.text = sb.String()
	t.raw = []byte(t.text)
	return t, nil
}

// escape decodes a Rez backslash escape. Rez uses \0xNN (hex), \$NN, and the
// usual C letters; sys.resources.r uses \0x1b for the escape character in
// printer strings.
func (l *lexer) escape() (byte, error) {
	l.pos++ // backslash
	if l.pos >= len(l.src) {
		return 0, l.errf("unterminated escape")
	}
	c := l.src[l.pos]
	switch c {
	case 'n':
		// classic Mac line endings: \n is carriage return, \r is line feed
		l.pos++
		return '\r', nil
	case 'r':
		l.pos++
		return '\n', nil
	case 't':
		l.pos++
		return '\t', nil
	case 'b':
		l.pos++
		return '\b', nil
	case 'f':
		l.pos++
		return '\f', nil
	case 'v':
		l.pos++
		return '\v', nil
	case '?':
		l.pos++
		return 0x7F, nil
	case '\\', '"', '\'':
		l.pos++
		return c, nil
	case '0':
		// \0xNN hex escape, or an octal run
		if l.pos+1 < len(l.src) && (l.src[l.pos+1] == 'x' || l.src[l.pos+1] == 'X') {
			l.pos += 2
			start := l.pos
			for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) && l.pos-start < 2 {
				l.pos++
			}
			n, err := parseUint(l.src[start:l.pos], 16)
			if err != nil {
				return 0, l.errf("bad \\0x escape")
			}
			return byte(n), nil
		}
		fallthrough
	case '1', '2', '3', '4', '5', '6', '7':
		start := l.pos
		for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '7' && l.pos-start < 3 {
			l.pos++
		}
		n, err := parseUint(l.src[start:l.pos], 8)
		if err != nil {
			return 0, l.errf("bad octal escape")
		}
		return byte(n), nil
	case '$':
		l.pos++
		start := l.pos
		for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) && l.pos-start < 2 {
			l.pos++
		}
		n, err := parseUint(l.src[start:l.pos], 16)
		if err != nil {
			return 0, l.errf("bad \\$ escape")
		}
		return byte(n), nil
	}
	return 0, l.errf("unknown escape \\%c", c)
}

// lexHexString reads $"00FF 3FC0" -- whitespace inside is insignificant.
func (l *lexer) lexHexString() (token, error) {
	t := token{file: l.file, line: l.line, kind: tHexString}
	l.pos += 2 // $"
	var hi int = -1
	for {
		if l.pos >= len(l.src) {
			return t, l.errf("unterminated hex string")
		}
		c := l.src[l.pos]
		if c == '"' {
			l.pos++
			break
		}
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case isHexDigit(c):
			v, _ := parseUint(string(c), 16)
			if hi < 0 {
				hi = int(v)
			} else {
				t.raw = append(t.raw, byte(hi<<4|int(v)))
				hi = -1
			}
			l.pos++
		default:
			return t, l.errf("bad character %q in hex string", string(c))
		}
	}
	if hi >= 0 {
		return t, l.errf("hex string has an odd number of digits")
	}
	return t, nil
}
