package rez

import (
	"fmt"
	"strings"
)

type fieldKind int

const (
	fBits fieldKind = iota // byte/integer/longint/bitstring -- a sized integer
	fBoolean
	fChar
	fPString
	fCString
	fWString
	fString // raw characters, no length prefix
	fHexString
	fRect
	fPoint
	fFill
	fAlign
	fArray
	fSwitch
	fGroup // "ReverseBytes { ... }" and other named groupings
	fLabel // "end:" alone -- marks an offset for $$Word(), emits nothing
)

// field is one member of a type template.
type field struct {
	kind  fieldKind
	label string // "height:" -- referenced by $$Word(height)
	hex   bool   // DeRez formatting hint; no effect on the bytes
	bits  int    // width in bits for fBits (8/16/32) and fBitstring
	size  []token
	def   []token          // "= expr": a default, or a literal when no data is supplied
	named map[string]int64 // "longint behind=0,infront=-1"

	// array / switch
	sub       []field
	arrayName string
	reverse   bool // ReverseBytes group
	optional  bool
	cases     []switchCase
}

type switchCase struct {
	name   string
	fields []field
}

// typeDecl is a parsed "type rFoo { ... }".
type typeDecl struct {
	name   string
	id     int64 // the numeric resource type, from the #define of the same name
	hasID  bool
	fields []field
}

// parser walks the preprocessed token stream.
type parser struct {
	toks []token
	pos  int
	c    *Compiler
}

func (p *parser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{kind: tEOF}
}

func (p *parser) next() token {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *parser) errf(t token, format string, a ...any) error {
	return fmt.Errorf("%s:%d: %s", t.file, t.line, fmt.Sprintf(format, a...))
}

func (p *parser) expect(s string) (token, error) {
	t := p.next()
	if !t.is(s) {
		return t, p.errf(t, "expected %q, found %s", s, t)
	}
	return t, nil
}

// accept consumes the next token if it matches.
func (p *parser) accept(s string) bool {
	if p.peek().is(s) {
		p.pos++
		return true
	}
	return false
}

// parseTypeDecl parses the body of "type NAME [ (id) ] { fields }".
func (p *parser) parseTypeDecl() (*typeDecl, error) {
	nameTok := p.next()
	if nameTok.kind != tIdent && nameTok.kind != tNumber {
		return nil, p.errf(nameTok, "type needs a name, found %s", nameTok)
	}
	td := &typeDecl{name: nameTok.text}
	// The name is normally a macro that already expanded to the numeric type
	// (TypesIIGS.r does "#define rIcon $8001" then "type rIcon {...}"), so a
	// numeric token here IS the type id.
	if nameTok.kind == tNumber {
		td.id, td.hasID = nameTok.num, true
		td.name = fmt.Sprintf("$%04X", nameTok.num)
	}
	if p.accept("(") { // "type rFoo (id)" -- an explicit id
		t := p.next()
		if t.kind != tNumber {
			return nil, p.errf(t, "type id must be numeric")
		}
		td.id, td.hasID = t.num, true
		if _, err := p.expect(")"); err != nil {
			return nil, err
		}
	}
	if _, err := p.expect("{"); err != nil {
		return nil, err
	}
	fs, err := p.parseFields("}")
	if err != nil {
		return nil, err
	}
	td.fields = fs
	if _, err := p.expect("}"); err != nil {
		return nil, err
	}
	p.accept(";")
	return td, nil
}

// parseFields reads template fields until the closing token (not consumed).
func (p *parser) parseFields(end string) ([]field, error) {
	var out []field
	for {
		t := p.peek()
		if t.kind == tEOF || t.is(end) {
			return out, nil
		}
		if p.accept(";") {
			continue
		}
		f, err := p.parseField()
		if err != nil {
			return nil, err
		}
		if f != nil {
			out = append(out, *f)
		}
	}
}

// parseField reads one field declaration.
func (p *parser) parseField() (*field, error) {
	f := &field{}

	// an optional "label:" prefix
	if p.peek().kind == tIdent && p.pos+1 < len(p.toks) && p.toks[p.pos+1].is(":") {
		f.label = p.next().text
		p.next() // ':'
		// A label on a line by itself just names an offset; rFileType's
		// "end:" is measured against "start:" by $$Word(). It may also stand
		// last in a switch case, directly before the next "case" (rPicture's
		// ClipEnd).
		if p.peek().is(";") || p.peek().is("}") || p.peek().is("case") ||
			(p.peek().kind == tIdent && p.pos+1 < len(p.toks) && p.toks[p.pos+1].is(":")) {
			p.accept(";")
			f.kind = fLabel
			return f, nil
		}
	}

	for {
		t := p.peek()
		if t.kind != tIdent {
			break
		}
		switch strings.ToLower(t.text) {
		case "hex":
			p.next()
			f.hex = true
			continue
		case "unsigned", "decimal", "literal", "binary", "octal", "key":
			// formatting hints and the switch "key" marker; no byte effect
			// (the key's VALUE is emitted via its "= expr" default)
			p.next()
			continue
		case "optional":
			p.next()
			f.optional = true
			continue
		case "wide":
			// "wide array" is a DeRez formatting hint (elements on one
			// line); it does not change the bytes
			p.next()
			continue
		}
		break
	}

	t := p.next()
	if t.kind != tIdent {
		return nil, p.errf(t, "field type expected, found %s", t)
	}

	switch strings.ToLower(t.text) {
	case "byte":
		f.kind, f.bits = fBits, 8
	case "integer", "word":
		f.kind, f.bits = fBits, 16
	case "longint", "long":
		f.kind, f.bits = fBits, 32
	case "boolean":
		f.kind, f.bits = fBoolean, 1
	case "bitstring":
		f.kind = fBits
		n, err := p.bracketCount()
		if err != nil {
			return nil, err
		}
		f.bits = int(n)
	case "bit":
		f.kind, f.bits = fBits, 1
	case "char":
		f.kind, f.bits = fChar, 8
	case "pstring":
		f.kind = fPString
		f.size, _ = p.optBracketExpr()
	case "cstring":
		f.kind = fCString
		f.size, _ = p.optBracketExpr()
	case "wstring":
		f.kind = fWString
		f.size, _ = p.optBracketExpr()
	case "string":
		f.kind = fString
		f.size, _ = p.optBracketExpr()
	case "rect":
		f.kind = fRect
	case "point":
		f.kind = fPoint
	case "fill":
		f.kind = fFill
		w, n, err := p.fillOrAlign()
		if err != nil {
			return nil, err
		}
		f.bits, f.size = w, n
	case "align":
		f.kind = fAlign
		w, _, err := p.fillOrAlign()
		if err != nil {
			return nil, err
		}
		f.bits = w
	case "array":
		f.kind = fArray
		if p.peek().kind == tIdent && !p.peek().is("{") {
			f.arrayName = p.next().text
		}
		// "array[1]{...}" repeats a fixed number of times instead of running
		// until the data does (KeyEquiv in rControlTemplate).
		f.size, _ = p.optBracketExpr()
		if _, err := p.expect("{"); err != nil {
			return nil, err
		}
		sub, err := p.parseFields("}")
		if err != nil {
			return nil, err
		}
		f.sub = sub
		if _, err := p.expect("}"); err != nil {
			return nil, err
		}
	case "switch":
		f.kind = fSwitch
		if _, err := p.expect("{"); err != nil {
			return nil, err
		}
		for {
			if p.accept("}") {
				break
			}
			if p.accept(";") {
				continue
			}
			ct := p.next()
			if !ct.is("case") {
				return nil, p.errf(ct, "expected case in switch, found %s", ct)
			}
			nameTok := p.next()
			if _, err := p.expect(":"); err != nil {
				return nil, err
			}
			sub, err := p.parseCaseFields()
			if err != nil {
				return nil, err
			}
			f.cases = append(f.cases, switchCase{name: nameTok.text, fields: sub})
		}
	case "reversebytes":
		// "ReverseBytes { ... }" emits its body with the byte order flipped;
		// rVersion's BCD block is the only use. RezIIGS takes no other bare
		// identifier as a field type, so neither do we.
		f.reverse = true
		if p.peek().is("{") {
			p.next()
			sub, err := p.parseFields("}")
			if err != nil {
				return nil, err
			}
			if _, err := p.expect("}"); err != nil {
				return nil, err
			}
			f.kind, f.sub, f.arrayName = fGroup, sub, t.text
			break
		}
		return nil, p.errf(t, "ReverseBytes needs a body")
	default:
		// "optional Fields { ... }" names a group so $$optionalcount can
		// refer to it. A bare identifier is a field type only in that form;
		// RezIIGS rejects it anywhere else and so do we.
		if f.optional && p.peek().is("{") {
			p.next()
			sub, err := p.parseFields("}")
			if err != nil {
				return nil, err
			}
			if _, err := p.expect("}"); err != nil {
				return nil, err
			}
			f.kind, f.sub, f.arrayName = fGroup, sub, t.text
			break
		}
		if f.hex {
			return nil, p.errf(t, "unsupported field type %q after hex", t.text)
		}
		return nil, p.errf(t, "unsupported field type %q", t.text)
	}

	// "hex string[n]" is raw bytes rather than characters
	if f.kind == fString && f.hex {
		f.kind = fHexString
	}

	// A symbolic-value list may follow the type: "longint behind=0,infront=-1"
	// and, via a #define, rVersion's "integer Region" which expands to
	// "integer verUS, verFrance, ... verFrBelgiumLux = 6, verSweden, ...".
	// Names without an "=" continue from the previous value, starting at 0.
	if p.peek().kind == tIdent && p.pos+1 < len(p.toks) &&
		(p.toks[p.pos+1].is("=") || p.toks[p.pos+1].is(",") || p.toks[p.pos+1].is(";")) {
		next := int64(0)
		for p.peek().kind == tIdent {
			nm := p.next().text
			v := next
			if p.accept("=") {
				expr, err := p.exprTokens()
				if err != nil {
					return nil, err
				}
				if v, err = p.c.evalConst(expr); err != nil {
					return nil, err
				}
			}
			if f.named == nil {
				f.named = map[string]int64{}
			}
			f.named[strings.ToLower(nm)] = v
			next = v + 1
			if !p.accept(",") {
				break
			}
		}
	}

	// a default/literal value: "= expr"
	if p.accept("=") {
		expr, err := p.exprTokens()
		if err != nil {
			return nil, err
		}
		f.def = expr
	}
	p.accept(";")
	return f, nil
}

// parseCaseFields reads a switch case body: fields up to the next "case" or
// the switch's closing brace.
func (p *parser) parseCaseFields() ([]field, error) {
	var out []field
	for {
		t := p.peek()
		if t.kind == tEOF || t.is("}") || t.is("case") {
			return out, nil
		}
		if p.accept(";") {
			continue
		}
		f, err := p.parseField()
		if err != nil {
			return nil, err
		}
		if f != nil {
			out = append(out, *f)
		}
	}
}

// optBracketExpr reads an optional "[expr]" size.
func (p *parser) optBracketExpr() ([]token, bool) {
	if !p.peek().is("[") {
		return nil, false
	}
	p.next()
	var depth int
	var out []token
	for {
		t := p.peek()
		if t.kind == tEOF {
			return out, true
		}
		if t.is("[") {
			depth++
		}
		if t.is("]") {
			if depth == 0 {
				p.next()
				return out, true
			}
			depth--
		}
		out = append(out, p.next())
	}
}

func (p *parser) bracketCount() (int64, error) {
	expr, ok := p.optBracketExpr()
	if !ok {
		return 0, fmt.Errorf("expected [n]")
	}
	return p.c.evalConst(expr)
}

// fillOrAlign parses the "long[3]" / "word" operand of fill and align,
// returning the unit width in bits and the optional count expression.
func (p *parser) fillOrAlign() (int, []token, error) {
	w := 8
	if p.peek().kind == tIdent {
		switch strings.ToLower(p.peek().text) {
		case "bit":
			w = 1
			p.next()
		case "nibble":
			w = 4
			p.next()
		case "byte":
			w = 8
			p.next()
		case "word":
			w = 16
			p.next()
		case "long":
			w = 32
			p.next()
		}
	}
	n, _ := p.optBracketExpr()
	return w, n, nil
}

// exprTokens collects the tokens of an expression, stopping at a delimiter
// that cannot be part of one.
func (p *parser) exprTokens() ([]token, error) {
	var out []token
	depth := 0
	for {
		t := p.peek()
		if t.kind == tEOF {
			return out, nil
		}
		if depth == 0 && (t.is(";") || t.is(",") || t.is("}")) {
			return out, nil
		}
		if t.is("(") || t.is("[") {
			depth++
		}
		if t.is(")") || t.is("]") {
			if depth == 0 {
				return out, nil
			}
			depth--
		}
		out = append(out, p.next())
	}
}
