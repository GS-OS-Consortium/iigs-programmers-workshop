package asm

import (
	"fmt"
	"strings"
)

// Expression evaluator for MPW IIgs assembler operands, producing linear
// Vals (constant, label+constant, or forward-label+constant).
//
// Operators (subset used by the GS/OS-era sources): + - * / unary +/-,
// ** (bitwise AND), ++ (bitwise OR is "--"? not seen; ** verified from
// Firmware.macros), << >> shifts, parentheses. `*` alone is the location
// counter. Symbols may contain letters, digits, _ ~ . @ & and don't start
// with a digit.

type exprCtx struct {
	st *asmState // symbol resolution + location counter; nil in pure-numeric contexts
	// pass-2 deferred evaluation: override the location counter
	pcOverride  int64
	segOverride int
	overridePC  bool
	// treat resolved labels as absolute numbers (org+offset) in arithmetic
	// contexts, matching the one-pass original where labels are plain values
	absLabels bool
	// macro-language contexts (SETA, &EVAL): labels are absolute numbers at
	// the term level
	macroTerms bool
}

type exprParser struct {
	s   string
	pos int
	ctx *exprCtx
}

func evalExpr(s string, ctx *exprCtx) (Val, error) {
	p := &exprParser{s: strings.TrimSpace(s), ctx: ctx}
	v, err := p.parseAdd()
	if err != nil {
		return Val{}, err
	}
	p.skipWS()
	if p.pos != len(p.s) {
		return Val{}, fmt.Errorf("junk after expression: %q", p.s[p.pos:])
	}
	return v, nil
}

// evalNumLenient evaluates in macro-language contexts (SETA, &EVAL) where
// the one-pass original assembler sees code labels as plain numbers: a
// single-label result yields its segment offset.
func evalNumLenient(s string, ctx *exprCtx) (int64, error) {
	ctx.absLabels = true
	ctx.macroTerms = true
	v, err := evalExpr(s, ctx)
	if err != nil {
		return 0, err
	}
	if v.isNum() {
		return v.C, nil
	}
	if len(v.Pos) == 1 && len(v.Neg) == 0 && v.Pos[0].fwd == "" && ctx.st != nil {
		seg := v.Pos[0].seg
		if seg >= 0 && seg < len(ctx.st.segs) {
			return ctx.st.segs[seg].org + v.C, nil
		}
	}
	return 0, fmt.Errorf("expression must be constant: %q", s)
}

// evalNum evaluates and requires a plain numeric result.
func evalNum(s string, ctx *exprCtx) (int64, error) {
	v, err := evalExpr(s, ctx)
	if err != nil {
		return 0, err
	}
	if !v.isNum() {
		return 0, fmt.Errorf("expression must be constant: %q", s)
	}
	return v.C, nil
}

func (p *exprParser) skipWS() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func (p *exprParser) peek() byte {
	if p.pos < len(p.s) {
		return p.s[p.pos]
	}
	return 0
}

func (p *exprParser) peek2() string {
	if p.pos+1 < len(p.s) {
		return p.s[p.pos : p.pos+2]
	}
	return ""
}

// peekWord reports whether the next token is the given word operator,
// delimited so that a symbol such as ANDMASK is not mistaken for one.
func (p *exprParser) peekWord(w string) bool {
	if p.pos+len(w) > len(p.s) || !strings.EqualFold(p.s[p.pos:p.pos+len(w)], w) {
		return false
	}
	if j := p.pos + len(w); j < len(p.s) && isSymChar(p.s[j]) {
		return false
	}
	return p.pos == 0 || !isSymChar(p.s[p.pos-1])
}

func (p *exprParser) parseAdd() (Val, error) {
	v, err := p.parseShift()
	if err != nil {
		return Val{}, err
	}
	for {
		p.skipWS()
		switch {
		case p.peekWord("AND"): // word forms of the bitwise operators
			p.pos += 3
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("AND", 0x08, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x & y, nil }); err != nil {
				return Val{}, err
			}
		case p.peekWord("OR"):
			p.pos += 2
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("OR", 0x09, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x | y, nil }); err != nil {
				return Val{}, err
			}
		case p.peekWord("EOR"), p.peekWord("XOR"):
			p.pos += 3
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("EOR", 0x0A, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x ^ y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek2() == "--": // bitwise XOR (MPW asm)
			p.pos += 2
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("--", 0x0A, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x ^ y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek2() == "++": // bitwise OR (MPW asm)
			p.pos += 2
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("++", 0x09, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x | y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek() == '+':
			p.pos++
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = v.add(r); err != nil {
				return Val{}, err
			}
		case p.peek() == '-':
			p.pos++
			r, err := p.parseShift()
			if err != nil {
				return Val{}, err
			}
			if v, err = v.sub(r); err != nil {
				return Val{}, err
			}
		default:
			return v, nil
		}
	}
}

// absify converts a single resolved label into its absolute numeric value
// when the context allows it (deferred pass-2 / macro-language arithmetic).
func (p *exprParser) absify(v Val) Val {
	if !p.ctx.absLabels || p.ctx.st == nil {
		return v
	}
	if len(v.Pos) == 1 && len(v.Neg) == 0 && v.Pos[0].fwd == "" {
		seg := v.Pos[0].seg
		if seg >= 0 && seg < len(p.ctx.st.segs) {
			return num(p.ctx.st.segs[seg].org + v.C)
		}
	}
	return v
}

func (p *exprParser) parseShift() (Val, error) {
	v, err := p.parseMul()
	if err != nil {
		return Val{}, err
	}
	for {
		p.skipWS()
		switch p.peek2() {
		case ">>":
			p.pos += 2
			r, err := p.parseMul()
			if err != nil {
				return Val{}, err
			}
			if v, err = shiftOp(">>", p.absify(v), p.absify(r), -r.C); err != nil {
				return Val{}, err
			}
		case "<<":
			p.pos += 2
			r, err := p.parseMul()
			if err != nil {
				return Val{}, err
			}
			if v, err = shiftOp("<<", p.absify(v), p.absify(r), r.C); err != nil {
				return Val{}, err
			}
		default:
			return v, nil
		}
	}
}

func (p *exprParser) parseMul() (Val, error) {
	v, err := p.parseUnary()
	if err != nil {
		return Val{}, err
	}
	for {
		p.skipWS()
		switch {
		case p.peek2() == "**": // bitwise AND (MPW asm)
			p.pos += 2
			r, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("**", 0x08, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x & y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek() == '*' && !p.atLocCounter():
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("*", 0x03, p.absify(v), p.absify(r), func(x, y int64) (int64, error) { return x * y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek2() == "//": // integer remainder (MPW asm)
			p.pos += 2
			r, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("//", 0x05, p.absify(v), p.absify(r), func(x, y int64) (int64, error) {
				if y == 0 {
					return 0, fmt.Errorf("division by zero")
				}
				return x % y, nil
			}); err != nil {
				return Val{}, err
			}
		case p.peek() == '/':
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOrDefer("/", 0x04, p.absify(v), p.absify(r), func(x, y int64) (int64, error) {
				if y == 0 {
					return 0, fmt.Errorf("division by zero")
				}
				return x / y, nil
			}); err != nil {
				return Val{}, err
			}
		default:
			return v, nil
		}
	}
}

// atLocCounter reports whether the '*' at p.pos is the location counter
// rather than a multiply: true when no operand precedes it — we only call
// this from infix position, so it is always an operator. Kept for clarity.
func (p *exprParser) atLocCounter() bool { return false }

func (p *exprParser) parseUnary() (Val, error) {
	p.skipWS()
	switch p.peek() {
	case '+':
		p.pos++
		return p.parseUnary()
	case '-':
		p.pos++
		v, err := p.parseUnary()
		if err != nil {
			return Val{}, err
		}
		return v.negate(), nil
	case '(':
		p.pos++
		v, err := p.parseAdd()
		if err != nil {
			return Val{}, err
		}
		p.skipWS()
		if p.peek() != ')' {
			return Val{}, fmt.Errorf("missing )")
		}
		p.pos++
		return v, nil
	}
	// word-form logical/bitwise operators
	rest := p.s[p.pos:]
	for _, w := range []struct {
		kw string
		f  func(int64) int64
	}{
		{"not", func(v int64) int64 {
			if v == 0 {
				return 1
			}
			return 0
		}},
	} {
		if len(rest) > len(w.kw) && strings.EqualFold(rest[:len(w.kw)], w.kw) &&
			(rest[len(w.kw)] == ' ' || rest[len(w.kw)] == '\t' || rest[len(w.kw)] == '(') {
			p.pos += len(w.kw)
			v, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if !v.isNum() {
				return Val{}, fmt.Errorf("%s requires a constant operand", w.kw)
			}
			return num(w.f(v.C)), nil
		}
	}
	// ≈ is the MPW assembler's one's-complement operator
	if strings.HasPrefix(p.s[p.pos:], "≈") {
		p.pos += len("≈")
		v, err := p.parseUnary()
		if err != nil {
			return Val{}, err
		}
		if !v.isNum() {
			return Val{}, fmt.Errorf("cannot complement a label")
		}
		return num(^v.C), nil
	}
	return p.parseTerm()
}

func (p *exprParser) parseTerm() (Val, error) {
	p.skipWS()
	if p.pos >= len(p.s) {
		return Val{}, fmt.Errorf("expected operand")
	}
	c := p.s[p.pos]
	switch {
	case c == '$':
		p.pos++
		return p.parseDigits(16, isHex)
	case c == '%':
		p.pos++
		return p.parseDigits(2, isBin)
	case c >= '0' && c <= '9':
		return p.parseDigits(10, isDec)
	case c == '\'':
		p.pos++
		var v int64
		n := 0
		hi := int64(0)
		if p.ctx.st != nil && p.ctx.st.msb {
			hi = 0x80 // MSB ON sets the high bit of character constants
		}
		for p.pos < len(p.s) {
			if p.s[p.pos] == '\'' {
				if p.pos+1 < len(p.s) && p.s[p.pos+1] == '\'' { // escaped quote
					v = v<<8 | ('\'' | hi)
					p.pos += 2
					n++
					continue
				}
				break
			}
			v = v<<8 | (int64(p.s[p.pos]) | hi)
			p.pos++
			n++
		}
		if p.pos >= len(p.s) || n == 0 || n > 4 {
			return Val{}, fmt.Errorf("bad character constant")
		}
		p.pos++
		return num(v), nil
	case c == '*':
		p.pos++
		if p.ctx.overridePC {
			return segVal(p.ctx.segOverride, p.ctx.pcOverride), nil
		}
		if p.ctx.st == nil {
			return Val{}, fmt.Errorf("* outside code")
		}
		if p.ctx.st.inRecord {
			return num(p.ctx.st.recPC), nil
		}
		if p.ctx.st.cur == nil {
			return Val{}, fmt.Errorf("* outside code")
		}
		return segVal(p.ctx.st.curSegIndex(), p.ctx.st.pc), nil
	case isSymStart(c):
		start := p.pos
		for p.pos < len(p.s) && isSymChar(p.s[p.pos]) {
			p.pos++
		}
		name := strings.ToUpper(p.s[start:p.pos])
		if p.ctx.st == nil {
			return Val{}, fmt.Errorf("undefined symbol %s", name)
		}
		v := p.ctx.st.lookup(name)
		if p.ctx.macroTerms {
			v = p.absify(v)
		}
		return v, nil
	}
	return Val{}, fmt.Errorf("unexpected %q", string(c))
}

func (p *exprParser) parseDigits(base int64, valid func(byte) bool) (Val, error) {
	start := p.pos
	var v int64
	for p.pos < len(p.s) && valid(p.s[p.pos]) {
		v = v*base + int64(hexVal(p.s[p.pos]))
		p.pos++
	}
	if p.pos == start {
		return Val{}, fmt.Errorf("expected digits")
	}
	return num(v), nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
func isBin(c byte) bool { return c == '0' || c == '1' }
func isDec(c byte) bool { return c >= '0' && c <= '9' }
func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}
func isSymStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '@' || c == '&' || c == '~'
}

// '$' may appear inside an identifier (e.g. cmd_$802A); it only introduces a
// hex constant at the start of a term.
func isSymChar(c byte) bool {
	return isSymStart(c) || c >= '0' && c <= '9' || c == '.' || c == '$'
}
