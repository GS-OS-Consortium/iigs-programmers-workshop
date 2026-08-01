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

func (p *exprParser) parseAdd() (Val, error) {
	v, err := p.parseShift()
	if err != nil {
		return Val{}, err
	}
	for {
		p.skipWS()
		switch {
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
			if v, err = numOp(">>", v, r, func(x, y int64) (int64, error) { return x >> uint(y), nil }); err != nil {
				return Val{}, err
			}
		case "<<":
			p.pos += 2
			r, err := p.parseMul()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOp("<<", v, r, func(x, y int64) (int64, error) { return x << uint(y), nil }); err != nil {
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
			if v, err = numOp("**", v, r, func(x, y int64) (int64, error) { return x & y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek() == '*' && !p.atLocCounter():
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOp("*", v, r, func(x, y int64) (int64, error) { return x * y, nil }); err != nil {
				return Val{}, err
			}
		case p.peek() == '/':
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return Val{}, err
			}
			if v, err = numOp("/", v, r, func(x, y int64) (int64, error) {
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
		for p.pos < len(p.s) {
			if p.s[p.pos] == '\'' {
				if p.pos+1 < len(p.s) && p.s[p.pos+1] == '\'' { // escaped quote
					v = v<<8 | '\''
					p.pos += 2
					n++
					continue
				}
				break
			}
			v = v<<8 | int64(p.s[p.pos])
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
		return p.ctx.st.lookup(name), nil
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
func isSymChar(c byte) bool { return isSymStart(c) || c >= '0' && c <= '9' || c == '.' }
