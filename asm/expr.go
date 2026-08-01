package asm

import (
	"fmt"
	"strings"
)

// Expression evaluator for MPW IIgs assembler operand expressions.
// First-light subset: $hex, decimal, %binary, 'c' char constants, symbols,
// unary + - ~ <(low byte) >(high byte) ^(bank byte), binary + - * / and
// parentheses. Symbol values must be resolvable at evaluation time.

type exprCtx struct {
	syms map[string]int64
	pc   int64
}

type exprParser struct {
	s   string
	pos int
	ctx *exprCtx
}

func evalExpr(s string, ctx *exprCtx) (int64, error) {
	p := &exprParser{s: strings.TrimSpace(s), ctx: ctx}
	v, err := p.parseAdd()
	if err != nil {
		return 0, err
	}
	p.skipWS()
	if p.pos != len(p.s) {
		return 0, fmt.Errorf("junk after expression: %q", p.s[p.pos:])
	}
	return v, nil
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

func (p *exprParser) parseAdd() (int64, error) {
	v, err := p.parseMul()
	if err != nil {
		return 0, err
	}
	for {
		p.skipWS()
		switch p.peek() {
		case '+':
			p.pos++
			r, err := p.parseMul()
			if err != nil {
				return 0, err
			}
			v += r
		case '-':
			p.pos++
			r, err := p.parseMul()
			if err != nil {
				return 0, err
			}
			v -= r
		default:
			return v, nil
		}
	}
}

func (p *exprParser) parseMul() (int64, error) {
	v, err := p.parseUnary()
	if err != nil {
		return 0, err
	}
	for {
		p.skipWS()
		switch p.peek() {
		case '*':
			// '*' is also the location counter; as an infix operator here.
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return 0, err
			}
			v *= r
		case '/':
			p.pos++
			r, err := p.parseUnary()
			if err != nil {
				return 0, err
			}
			if r == 0 {
				return 0, fmt.Errorf("division by zero")
			}
			v /= r
		default:
			return v, nil
		}
	}
}

func (p *exprParser) parseUnary() (int64, error) {
	p.skipWS()
	switch p.peek() {
	case '+':
		p.pos++
		return p.parseUnary()
	case '-':
		p.pos++
		v, err := p.parseUnary()
		return -v, err
	case '<': // low byte
		p.pos++
		v, err := p.parseUnary()
		return v & 0xFF, err
	case '>': // high byte
		p.pos++
		v, err := p.parseUnary()
		return (v >> 8) & 0xFF, err
	case '^': // bank byte
		p.pos++
		v, err := p.parseUnary()
		return (v >> 16) & 0xFF, err
	case '(':
		p.pos++
		v, err := p.parseAdd()
		if err != nil {
			return 0, err
		}
		p.skipWS()
		if p.peek() != ')' {
			return 0, fmt.Errorf("missing )")
		}
		p.pos++
		return v, nil
	}
	return p.parseTerm()
}

func (p *exprParser) parseTerm() (int64, error) {
	p.skipWS()
	if p.pos >= len(p.s) {
		return 0, fmt.Errorf("expected operand")
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
		for p.pos < len(p.s) && p.s[p.pos] != '\'' {
			v = v<<8 | int64(p.s[p.pos])
			p.pos++
			n++
		}
		if p.pos >= len(p.s) || n == 0 || n > 4 {
			return 0, fmt.Errorf("bad character constant")
		}
		p.pos++
		return v, nil
	case c == '*':
		p.pos++
		return p.ctx.pc, nil
	case isSymStart(c):
		start := p.pos
		for p.pos < len(p.s) && isSymChar(p.s[p.pos]) {
			p.pos++
		}
		name := strings.ToUpper(p.s[start:p.pos])
		v, ok := p.ctx.syms[name]
		if !ok {
			return 0, fmt.Errorf("undefined symbol %s", name)
		}
		return v, nil
	}
	return 0, fmt.Errorf("unexpected %q", string(c))
}

func (p *exprParser) parseDigits(base int64, valid func(byte) bool) (int64, error) {
	start := p.pos
	var v int64
	for p.pos < len(p.s) && valid(p.s[p.pos]) {
		v = v*base + int64(hexVal(p.s[p.pos]))
		p.pos++
	}
	if p.pos == start {
		return 0, fmt.Errorf("expected digits")
	}
	return v, nil
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
