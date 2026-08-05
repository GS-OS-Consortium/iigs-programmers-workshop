package rez

import (
	"fmt"
	"strings"
)

// constEval evaluates Rez expressions: integers, #defined names, the usual
// C operators, and the builtins the templates use ($$Word, $$Countof,
// $$optionalcount). When em is set, labels and array counts recorded during
// emission are in scope.
type constEval struct {
	c    *Compiler
	em   *emitter
	toks []token
	pos  int
	seen map[string]bool
}

func (e *constEval) peek() token {
	if e.pos < len(e.toks) {
		return e.toks[e.pos]
	}
	return token{kind: tEOF}
}

func (e *constEval) next() token {
	t := e.peek()
	if e.pos < len(e.toks) {
		e.pos++
	}
	return t
}

// precedence levels, loosest first
var binOps = [][]string{
	{"||"}, {"&&"}, {"|"}, {"^"}, {"&"},
	{"==", "!="}, {"<", ">", "<=", ">="},
	{"<<", ">>"}, {"+", "-"}, {"*", "/", "%"},
}

func (e *constEval) expr(level int) (int64, error) {
	if level >= len(binOps) {
		return e.unary()
	}
	l, err := e.expr(level + 1)
	if err != nil {
		return 0, err
	}
	for {
		t := e.peek()
		matched := ""
		for _, op := range binOps[level] {
			if t.is(op) {
				matched = op
				break
			}
		}
		if matched == "" {
			return l, nil
		}
		e.next()
		r, err := e.expr(level + 1)
		if err != nil {
			return 0, err
		}
		l, err = applyBin(matched, l, r)
		if err != nil {
			return 0, err
		}
	}
}

func applyBin(op string, l, r int64) (int64, error) {
	switch op {
	case "+":
		return l + r, nil
	case "-":
		return l - r, nil
	case "*":
		return l * r, nil
	case "/":
		if r == 0 {
			return 0, fmt.Errorf("division by zero")
		}
		return l / r, nil
	case "%":
		if r == 0 {
			return 0, fmt.Errorf("division by zero")
		}
		return l % r, nil
	case "<<":
		return l << uint(r), nil
	case ">>":
		return l >> uint(r), nil
	case "&":
		return l & r, nil
	case "|":
		return l | r, nil
	case "^":
		return l ^ r, nil
	case "&&":
		return b2i(l != 0 && r != 0), nil
	case "||":
		return b2i(l != 0 || r != 0), nil
	case "==":
		return b2i(l == r), nil
	case "!=":
		return b2i(l != r), nil
	case "<":
		return b2i(l < r), nil
	case ">":
		return b2i(l > r), nil
	case "<=":
		return b2i(l <= r), nil
	case ">=":
		return b2i(l >= r), nil
	}
	return 0, fmt.Errorf("unknown operator %q", op)
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (e *constEval) unary() (int64, error) {
	t := e.peek()
	switch {
	case t.is("-"):
		e.next()
		v, err := e.unary()
		return -v, err
	case t.is("+"):
		e.next()
		return e.unary()
	case t.is("~"):
		e.next()
		v, err := e.unary()
		return ^v, err
	case t.is("!"):
		e.next()
		v, err := e.unary()
		return b2i(v == 0), err
	case t.is("("):
		e.next()
		v, err := e.expr(0)
		if err != nil {
			return 0, err
		}
		if !e.peek().is(")") {
			return 0, fmt.Errorf("missing ) in expression")
		}
		e.next()
		return v, nil
	}
	return e.primary()
}

func (e *constEval) primary() (int64, error) {
	t := e.next()
	switch {
	case t.kind == tNumber:
		return t.num, nil

	case t.kind == tString:
		// a character literal used as a number ('abcd' style) -- pack the
		// bytes big-endian, which is how Rez reads a 4-char type
		var v int64
		for _, b := range macRomanBytes(t) {
			v = v<<8 | int64(b)
		}
		return v, nil

	case t.kind == tIdent && strings.HasPrefix(t.text, "$$"):
		return e.builtin(t)

	case t.kind == tIdent:
		// a named constant declared on the field ("behind=0,infront=-1")
		if e.em != nil && e.em.consts != nil {
			if v, ok := e.em.consts[strings.ToLower(t.text)]; ok {
				return v, nil
			}
		}
		// a label recorded during emission; "label[expr]" addresses one
		// instance of a label defined inside an array element (rPicture)
		if e.em != nil {
			key := strings.ToLower(t.text)
			if e.peek().is("[") {
				e.next()
				idx, err := e.expr(0)
				if err != nil {
					return 0, err
				}
				if !e.peek().is("]") {
					return 0, fmt.Errorf("missing ] after %s[", t.text)
				}
				e.next()
				key = fmt.Sprintf("%s#%d", key, idx)
				if off, ok := e.em.labels[key]; ok {
					return int64(off), nil
				}
				if e.em.pass1 {
					return 0, nil
				}
				return 0, fmt.Errorf("%s:%d: unknown label instance %q", t.file, t.line, key)
			}
			if off, ok := e.em.labels[key]; ok {
				return int64(off), nil
			}
		}
		if body, ok := e.c.defs[strings.ToLower(t.text)]; ok {
			if e.seen == nil {
				e.seen = map[string]bool{}
			}
			if e.seen[strings.ToLower(t.text)] {
				return 0, fmt.Errorf("recursive definition of %q", t.text)
			}
			e.seen[t.text] = true
			defer delete(e.seen, t.text)
			sub := &constEval{c: e.c, em: e.em, toks: body, seen: e.seen}
			v, err := sub.expr(0)
			if err != nil {
				return 0, err
			}
			return v, nil
		}
		if e.em != nil && e.em.pass1 {
			return 0, nil // a label not yet placed; the second pass has it
		}
		return 0, fmt.Errorf("%s:%d: undefined name %q", t.file, t.line, t.text)
	}
	return 0, fmt.Errorf("%s:%d: unexpected %s in expression", t.file, t.line, t)
}

// builtin evaluates $$Word(label), $$Byte(label), $$Long(label),
// $$Countof(array) and $$optionalcount(array).
func (e *constEval) builtin(t token) (int64, error) {
	name := strings.ToLower(strings.TrimPrefix(t.text, "$$"))
	if !e.peek().is("(") {
		return 0, fmt.Errorf("%s needs an argument", t.text)
	}
	e.next()
	argTok := e.next()
	arg := strings.ToLower(argTok.text)
	if e.em == nil {
		return 0, fmt.Errorf("%s is only valid while emitting a resource", t.text)
	}
	// the argument may be an indexed label instance: $$Word(ClipStart[expr])
	if e.peek().is("[") {
		e.next()
		idx, err := e.expr(0)
		if err != nil {
			return 0, err
		}
		if !e.peek().is("]") {
			return 0, fmt.Errorf("missing ] in %s argument", t.text)
		}
		e.next()
		arg = fmt.Sprintf("%s#%d", arg, idx)
	}
	if !e.peek().is(")") {
		return 0, fmt.Errorf("%s(: missing )", t.text)
	}
	e.next()

	switch name {
	case "countof", "optionalcount":
		// inside an array element, the per-element count (recorded by
		// setCount under "name#i") wins over whatever the previous element
		// left under the bare key
		if l := len(e.em.arrStack); l > 0 {
			key := fmt.Sprintf("%s#%d", arg, e.em.arrStack[l-1].idx)
			if v, ok := e.em.counts[key]; ok {
				return v, nil
			}
		}
		return e.em.counts[arg], nil
	case "arrayindex":
		// index (1-based) of the element being emitted in the named
		// enclosing array
		for i := len(e.em.arrStack) - 1; i >= 0; i-- {
			if e.em.arrStack[i].name == arg {
				return e.em.arrStack[i].idx, nil
			}
		}
		return 0, fmt.Errorf("$$ArrayIndex(%s): not inside that array", argTok.text)
	case "word", "byte", "long":
		bitOff, ok := e.em.labels[arg]
		off := bitOff / 8 // labels are bit offsets; these builtins read bytes
		n := map[string]int{"byte": 1, "word": 2, "long": 4}[name]
		if !ok || off+n > len(e.em.buf) {
			if e.em.pass1 {
				return 0, nil
			}
			if !ok {
				return 0, fmt.Errorf("%s: unknown label %q", t.text, argTok.text)
			}
			return 0, fmt.Errorf("%s(%s): reads past the data emitted so far",
				t.text, argTok.text)
		}
		var v int64
		for i := n - 1; i >= 0; i-- {
			v = v<<8 | int64(e.em.buf[off+i])
		}
		return v, nil
	}
	return 0, fmt.Errorf("unsupported builtin %s", t.text)
}
