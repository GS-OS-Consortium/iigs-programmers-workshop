package asm

import "fmt"

// Val is an assembler expression value as a linear combination:
//
//	value = C + sum(base of Pos terms) - sum(base of Neg terms)
//
// A term is either a resolved segment base (seg >= 0) or an unresolved
// forward symbol (fwd != ""). Same-segment positive/negative pairs cancel
// (the original assembler folds e.g. `APPLESOFT+$912-*` and even
// forward-forward differences like `FDCEND-FOUTBL` to plain constants).
type term struct {
	seg    int    // -1 when fwd is set
	fwd    string // unresolved symbol name
	name   string // original symbol name for resolved labels (may be "")
	symOff int64  // the symbol's own offset (to recover addends by name)
	viaFwd bool   // reference was forward (symbol undefined when referenced)
	atSeq  int64  // definition counter when the forward reference was made
}

type Val struct {
	C   int64
	Pos []term
	Neg []term
	// Shift is a pending shift on a relocatable value (negative = right), as
	// in `pushlong #label>>16` to extract a label's bank. The amount cannot be
	// applied here because the segment base is not known until link time, so
	// it rides along and the linker performs it via an expression record.
	Shift int64
	// defSeq orders definitions of duplicated labels (see asmState.symSeq).
	defSeq int64
}

func num(c int64) Val { return Val{C: c} }

func segVal(seg int, off int64) Val { return Val{C: off, Pos: []term{{seg: seg}}} }

func fwdVal(name string) Val { return Val{Pos: []term{{seg: -1, fwd: name}}} }

func (v Val) isNum() bool   { return len(v.Pos) == 0 && len(v.Neg) == 0 }
func (v Val) isLabel() bool { return !v.isNum() }

// hasUnresolvedFwd: any forward term that could still resolve from syms
// (external IMPORTs never resolve and are kept symbolic).
func (v Val) hasUnresolvedFwd(st *asmState) bool {
	for _, t := range v.Pos {
		if t.fwd != "" && !st.imports[t.fwd] {
			return true
		}
	}
	for _, t := range v.Neg {
		if t.fwd != "" && !st.imports[t.fwd] {
			return true
		}
	}
	return false
}

func (v Val) hasFwd() bool {
	for _, t := range v.Pos {
		if t.fwd != "" {
			return true
		}
	}
	for _, t := range v.Neg {
		if t.fwd != "" {
			return true
		}
	}
	return false
}

// cancel removes resolved same-segment pos/neg pairs.
func (v Val) cancel() Val {
	pos := append([]term(nil), v.Pos...)
	var neg []term
outer:
	for _, n := range v.Neg {
		if n.fwd == "" {
			for i, p := range pos {
				if p.fwd == "" && p.seg == n.seg {
					pos = append(pos[:i], pos[i+1:]...)
					continue outer
				}
			}
		}
		neg = append(neg, n)
	}
	return Val{C: v.C, Pos: pos, Neg: neg}
}

func (v Val) add(o Val) (Val, error) {
	r := Val{
		C:   v.C + o.C,
		Pos: append(append([]term(nil), v.Pos...), o.Pos...),
		Neg: append(append([]term(nil), v.Neg...), o.Neg...),
	}
	return r.cancel(), nil
}

func (v Val) sub(o Val) (Val, error) {
	r := Val{
		C:   v.C - o.C,
		Pos: append(append([]term(nil), v.Pos...), o.Neg...),
		Neg: append(append([]term(nil), v.Neg...), o.Pos...),
	}
	return r.cancel(), nil
}

func (v Val) negate() Val {
	return Val{C: -v.C, Pos: append([]term(nil), v.Neg...), Neg: append([]term(nil), v.Pos...)}
}

// numOp applies an operator that only makes sense on plain numbers.
func numOp(name string, a, b Val, f func(x, y int64) (int64, error)) (Val, error) {
	if !a.isNum() || !b.isNum() {
		return Val{}, fmt.Errorf("%s requires constant operands", name)
	}
	c, err := f(a.C, b.C)
	return num(c), err
}

// shiftOp applies << or >> (amount negated for >>). A relocatable left side
// defers the shift to the linker; anything more involved than one pending
// shift on a bare label is beyond what an expression record can carry.
func shiftOp(name string, a, b Val, amount int64) (Val, error) {
	if a.isNum() && b.isNum() {
		return num(applyShift(a.C, amount)), nil
	}
	if !b.isNum() {
		return Val{}, fmt.Errorf("%s requires a constant shift count", name)
	}
	if a.Shift != 0 {
		return Val{}, fmt.Errorf("%s: cannot shift a relocatable value twice", name)
	}
	r := a
	r.Shift = amount
	return r, nil
}
