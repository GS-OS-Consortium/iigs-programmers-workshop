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
	defSeq int64  // definition counter of the definition this resolved to
	scope  string // symbol-table scope prefix in effect at the reference
	// pub marks a reference to a published (ENTRY/EXPORT) symbol other than a
	// segment's own label.
	pub bool
}

// blocksFold reports whether a term keeps a difference of labels from folding
// to a constant. Only a *forward* reference to a published symbol does: the
// one-pass assembler has not seen its offset yet and, because the symbol is
// global, cannot resolve it at the end of the pass either -- it has to hand
// the whole expression to the linker. A backward reference to a published
// symbol folds like any other (oracle-probed over all four combinations of
// forward/backward and published/local).
func (t term) blocksFold() bool { return t.pub && t.viaFwd }

// postOp is an operation the linker applies after the linear part, using the
// OMF expression opcodes ($03 multiply, $04 divide, $05 mod, $07 shift,
// $08 AND, $09 OR, $0A EOR). It exists because an expression over published
// symbols cannot be folded here -- "(past_offset_tbl-offset_tbl)/4" reaches
// the object as PAST, OFFSET, subtract, 4, divide.
type postOp struct {
	Op  byte
	Val int64
}

type Val struct {
	C    int64
	Pos  []term
	Neg  []term
	Post []postOp
	// Shift is a pending shift on a relocatable value (negative = right), as
	// in `pushlong #label>>16` to extract a label's bank. The amount cannot be
	// applied here because the segment base is not known until link time, so
	// it rides along and the linker performs it via an expression record.
	Shift int64
	// AfterShift records that C was added AFTER the shift rather than before,
	// which the linker has to be told apart: Applesoft's "(romasoft-48)>>8"
	// shifts the sum, while Init2's "$4000+(draw_window>>16)" shifts only the
	// label. Same fields otherwise, different arithmetic.
	AfterShift bool
	// defSeq orders definitions of duplicated labels (see asmState.symSeq).
	defSeq int64
}

func num(c int64) Val { return Val{C: c} }

// segVal is a location in a segment. The offset is recorded on the term as
// well as in C: a general expression record emits each operand as its own
// label-plus-displacement pair, so the operands' offsets must stay separable
// from any literal addend in the expression.
func segVal(seg int, off int64) Val {
	return Val{C: off, Pos: []term{{seg: seg, symOff: off}}}
}

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
		if n.fwd == "" && !n.blocksFold() {
			for i, p := range pos {
				if p.fwd == "" && p.seg == n.seg && !p.blocksFold() {
					pos = append(pos[:i], pos[i+1:]...)
					continue outer
				}
			}
		}
		neg = append(neg, n)
	}
	return Val{C: v.C, Pos: pos, Neg: neg, Post: v.Post, Shift: v.Shift, AfterShift: v.AfterShift}
}

// foldPub cancels pairs that cancel() left alone because they name published
// symbols. An EQU must produce an absolute value -- ProDOS.FST publishes
// "Max_call equ end_tbl-cmd_tbl" as a GEQU -- so its operands fold even
// though the same expression in a DC would stay symbolic.
func (v Val) foldPub() Val {
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
	return Val{C: v.C, Pos: pos, Neg: neg, Post: v.Post, Shift: v.Shift}
}

// combine carries a pending shift or deferred operation through an addition:
// "$4000+(draw_window>>16)" adds a constant to an already-shifted label, and
// dropping the shift here silently produced the label's low word instead of
// its bank.
func combine(a, b Val) (int64, []postOp, error) {
	if a.Shift != 0 && b.Shift != 0 {
		return 0, nil, fmt.Errorf("cannot combine two shifted values")
	}
	_ = a
	if len(a.Post) > 0 && len(b.Post) > 0 {
		return 0, nil, fmt.Errorf("cannot combine two deferred expressions")
	}
	post := a.Post
	if len(post) == 0 {
		post = b.Post
	}
	return a.Shift + b.Shift, post, nil
}

func (v Val) add(o Val) (Val, error) {
	shift, post, err := combine(v, o)
	if err != nil {
		return Val{}, err
	}
	r := Val{
		C:     v.C + o.C,
		// a constant joining an already-shifted value lands after the shift
		AfterShift: v.AfterShift || o.AfterShift || shift != 0,
		Pos:   append(append([]term(nil), v.Pos...), o.Pos...),
		Neg:   append(append([]term(nil), v.Neg...), o.Neg...),
		Shift: shift, Post: post,
	}
	return r.cancel(), nil
}

func (v Val) sub(o Val) (Val, error) {
	shift, post, err := combine(v, o)
	if err != nil {
		return Val{}, err
	}
	r := Val{
		C:     v.C - o.C,
		// a constant joining an already-shifted value lands after the shift
		AfterShift: v.AfterShift || o.AfterShift || shift != 0,
		Pos:   append(append([]term(nil), v.Pos...), o.Neg...),
		Neg:   append(append([]term(nil), v.Neg...), o.Pos...),
		Shift: shift, Post: post,
	}
	return r.cancel(), nil
}

func (v Val) negate() Val {
	return Val{C: -v.C, Pos: append([]term(nil), v.Neg...), Neg: append([]term(nil), v.Pos...)}
}

// numOrDefer folds when both sides are constant, and otherwise defers the
// operation to the linker when the right side is constant and the OMF
// expression grammar has an opcode for it.
func numOrDefer(name string, code byte, a, b Val, f func(x, y int64) (int64, error)) (Val, error) {
	if a.isNum() && b.isNum() {
		c, err := f(a.C, b.C)
		return num(c), err
	}
	if !b.isNum() || !a.isLabel() {
		return Val{}, fmt.Errorf("%s requires constant operands", name)
	}
	r := a
	r.Post = append(append([]postOp(nil), a.Post...), postOp{Op: code, Val: b.C})
	return r, nil
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

// applyPost folds the deferred operations into a value that turned out to be
// constant after all (a forward reference that resolved within the segment).
func applyPost(c int64, post []postOp) int64 {
	for _, o := range post {
		switch o.Op {
		case 0x03:
			c *= o.Val
		case 0x04:
			if o.Val != 0 {
				c /= o.Val
			}
		case 0x05:
			if o.Val != 0 {
				c %= o.Val
			}
		case 0x07:
			c = applyShift(c, o.Val)
		case 0x08:
			c &= o.Val
		case 0x09:
			c |= o.Val
		case 0x0A:
			c ^= o.Val
		}
	}
	return c
}
