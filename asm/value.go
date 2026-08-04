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
	// chain is the @local scope chain at an @-label forward reference: the
	// definition may land in ANY enclosing scope (a macro argument like
	// "pushword |@deref_handle" is evaluated inside the expansion's scope,
	// but the label is defined later in the caller's scope).
	chain []int
	// pub marks a reference to a published (ENTRY/EXPORT) symbol other than a
	// segment's own label.
	pub bool
	// viaWith marks a binding made through a WITH instance; it is final --
	// pass 2 must not rebind it to a same-name local label (pascal.fst's
	// p_create_date stores to the GLOBALS field temp under "WITH globals"
	// even though the PROC defines its own temp further down).
	viaWith bool
	// byName marks a reference the one-pass original emitted BY NAME because
	// its binding at reference time was cross-segment, even though the final
	// (published) definition is in the referencing segment. ProDOS.FST's
	// get_write_blk does "jsr clear_index" before its own published
	// clear_index label, while an earlier segment already defined one.
	byName bool
	// lits are literal addends that stood directly after this term in the
	// source ("lst_rslt_scode+2-lst_rslt_ec"), in order, negative meaning
	// subtracted. The one-pass original emits expression operands in source
	// order and never merges two source constants once the value is
	// symbolic, so the +2 belongs to scode's operand (label, 2, add), not
	// after the subtraction, and "+zeropg_code+2" is two separate adds.
	lits []int64
}

// blocksFold reports whether a term keeps a difference of labels from folding
// to a constant. Only a *forward* reference to a published symbol does: the
// one-pass assembler has not seen its offset yet and, because the symbol is
// global, cannot resolve it at the end of the pass either -- it has to hand
// the whole expression to the linker. A backward reference to a published
// symbol folds like any other (oracle-probed over all four combinations of
// forward/backward and published/local).
func (t term) blocksFold() bool { return t.pub && t.viaFwd }

// blocksFoldIn is blocksFold with the defining segment known. In a DATA
// segment a published symbol is named in BOTH directions (see exprRef), so it
// blocks the fold either way: the printer drivers' templates open with
// "StatusWindowTemp dc.w StatusWindowTempEnd-StatusWindowTemp" and the
// original keeps the exported StatusWindowTemp symbolic (oracle-verified).
func (st *asmState) blocksFoldIn(t term) bool {
	if t.blocksFold() {
		return true
	}
	return t.pub && t.seg >= 0 && t.seg < len(st.segs) && st.segs[t.seg].kind&0x0001 != 0
}

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
	// ConstFirst records that the constant stood to the LEFT of the shifted
	// label in the source; the original emits the operands in source order.
	ConstFirst bool
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
	for _, t := range append(append([]term(nil), v.Pos...), v.Neg...) {
		// An EXPORTed EQU is published as a GEQU, and a FORWARD reference to
		// one is emitted by name rather than folded to its value -- the same
		// rule published labels follow (oracle-probed; a backward reference
		// folds). The printer drivers' dialog templates are full of them.
		if t.fwd != "" && st.entryEqu[t.fwd] {
			continue
		}
		if t.fwd != "" && (!st.imports[t.fwd] || st.localBeatsImport(t)) {
			return true
		}
	}
	return false
}

// localBeatsImport reports whether a term names a FILE-scope import that the
// referencing segment defines itself -- the LaserWriter case, where the local
// label wins (see resolveMode).
func (st *asmState) localBeatsImport(t term) bool {
	if !st.fileImports[t.fwd] {
		return false
	}
	_, ok := st.nextDefScoped(t.fwd, t.scope, t.atSeq)
	return ok
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

// cancel removes resolved same-segment pos/neg pairs. A pair naming a
// PUBLISHED symbol is left alone here: whether it folds depends on where the
// REFERENCE stands (same segment as the labels: folds, like ud3.5's
// dib_1-driver_data; another segment: stays a symbolic EXPR, like
// DOS3.3.FST's "dc.w access - g" table built in fill_param from
// global_params' fields, oracle-probed) -- and only pass 2 knows the
// segment. cancelForSeg finishes the job there.
func (v Val) cancel() Val {
	pos := append([]term(nil), v.Pos...)
	var neg []term
outer:
	for _, n := range v.Neg {
		if n.fwd == "" && !n.pub && !n.blocksFold() {
			for i, p := range pos {
				if p.fwd == "" && p.seg == n.seg && !p.pub && !p.blocksFold() {
					pos = append(pos[:i], pos[i+1:]...)
					continue outer
				}
			}
		}
		neg = append(neg, n)
	}
	return Val{C: v.C, Pos: pos, Neg: neg, Post: v.Post, Shift: v.Shift,
		AfterShift: v.AfterShift, ConstFirst: v.ConstFirst}
}

// cancelForSeg folds the same-segment pairs cancel() deferred, now that the
// referencing segment is known: a pair of labels in the reference's OWN
// segment cancels even when published (a forward reference to a published
// symbol still blocks, per blocksFold).
func (v Val) cancelForSeg(curSeg int) Val { return v.cancelForSegIn(curSeg, nil) }

func (v Val) cancelForSegIn(curSeg int, st *asmState) Val {
	blocks := func(t term) bool {
		if st != nil {
			return st.blocksFoldIn(t)
		}
		return t.blocksFold()
	}
	pos := append([]term(nil), v.Pos...)
	var neg []term
outer:
	for _, n := range v.Neg {
		if n.fwd == "" && n.seg == curSeg && !blocks(n) {
			for i, p := range pos {
				if p.fwd == "" && p.seg == curSeg && !blocks(p) {
					pos = append(pos[:i], pos[i+1:]...)
					continue outer
				}
			}
		}
		neg = append(neg, n)
	}
	return Val{C: v.C, Pos: pos, Neg: neg, Post: v.Post, Shift: v.Shift,
		AfterShift: v.AfterShift, ConstFirst: v.ConstFirst, defSeq: v.defSeq}
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

// attachLit folds a constant that follows a single positive label term onto
// that term, preserving the source order the one-pass original emits:
// "scode+2-ec" reaches the object as scode, 2, add, ec, subtract, not as
// (scode-ec)+2. Only that shape attaches -- a trailing constant after a
// subtraction ("scode-ec+2") really is emitted last, and shifted or deferred
// values keep their own ordering rules.
func (v Val) attachLit(o Val, c int64) (Val, bool) {
	if !o.isNum() || c == 0 || o.Shift != 0 || len(o.Post) > 0 {
		return Val{}, false
	}
	if len(v.Pos) != 1 || len(v.Neg) != 0 || len(v.Post) > 0 || v.Shift != 0 {
		return Val{}, false
	}
	r := v
	r.Pos = append([]term(nil), v.Pos...)
	r.Pos[0].lits = append(append([]int64(nil), r.Pos[0].lits...), c)
	r.C += c
	return r, true
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

// addConst appends a constant to a value that already carries deferred
// operations, so that it is applied after them rather than folded into the
// linear part. "cst_size*2-2" is (cst_size*2)-2; folding the -2 into C and
// then multiplying gives (cst_size-2)*2.
func (v Val) addConst(op byte, c int64) Val {
	r := v
	r.Post = append(append([]postOp(nil), v.Post...), postOp{Op: op, Val: c})
	return r
}

func (v Val) add(o Val) (Val, error) {
	// A constant joining a symbolic value keeps its own place in the token
	// stream: attached to the single positive term when nothing follows it
	// yet, or as an ordered trailing add otherwise. Two source constants
	// never merge once the value is symbolic ("+zeropg_code+2" in
	// SCSIM.Mgmnt is two separate adds, oracle-verified). A shifted value
	// keeps the AfterShift/ConstFirst path below.
	if o.isNum() && v.isLabel() && v.Shift == 0 && o.Shift == 0 {
		if o.C == 0 {
			return v, nil
		}
		if r, ok := v.attachLit(o, o.C); ok {
			return r, nil
		}
		return v.addConst(0x01, o.C), nil
	}
	if len(v.Post) > 0 && o.isNum() {
		if o.C == 0 {
			return v, nil
		}
		return v.addConst(0x01, o.C), nil
	}
	shift, post, err := combine(v, o)
	if err != nil {
		return Val{}, err
	}
	r := Val{
		C: v.C + o.C,
		// a constant joining an already-shifted value lands after the shift,
		// and on whichever side of the operator it stood in the source
		AfterShift: v.AfterShift || o.AfterShift || shift != 0,
		ConstFirst: v.ConstFirst || o.ConstFirst || (v.isNum() && o.Shift != 0),
		Pos:        append(append([]term(nil), v.Pos...), o.Pos...),
		Neg:        append(append([]term(nil), v.Neg...), o.Neg...),
		Shift:      shift, Post: post,
	}
	return r.cancel(), nil
}

func (v Val) sub(o Val) (Val, error) {
	if o.isNum() && v.isLabel() && v.Shift == 0 && o.Shift == 0 {
		if o.C == 0 {
			return v, nil
		}
		if r, ok := v.attachLit(o, -o.C); ok {
			return r, nil
		}
		return v.addConst(0x02, o.C), nil
	}
	if len(v.Post) > 0 && o.isNum() {
		if o.C == 0 {
			return v, nil
		}
		return v.addConst(0x02, o.C), nil
	}
	shift, post, err := combine(v, o)
	if err != nil {
		return Val{}, err
	}
	r := Val{
		C: v.C - o.C,
		// a constant joining an already-shifted value lands after the shift
		AfterShift: v.AfterShift || o.AfterShift || shift != 0,
		Pos:        append(append([]term(nil), v.Pos...), o.Neg...),
		Neg:        append(append([]term(nil), v.Neg...), o.Pos...),
		Shift:      shift, Post: post,
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
		case 0x01:
			c += o.Val
		case 0x02:
			c -= o.Val
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
