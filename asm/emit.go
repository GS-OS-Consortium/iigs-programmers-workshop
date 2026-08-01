package asm

import (
	"encoding/binary"
	"fmt"
	"os"
)

// OMF record opcodes emitted by the assembler (kept local to avoid a
// dependency on the omf package).
const (
	recEnd    = 0x00
	recDS     = 0xF1
	recLconst = 0xF2
	recLexpr  = 0xF3
	recBexpr  = 0xED
	recExpr   = 0xEB // general expression (more than one label term)
)

// segEmitter builds a segment's record stream with the original assembler's
// chunking rules (oracle-verified): runs of code flush as CONST records when
// <= $DF bytes; longer runs emit LCONST chunks of at most $FF bytes; DS
// reservations chunk at $7FFF.
type segEmitter struct {
	pending []byte
	recs    []byte
}

// bytes appends one emission unit, flushing first if the unit would push the
// pending run past 255 bytes (oracle-verified chunking rule).
func (e *segEmitter) bytes(b []byte) {
	if len(e.pending) > 0 && len(e.pending)+len(b) > 0xFF {
		e.flush()
	}
	e.pending = append(e.pending, b...)
	for len(e.pending) > 0xFF { // oversized single unit (large fills)
		chunk := e.pending[:0xFF]
		e.recs = append(e.recs, recLconst, 0xFF, 0, 0, 0)
		e.recs = append(e.recs, chunk...)
		e.pending = e.pending[0xFF:]
	}
}

func (e *segEmitter) flush() {
	n := len(e.pending)
	if n == 0 {
		return
	}
	if n <= 0xDF {
		e.recs = append(e.recs, byte(n))
	} else {
		e.recs = append(e.recs, recLconst, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	}
	e.recs = append(e.recs, e.pending...)
	e.pending = e.pending[:0]
}

func (e *segEmitter) ds(count int64) {
	e.flush()
	for count > 0 {
		n := count
		if n > 0x7FFF {
			n = 0x7FFF
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(n))
		e.recs = append(e.recs, recDS, b[0], b[1], b[2], b[3])
		count -= n
	}
}

// expr emits an expression record: value = segLabel + disp, optionally
// shifted (negative = right). Layout (oracle-verified):
//
//	<rec> <size> $83 <pstr segname> [$81 <disp:4> $01] [$81 <shift:4> $07] $00
func (e *segEmitter) expr(rec byte, size int, segName string, disp int64, shift int64) {
	e.flush()
	e.recs = append(e.recs, rec, byte(size), 0x83, byte(len(segName)))
	e.recs = append(e.recs, segName...)
	if disp != 0 {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(disp))
		e.recs = append(e.recs, 0x81, b[0], b[1], b[2], b[3], 0x01)
	}
	if shift != 0 {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(shift))
		e.recs = append(e.recs, 0x81, b[0], b[1], b[2], b[3], 0x07)
	}
	e.recs = append(e.recs, recEnd)
}

// termRef is one operand of a general expression record: a label and the
// displacement to add to it. A symbol published by name carries its offset
// in the name itself, so its displacement is zero.
type termRef struct {
	name string
	disp int64
}

// exprGeneral emits a general EXPR record for a value that does not reduce
// to a single label plus a constant (e.g. the difference of labels in two
// different segments). The body is an RPN token stream: $83 pushes a label,
// $81 pushes a constant, $01 adds, $02 subtracts, $00 ends. Each operand is
// pushed with its own displacement, and only a literal addend left over from
// the source expression is applied at the end (oracle-verified: "elab-*" at
// offset 2 of P2 emits ELAB, P2, 2, add, subtract).
func (e *segEmitter) exprGeneral(size int, pos, neg []termRef, c int64) {
	e.flush()
	body := []byte{}
	pushConst := func(v int64) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		body = append(body, 0x81, b[0], b[1], b[2], b[3])
	}
	pushTerm := func(t termRef) {
		body = append(body, 0x83, byte(len(t.name)))
		body = append(body, t.name...)
		if t.disp != 0 {
			pushConst(t.disp)
			body = append(body, 0x01)
		}
	}
	first := true
	for _, t := range pos {
		pushTerm(t)
		if !first {
			body = append(body, 0x01)
		}
		first = false
	}
	if first { // no positive label terms: start from the constant
		pushConst(c)
		c = 0
		first = false
	}
	for _, t := range neg {
		pushTerm(t)
		body = append(body, 0x02)
	}
	if c != 0 {
		pushConst(c)
		body = append(body, 0x01)
	}
	body = append(body, recEnd)
	e.recs = append(e.recs, recExpr, byte(size))
	e.recs = append(e.recs, body...)
}

func (e *segEmitter) end() []byte {
	e.flush()
	return append(e.recs, recEnd)
}

// resolve substitutes forward symbols and cancels terms; the result must be
// a plain constant or a single positive term. ENTRY/IMPORT symbols stay
// symbolic unless forceAll is set (branch displacement resolution).
func (st *asmState) resolve(v Val) (Val, error)    { return st.resolveMode(v, false) }
func (st *asmState) resolveAll(v Val) (Val, error) { return st.resolveMode(v, true) }
func (st *asmState) resolveMode(v Val, forceAll bool) (Val, error) {
	pending := func() bool {
		if forceAll {
			return v.hasFwd()
		}
		return v.hasUnresolvedFwd(st)
	}
	for guard := 0; pending(); guard++ {
		if guard > 64 {
			return Val{}, fmt.Errorf("unresolvable expression (symbol cycle)")
		}
		next := num(v.C)
		var err error
		expandTerm := func(t term, neg bool) {
			var tv Val
			if t.fwd != "" {
				if !forceAll && st.imports[t.fwd] {
					if neg {
						next, _ = next.sub(Val{Pos: []term{t}})
					} else {
						next, _ = next.add(Val{Pos: []term{t}})
					}
					return
				}
				r, ok := st.nextDef(t.fwd, t.scope, t.atSeq)
				if !ok {
					// unresolvable (e.g. branch to an external): hard error,
					// never loop
					err = fmt.Errorf("undefined ID: %s", t.fwd)
					return
				}
				if r.hasFwd() {
					err = fmt.Errorf("undefined ID (unresolvable): %s", t.fwd)
					return
				}
				if len(r.Pos) == 1 && len(r.Neg) == 0 {
					r.Pos = append([]term(nil), r.Pos...)
					if r.Pos[0].name == "" {
						r.Pos[0].name = t.fwd
						r.Pos[0].symOff = r.C
					}
					r.Pos[0].viaFwd = true
				}
				tv = r
			} else {
				tv = Val{Pos: []term{t}}
			}
			if neg {
				next, _ = next.sub(tv)
			} else {
				next, _ = next.add(tv)
			}
		}
		for _, t := range v.Pos {
			expandTerm(t, false)
		}
		for _, t := range v.Neg {
			expandTerm(t, true)
		}
		if err != nil {
			return Val{}, err
		}
		v = next
	}
	return v.cancel(), nil
}

// termRefs maps resolved terms to the operands an expression record uses,
// and returns how much of the value the operands already account for. The
// caller subtracts that from the expression's constant to get the residual
// literal addend.
func (st *asmState) termRefs(ts []term) ([]termRef, int64) {
	var out []termRef
	var covered int64
	for _, t := range ts {
		n, d := st.exprRef(t, t.symOff, -1) // -1: never the "current" segment
		out = append(out, termRef{name: n, disp: d})
		covered += t.symOff
	}
	return out, covered
}

// nextDef returns the first definition of name made after seq (a one-pass
// forward reference binds to the next definition, not the last). The
// reference's own segment scope is searched before the file-wide one.
func (st *asmState) nextDef(name, scope string, seq int64) (Val, bool) {
	for _, key := range [2]string{scope + name, name} {
		defs := st.symSeq[key]
		if len(defs) == 0 {
			continue
		}
		for _, d := range defs {
			if d.defSeq > seq {
				return d, true
			}
		}
		return defs[len(defs)-1], true
	}
	v, ok := st.syms[name]
	return v, ok
}

// exprRef gives the label name and displacement for an expression record
// (oracle-verified one-pass rules):
//   - external (IMPORT) symbols: by name
//   - cross-segment references: by the symbol's own name (it must be an ENTRY)
//   - same-segment forward references to ENTRY symbols: by name, because the
//     one-pass assembler did not yet know the symbol was local
//   - everything else (same-segment, already defined): segment name + offset
func (st *asmState) exprRef(t term, c int64, curSeg int) (string, int64) {
	if t.fwd != "" {
		return t.fwd, c
	}
	// Only ENTRY symbols can be named in an expression record; a plain
	// cross-segment label is reached through its own segment plus offset.
	if t.name != "" && st.entries[t.name] && (t.seg != curSeg || t.viaFwd) {
		return t.name, c - t.symOff
	}
	return st.segs[t.seg].name, c
}

// emitSegment runs pass 2 over a segment's actions.
func (st *asmState) emitSegment(seg *segState) (*Segment, error) {
	e := &segEmitter{}
	segIdx := -1
	for i, s := range st.segs {
		if s == seg {
			segIdx = i
			break
		}
	}
	for _, a := range seg.actions {
		switch a.kind {
		case aBytes:
			e.bytes(a.bytes)
		case aRec:
			e.flush()
			e.recs = append(e.recs, a.bytes...)
		case aDS:
			e.ds(a.count)
		case aBranch:
			t := a.target
			if a.expr != "" && t.hasFwd() {
				v, err := evalExpr(a.expr, &exprCtx{st: st, overridePC: true,
					pcOverride: a.pcAt, segOverride: a.segAt, absLabels: true})
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %v", a.file, a.line, err)
				}
				t = v
			}
			t, err := st.resolveAll(t)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", a.file, a.line, err)
			}
			var disp int64
			if t.isNum() {
				// branch to an absolute constant: relative to org-based pc
				disp = t.C - (seg.org + a.pcNext)
			} else {
				disp = t.C - a.pcNext
			}
			if a.size == 1 {
				if (disp < -128 || disp > 127) && os.Getenv("ASMIIGS_SLOPPY_BRANCH") == "" {
					return nil, fmt.Errorf("%s:%d: branch out of range (%d)", a.file, a.line, disp)
				}
				e.bytes([]byte{byte(disp)})
			} else {
				e.bytes([]byte{byte(disp), byte(disp >> 8)})
			}
		case aDefer:
			st.scopeSeg = a.segAt
			v, err := evalExpr(a.expr, &exprCtx{st: st, overridePC: true,
				pcOverride: a.pcAt, segOverride: a.segAt, absLabels: true})
			st.scopeSeg = -1
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", a.file, a.line, err)
			}
			t, err := st.resolve(v)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", a.file, a.line, err)
			}
			if t.isNum() {
				c := applyShift(t.C, a.shift)
				var b []byte
				for i := 0; i < a.size; i++ {
					b = append(b, byte(c>>(8*i)))
				}
				e.bytes(b)
				continue
			}
			if len(t.Pos)+len(t.Neg) > 1 {
				pos, gained := st.termRefs(t.Pos)
				neg, lost := st.termRefs(t.Neg)
				e.exprGeneral(a.size, pos, neg, t.C-gained+lost)
				continue
			}
			nm, disp := st.exprRef(t.Pos[0], t.C, segIdx)
			e.expr(a.rec, a.size, nm, disp, a.shift)
		case aExpr:
			t, err := st.resolve(a.target)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", a.file, a.line, err)
			}
			if t.isNum() {
				// resolved to a constant after all (e.g. forward EQU)
				c := applyShift(t.C, a.shift)
				var b []byte
				for i := 0; i < a.size; i++ {
					b = append(b, byte(c>>(8*i)))
				}
				e.bytes(b)
				continue
			}
			if len(t.Pos)+len(t.Neg) > 1 {
				pos, gained := st.termRefs(t.Pos)
				neg, lost := st.termRefs(t.Neg)
				e.exprGeneral(a.size, pos, neg, t.C-gained+lost)
				continue
			}
			nm, disp := st.exprRef(t.Pos[0], t.C, segIdx)
			e.expr(a.rec, a.size, nm, disp, a.shift)
		}
	}
	return &Segment{Name: seg.name, LoadName: seg.loadName, Org: seg.org, Kind: seg.kind,
		TempOrg: seg.tempOrg, HasTempOrg: seg.hasTempOrg,
		Length: seg.endPC, Records: e.end()}, nil
}
