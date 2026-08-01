package asm

import (
	"encoding/binary"
	"fmt"
)

// OMF record opcodes emitted by the assembler (kept local to avoid a
// dependency on the omf package).
const (
	recEnd    = 0x00
	recDS     = 0xF1
	recLconst = 0xF2
	recLexpr  = 0xF3
	recBexpr  = 0xED
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

func (e *segEmitter) end() []byte {
	e.flush()
	return append(e.recs, recEnd)
}

// resolve substitutes forward symbols and cancels terms; the result must be
// a plain constant or a single positive segment term.
func (st *asmState) resolve(v Val) (Val, error) {
	for v.hasFwd() {
		next := num(v.C)
		var err error
		expandTerm := func(t term, neg bool) {
			var tv Val
			if t.fwd != "" {
				r, ok := st.syms[t.fwd]
				if !ok {
					err = fmt.Errorf("undefined ID: %s", t.fwd)
					return
				}
				if r.hasFwd() {
					err = fmt.Errorf("undefined ID (unresolvable): %s", t.fwd)
					return
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
	v = v.cancel()
	if len(v.Neg) > 0 || len(v.Pos) > 1 {
		return Val{}, fmt.Errorf("expression does not reduce to label+constant")
	}
	return v, nil
}

// emitSegment runs pass 2 over a segment's actions.
func (st *asmState) emitSegment(seg *segState) (*Segment, error) {
	e := &segEmitter{}
	for _, a := range seg.actions {
		switch a.kind {
		case aBytes:
			e.bytes(a.bytes)
		case aDS:
			e.ds(a.count)
		case aBranch:
			t, err := st.resolve(a.target)
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
				if disp < -128 || disp > 127 {
					return nil, fmt.Errorf("%s:%d: branch out of range (%d)", a.file, a.line, disp)
				}
				e.bytes([]byte{byte(disp)})
			} else {
				e.bytes([]byte{byte(disp), byte(disp >> 8)})
			}
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
			e.expr(a.rec, a.size, st.segs[t.Pos[0].seg].name, t.C, a.shift)
		}
	}
	return &Segment{Name: seg.name, Org: seg.org, Length: seg.endPC, Records: e.end()}, nil
}
