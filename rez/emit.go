package rez

import (
	"fmt"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// Resource attribute bits, recovered by diffing the original RezIIGS's index
// against the declarations in sys.resources.r:
//
//	(none)                                -> $0000
//	nospecialmemory+preload               -> $0048
//	fixed+locked+nospecialmemory+preload  -> $C048
//	convert+locked                        -> $8800
//
// which solves to locked $8000, fixed $4000, convert $0800, preload $0040,
// nospecialmemory $0008. Note Convert is NOT purely a compile-time
// instruction: the bit is stored in the index, telling the Resource Manager
// the resource was converted from a load file.
const (
	attrLocked      uint16 = 0x8000
	attrFixed       uint16 = 0x4000
	attrConvert     uint16 = 0x0800
	attrPreload     uint16 = 0x0040
	attrNoSpecial   uint16 = 0x0008
	attrNoCrossBank uint16 = 0x0004
	attrAbsolute    uint16 = 0x0002
	attrPurgeable   uint16 = 0x0300
)

func resAttr(name string) (uint16, bool) {
	switch strings.ToLower(name) {
	case "locked":
		return attrLocked, true
	case "unlocked":
		return 0, true
	case "fixed":
		return attrFixed, true
	case "convert", "converted":
		return attrConvert, true
	case "preload":
		return attrPreload, true
	case "nospecialmemory":
		return attrNoSpecial, true
	case "nocrossbank":
		return attrNoCrossBank, true
	case "absolute":
		return attrAbsolute, true
	case "purgeable":
		return attrPurgeable, true
	case "nonpurgeable", "unprotected", "crossbank", "specialmemory", "nopreload":
		return 0, true
	}
	return 0, false
}

var macRomanEnc = charmap.Macintosh.NewEncoder()

// macRomanBytes gives a string token's bytes in MacRoman, which is what the
// original tool wrote: sys.resources.r's messages contain curly quotes and
// guillemets, and our working copy of the source is UTF-8.
func macRomanBytes(t token) []byte {
	if t.kind == tHexString {
		return t.raw
	}
	return macRomanString(t.text)
}

func macRomanString(s string) []byte {
	if b, err := macRomanEnc.Bytes([]byte(s)); err == nil {
		return b
	}
	return []byte(s)
}

// emitter walks a template against the data tokens, accumulating bytes.
type emitter struct {
	c   *Compiler
	p   *parser
	buf []byte

	bitPos int // bits consumed in the final byte of buf (0 = byte aligned)

	labels map[string]int   // label -> BIT offset within buf
	counts map[string]int64 // array name -> element count
	consts map[string]int64 // named constants in scope for the current field

	// A resource body is emitted twice. Labels are freely used before they
	// are defined -- rIcon sizes its image as "(Mask-Image)/8 - 6", naming a
	// label three fields further down -- so the first pass resolves unknown
	// labels to zero just to discover where they land, and the second pass
	// emits for real with them all in scope.
	pass1 bool
}

func (e *emitter) flush() []byte {
	e.alignByte()
	return e.buf
}

func (e *emitter) alignByte() {
	e.bitPos = 0
}

// bitOffset is the current position in bits. Rez measures labels in bits --
// rIcon's "integer = (Mask-Image)/8 - 6" divides by eight to get bytes and
// then subtracts its three header words -- so that is what a label records.
func (e *emitter) bitOffset() int {
	if e.bitPos == 0 {
		return len(e.buf) * 8
	}
	return (len(e.buf)-1)*8 + e.bitPos
}

// putBits appends an integer of n bits, big-endian within the byte stream
// for sub-byte widths and little-endian for whole 8/16/32-bit fields (the
// 65816 order the toolbox reads).
func (e *emitter) putBits(v int64, n int) {
	if e.bitPos == 0 && n%8 == 0 {
		for i := 0; i < n/8; i++ {
			e.buf = append(e.buf, byte(v>>(8*i)))
		}
		return
	}
	// bit-level packing (bitstring[n], bit, boolean): MSB first
	for i := n - 1; i >= 0; i-- {
		bit := byte((v >> uint(i)) & 1)
		if e.bitPos == 0 {
			e.buf = append(e.buf, 0)
		}
		e.buf[len(e.buf)-1] |= bit << uint(7-e.bitPos)
		e.bitPos = (e.bitPos + 1) % 8
	}
}

func (e *emitter) putBytes(b []byte) {
	e.alignByte()
	e.buf = append(e.buf, b...)
}

// fields consumes the data for a list of template fields.
func (e *emitter) fields(fs []field) error {
	if e.labels == nil {
		e.labels = map[string]int{}
	}
	if e.counts == nil {
		e.counts = map[string]int64{}
	}
	for i := range fs {
		if err := e.field(&fs[i]); err != nil {
			return err
		}
		// data items are comma separated; a trailing comma before '}' is fine
		e.p.accept(",")
	}
	return nil
}

// dataEnd reports whether the current data group has run out of items. Data
// items are comma separated, so a semicolon terminates the whole body.
func (e *emitter) dataEnd() bool {
	t := e.p.peek()
	return t.kind == tEOF || t.is("}") || t.is(";")
}

func (e *emitter) field(f *field) error {
	if f.label != "" {
		e.labels[strings.ToLower(f.label)] = e.bitOffset()
	}
	e.consts = f.named

	switch f.kind {
	case fLabel:
		return nil

	case fGroup:
		start := len(e.buf)
		// a group's data may or may not be brace-wrapped
		braced := e.p.accept("{")
		if f.optional {
			// An "optional Fields { ... }" group stops as soon as the data
			// runs out; rControlTemplate sizes its pCount from how many were
			// supplied, via "integer = 3+$$optionalcount(Fields)". That count
			// is read before the group is reached, which is what the first
			// emission pass is for.
			n := int64(0)
			for i := range f.sub {
				if e.dataEnd() {
					break
				}
				if err := e.field(&f.sub[i]); err != nil {
					return err
				}
				e.p.accept(",")
				n++
			}
			e.counts[strings.ToLower(f.arrayName)] = n
		} else if err := e.fields(f.sub); err != nil {
			return err
		}
		if braced {
			if _, err := e.p.expect("}"); err != nil {
				return err
			}
		}
		if f.reverse {
			rev := e.buf[start:]
			for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
				rev[i], rev[j] = rev[j], rev[i]
			}
		}
		return nil

	case fFill:
		n := int64(1)
		if len(f.size) > 0 {
			v, err := e.eval(f.size)
			if err != nil {
				return err
			}
			n = v
		}
		e.alignByte()
		for i := int64(0); i < n*int64(f.bits)/8; i++ {
			e.buf = append(e.buf, 0)
		}
		return nil

	case fAlign:
		e.alignByte()
		w := f.bits / 8
		if w > 0 {
			for len(e.buf)%w != 0 {
				e.buf = append(e.buf, 0)
			}
		}
		return nil

	case fArray:
		n := int64(0)
		// a fixed-count array repeats exactly that many times
		want := int64(-1)
		if len(f.size) > 0 {
			v, err := e.eval(f.size)
			if err != nil {
				return err
			}
			want = v
		}
		braced := e.p.accept("{")
		for {
			if want >= 0 && n >= want {
				break
			}
			if braced && e.p.peek().is("}") {
				break
			}
			if !braced && e.dataEnd() {
				break
			}
			if e.p.accept(",") {
				continue
			}
			if err := e.fields(f.sub); err != nil {
				return err
			}
			n++
			if !e.p.accept(",") {
				if braced && e.p.peek().is("}") {
					break
				}
				if !braced {
					break
				}
			}
		}
		if braced {
			if _, err := e.p.expect("}"); err != nil {
				return err
			}
		}
		if f.arrayName != "" {
			e.counts[strings.ToLower(f.arrayName)] = n
		}
		return nil

	case fRect, fPoint:
		// "{ 6, 92, 46, 405 }" -- the braces are optional in Rez, and the
		// closing one has to be consumed here or it looks like the end of the
		// enclosing body.
		n := 4
		if f.kind == fPoint {
			n = 2
		}
		if _, err := e.p.expect("{"); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if i > 0 {
				e.p.accept(",")
			}
			v, err := e.dataExpr()
			if err != nil {
				return err
			}
			e.putBits(v, 16)
		}
		if _, err := e.p.expect("}"); err != nil {
			return err
		}
		return nil

	case fSwitch:
		sel := e.p.next()
		if sel.kind != tIdent {
			return e.p.errf(sel, "switch selector expected, found %s", sel)
		}
		var cs *switchCase
		for i := range f.cases {
			if strings.EqualFold(f.cases[i].name, sel.text) {
				cs = &f.cases[i]
				break
			}
		}
		if cs == nil {
			return e.p.errf(sel, "no case %q in switch", sel.text)
		}
		braced := e.p.accept("{")
		if err := e.fields(cs.fields); err != nil {
			return err
		}
		if braced {
			if _, err := e.p.expect("}"); err != nil {
				return err
			}
		}
		return nil
	}

	// A "= expr" field is a literal the template supplies itself -- lengths,
	// counts, version words, switch keys -- and the source gives no operand
	// for it. Strings are the exception: there "= expr" is a default that a
	// supplied operand overrides.
	if f.def != nil && (e.dataEnd() || f.kind == fBits) {
		v, err := e.eval(f.def)
		if err != nil {
			return err
		}
		return e.scalar(f, v, nil)
	}

	return e.dataField(f)
}

// dataField consumes one data item for a scalar field.
func (e *emitter) dataField(f *field) error {
	switch f.kind {
	case fPString, fCString, fWString, fString, fHexString, fChar:
		var raw []byte
		// adjacent string literals concatenate; note an empty one still
		// counts, so track that separately from the byte slice being nil
		got := false
		for {
			t := e.p.peek()
			if t.kind != tString && t.kind != tHexString {
				break
			}
			e.p.next()
			raw = append(raw, macRomanBytes(t)...)
			got = true
		}
		if !got {
			if e.dataEnd() {
				break
			}
			// a numeric operand for a char field
			v, err := e.dataExpr()
			if err != nil {
				return err
			}
			raw = []byte{byte(v)}
		}
		return e.stringField(f, raw)
	}

	if e.dataEnd() {
		if f.def != nil {
			v, err := e.eval(f.def)
			if err != nil {
				return err
			}
			return e.scalar(f, v, nil)
		}
		return e.p.errf(e.p.peek(), "missing data for field, found %s", e.p.peek())
	}
	v, err := e.dataExpr()
	if err != nil {
		return err
	}
	return e.scalar(f, v, nil)
}

func (e *emitter) stringField(f *field, raw []byte) error {
	switch f.kind {
	case fPString:
		n := len(raw)
		if n > 255 {
			return fmt.Errorf("pstring longer than 255 bytes")
		}
		e.alignByte()
		e.buf = append(e.buf, byte(n))
		e.buf = append(e.buf, raw...)
	case fCString:
		e.putBytes(append(append([]byte(nil), raw...), 0))
	case fWString:
		e.alignByte()
		e.buf = append(e.buf, byte(len(raw)), byte(len(raw)>>8))
		e.buf = append(e.buf, raw...)
	case fString, fHexString:
		e.putBytes(raw)
	case fChar:
		// a char is one byte wide whatever the operand: rMenuItem's key
		// equivalents are written as "" when there is no key
		var b byte
		if len(raw) > 0 {
			b = raw[0]
		}
		e.alignByte()
		e.buf = append(e.buf, b)
		return nil
	}
	// A fixed size pads to that many characters (the size counts characters,
	// not any length prefix). Scouting passes skip this: the size can name a
	// label that has not been placed yet -- rIcon's image is sized by reading
	// back a word computed from the mask's offset -- and padding only ever
	// grows, so a bad first guess would be a fixed point the real length
	// could never come back from.
	if len(f.size) > 0 && !e.pass1 {
		want, err := e.eval(f.size)
		if err != nil {
			return err
		}
		if int64(len(raw)) > want {
			return fmt.Errorf("%d bytes of data in a field declared %d wide",
				len(raw), want)
		}
		for have := int64(len(raw)); have < want; have++ {
			e.buf = append(e.buf, 0)
		}
	}
	return nil
}

func (e *emitter) scalar(f *field, v int64, _ []byte) error {
	switch f.kind {
	case fBits, fBoolean:
		e.putBits(v, f.bits)
	default:
		return fmt.Errorf("cannot emit field kind %d as a scalar", f.kind)
	}
	return nil
}

// dataExpr evaluates one comma-delimited data expression.
func (e *emitter) dataExpr() (int64, error) {
	toks, err := e.p.exprTokens()
	if err != nil {
		return 0, err
	}
	if len(toks) == 0 {
		t := e.p.peek()
		return 0, e.p.errf(t, "data value expected, found %s", t)
	}
	return e.eval(toks)
}

// eval evaluates a template or data expression in the emitter's context, so
// $$Word(label)/$$Countof(array) and field-local named constants resolve.
func (e *emitter) eval(ts []token) (int64, error) {
	ev := &constEval{c: e.c, toks: ts, em: e}
	v, err := ev.expr(0)
	if err != nil {
		return 0, err
	}
	if ev.pos < len(ev.toks) {
		return 0, fmt.Errorf("trailing %s in expression", ev.toks[ev.pos])
	}
	return v, nil
}
