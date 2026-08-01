// Package link reimplements the Apple MPW IIGS linker (LinkIIGS): it reads
// OMF v2 object files and produces ExpressLoad-style load files, matching
// LinkIIGS 1.2 output byte-for-byte (verified against the original under
// emulation).
package link

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/dagenbrock/iigs-tools/omf"
)

type objSeg struct {
	name string
	base int64 // offset within the merged load segment image
	seg  *omf.Segment
}

type relocPatch struct {
	size   int
	shift  int64
	offset int64
	value  int64
}

// Link links object segments (currently: one load segment named "main",
// which is what every GS/OS-era makefile default produces for single-file
// links) into a load file.
// Link produces an ExpressLoad-style load file. LinkOpts is the same with
// express=false selecting the plain form that LinkIIGS -x emits.
func Link(objs []*omf.File) ([]byte, error) { return LinkOpts(objs, true) }

func LinkOpts(objs []*omf.File, express bool) ([]byte, error) {
	// Object segments merge into load segments by their load name (the SEG
	// directive). The loader is built from two -- 'Loader' and 'Loader_LC' --
	// and becomes Loader.bin and Loader.bin.2.
	if gs := groupByLoadName(objs); len(gs) > 1 {
		return LinkGroups(gs, true)
	}
	// place object segments sequentially
	var segs []*objSeg
	byName := map[string]*objSeg{}
	globals := map[string]int64{} // ENTRY symbols -> offset in the image
	// "EXPORT name:EQU" symbols: absolute values, not image offsets
	absolutes := map[string]int64{}
	var image []byte
	var org int64
	var kind uint16 = 0x4000
	for _, f := range objs {
		for i := range f.Segments {
			s := &f.Segments[i]
			os := &objSeg{name: s.SegName, base: int64(len(image)), seg: s}
			segs = append(segs, os)
			byName[s.SegName] = os
			if len(segs) == 1 {
				org = int64(s.Org)
				kind = s.Kind
			}
			img, err := segImage(s)
			if err != nil {
				return nil, err
			}
			// Record GLOBAL (ENTRY/EXPORT) definitions at their offsets in
			// the merged image so expressions can reference them by name.
			off := os.base
			for _, r := range s.Records {
				switch {
				case r.Op >= 0x01 && r.Op <= 0xDF:
					off += int64(r.Op)
				case r.Op == omf.RecLconst, r.Op == omf.RecDS:
					off += int64(binary.LittleEndian.Uint32(r.Raw[1:]))
				case r.Op == omf.RecLexpr, r.Op == omf.RecBexpr, r.Op == omf.RecExpr,
					r.Op == omf.RecRelexpr:
					off += int64(r.Raw[1])
				case r.Op == omf.RecOrg:
					off += int64(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
				case r.Op == omf.RecGlobal:
					n := int(r.Raw[1])
					globals[string(r.Raw[2:2+n])] = off
				case r.Op == omf.RecGequ:
					// "EXPORT name:EQU" publishes a constant rather than a
					// location, so its value is absolute, not image-relative.
					n := int(r.Raw[1])
					v, _, err := evalOMFExpr(r.Raw[2+n+4:], nil, nil, nil, nil)
					if err != nil {
						return nil, fmt.Errorf("GEQU %s: %w", r.Raw[2:2+n], err)
					}
					absolutes[string(r.Raw[2:2+n])] = v
				}
			}
			image = append(image, img...)
		}
	}

	// second pass: apply expression patches
	var patches []relocPatch
	for _, os := range segs {
		pc := os.base
		for _, r := range os.seg.Records {
			switch {
			case r.Op >= 0x01 && r.Op <= 0xDF:
				pc += int64(r.Op)
			case r.Op == omf.RecLconst:
				pc += int64(binary.LittleEndian.Uint32(r.Raw[1:]))
			case r.Op == omf.RecDS:
				pc += int64(binary.LittleEndian.Uint32(r.Raw[1:]))
			case r.Op == omf.RecLexpr || r.Op == omf.RecBexpr || r.Op == omf.RecExpr:
				size := int(r.Raw[1])
				val, shift, reloc, err := evalOMFExprReloc(r.Raw[2:], byName, globals, absolutes, os)
				if err != nil {
					return nil, fmt.Errorf("segment %s: %w", os.name, err)
				}
				if org != 0 || !reloc {
					// absolute segment, or a value that does not depend on
					// the load address: patch statically
					v := val
					if reloc {
						v += org
					}
					if shift < 0 {
						v >>= uint(-shift)
					} else if shift > 0 {
						v <<= uint(shift)
					}
					putLE(image[pc:], v, size)
				} else {
					putLE(image[pc:], val, size)
					patches = append(patches, relocPatch{size: size, shift: shift, offset: pc, value: val})
				}
				pc += int64(size)
			case r.Op == omf.RecRelexpr:
				size := int(r.Raw[1])
				v, err := relBranch(r.Raw, pc, org, byName, globals, absolutes, os)
				if err != nil {
					return nil, fmt.Errorf("segment %s: %w", os.name, err)
				}
				putLE(image[pc:], v, size)
				pc += int64(size)
			case r.Op == omf.RecOrg:
				pc += int64(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
			case r.Op == omf.RecEnd || r.Op == omf.RecGlobal || r.Op == omf.RecGequ:
			default:
				return nil, fmt.Errorf("segment %s: unsupported record %s in linker", os.name, omf.RecName(r.Op))
			}
		}
	}

	if !express {
		return loadSegment(mainName, 1, image, org, kind, patches), nil
	}
	return buildLoadFile(image, org, kind, patches)
}

// segImage extracts the raw code image of an object segment (expression
// bytes left as zeros to be patched).
func segImage(s *omf.Segment) ([]byte, error) {
	// An ORG record moves the write position, so bytes are placed at a
	// cursor rather than appended: a backwards ORG overlays what is there.
	var img []byte
	pos := 0
	put := func(b []byte) {
		if need := pos + len(b); need > len(img) {
			img = append(img, make([]byte, need-len(img))...)
		}
		copy(img[pos:], b)
		pos += len(b)
	}
	for _, r := range s.Records {
		switch {
		case r.Op >= 0x01 && r.Op <= 0xDF:
			put(r.Raw[1:])
		case r.Op == omf.RecLconst:
			put(r.Raw[5:])
		case r.Op == omf.RecDS:
			// DS reserves space rather than writing: after a backwards ORG
			// the bytes it skips over must keep what is already there.
			pos += int(binary.LittleEndian.Uint32(r.Raw[1:]))
			if pos > len(img) {
				img = append(img, make([]byte, pos-len(img))...)
			}
		case r.Op == omf.RecLexpr || r.Op == omf.RecBexpr || r.Op == omf.RecExpr ||
			r.Op == omf.RecRelexpr:
			put(make([]byte, r.Raw[1]))
		case r.Op == omf.RecOrg:
			pos += int(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
			if pos < 0 {
				return nil, fmt.Errorf("segment %s: ORG before segment start", s.SegName)
			}
		case r.Op == omf.RecEnd || r.Op == omf.RecGlobal || r.Op == omf.RecGequ:
		default:
			return nil, fmt.Errorf("unsupported record %s", omf.RecName(r.Op))
		}
	}
	return img, nil
}

// relBranch resolves a RELEXPR record into the displacement stored at the
// branch site. The record's origin field says how far past the displacement
// the CPU measures from, so the result is target - (here + origin). Both are
// image-relative, so a load-address-dependent target cancels against the
// branch's own address and the site never needs a relocation record; an
// absolute target has to give the load address back before subtracting.
func relBranch(raw []byte, pc, org int64, byName map[string]*objSeg, globals, absolutes map[string]int64, cur *objSeg) (int64, error) {
	origin := int64(int32(binary.LittleEndian.Uint32(raw[2:])))
	val, shift, reloc, err := evalOMFExprReloc(raw[6:], byName, globals, absolutes, cur)
	if err != nil {
		return 0, err
	}
	if !reloc {
		val -= org
	}
	v := val - (pc + origin)
	if shift < 0 {
		v >>= uint(-shift)
	} else if shift > 0 {
		v <<= uint(shift)
	}
	return v, nil
}

// evalOMFExpr evaluates an OMF expression (label +- consts, optional final
// shift) against object-segment bases. Returns (value, shift).
//
// relocatable reports whether the result still depends on the load address:
// a difference of two labels in the same segment cancels the base and needs
// no relocation, which is how "end_of_perm_msgs-error_data" is a plain
// constant in the load file.
func evalOMFExpr(b []byte, byName map[string]*objSeg, globals, absolutes map[string]int64, cur *objSeg) (int64, int64, error) {
	v, sh, _, err := evalOMFExprReloc(b, byName, globals, absolutes, cur)
	return v, sh, err
}

func evalOMFExprReloc(b []byte, byName map[string]*objSeg, globals, absolutes map[string]int64, cur *objSeg) (int64, int64, bool, error) {
	var stack []int64
	var base []int64 // per-entry coefficient of the load address
	var shift int64
	push := func(v, c int64) { stack = append(stack, v); base = append(base, c) }
	pop2 := func() (int64, int64, int64, int64, bool) {
		if len(stack) < 2 {
			return 0, 0, 0, 0, false
		}
		x, y := stack[len(stack)-2], stack[len(stack)-1]
		cx, cy := base[len(base)-2], base[len(base)-1]
		stack, base = stack[:len(stack)-1], base[:len(base)-1]
		return x, y, cx, cy, true
	}
	set := func(v, c int64) { stack[len(stack)-1], base[len(base)-1] = v, c }
	pos := 0
	for pos < len(b) {
		tok := b[pos]
		pos++
		switch {
		case tok == 0x00:
			if len(stack) != 1 {
				return 0, 0, false, fmt.Errorf("bad expression stack depth %d", len(stack))
			}
			return stack[0], shift, base[0] != 0, nil
		case tok == 0x81 || tok == 0x80 || tok == 0x87: // numeric operand
			push(int64(int32(binary.LittleEndian.Uint32(b[pos:]))), 0)
			pos += 4
		case tok == 0x82 || tok == 0x83: // label reference
			n := int(b[pos])
			name := string(b[pos+1 : pos+1+n])
			pos += 1 + n
			if os, ok := byName[name]; ok {
				push(os.base, 1)
			} else if off, ok := globals[name]; ok {
				push(off, 1)
			} else if v, ok := absolutes[name]; ok {
				push(v, 0) // an EQU symbol is absolute, not a location
			} else {
				return 0, 0, false, fmt.Errorf("undefined label %q", name)
			}
		case tok == 0x01, tok == 0x02: // + -
			x, y, cx, cy, ok := pop2()
			if !ok {
				return 0, 0, false, fmt.Errorf("stack underflow")
			}
			if tok == 0x01 {
				set(x+y, cx+cy)
			} else {
				set(x-y, cx-cy)
			}
		case tok >= 0x03 && tok <= 0x05, tok == 0x08, tok == 0x09, tok == 0x0A:
			// multiply, divide, mod, AND, OR, EOR
			x, y, cx, cy, ok := pop2()
			if !ok {
				return 0, 0, false, fmt.Errorf("stack underflow")
			}
			c := cx | cy // still address-dependent if either side was
			switch tok {
			case 0x03:
				x *= y
			case 0x04:
				if y == 0 {
					return 0, 0, false, fmt.Errorf("division by zero")
				}
				x /= y
			case 0x05:
				if y == 0 {
					return 0, 0, false, fmt.Errorf("division by zero")
				}
				x %= y
			case 0x08:
				x &= y
			case 0x09:
				x |= y
			case 0x0A:
				x ^= y
			}
			set(x, c)
		case tok == 0x07: // shift (negative = right); operand is the count
			if len(stack) < 2 {
				return 0, 0, false, fmt.Errorf("stack underflow")
			}
			shift = stack[len(stack)-1]
			stack, base = stack[:len(stack)-1], base[:len(base)-1]
		default:
			return 0, 0, false, fmt.Errorf("unsupported expression token $%02X", tok)
		}
	}
	return 0, 0, false, fmt.Errorf("unterminated expression")
}

func putLE(b []byte, v int64, size int) {
	for i := 0; i < size; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// ---------- load-file emission ----------

const (
	mainDispName = 0x2C
	mainName     = "main"
)

// buildLoadFile emits ~ExpressLoad + the "main" load segment, matching
// LinkIIGS 1.2 byte-for-byte.
func buildLoadFile(image []byte, org int64, kind uint16, patches []relocPatch) ([]byte, error) {
	le := binary.LittleEndian

	// --- main segment header (needed for the ExpressLoad header copy) ---
	dispData := mainDispName + 10 + 1 + len(mainName) // 0x3B
	relocBytes := relocRecords(patches)
	mainRecs := len(image) + 5 + len(relocBytes) + 1 // LCONST hdr + image + relocs + END
	mainByteCnt := dispData + mainRecs

	mainHdr := make([]byte, dispData)
	le.PutUint32(mainHdr[0x00:], uint32(mainByteCnt))
	le.PutUint32(mainHdr[0x08:], uint32(len(image)))
	mainHdr[0x0E] = 4
	mainHdr[0x0F] = 2
	le.PutUint32(mainHdr[0x10:], 0x10000)
	le.PutUint16(mainHdr[0x14:], kind)
	le.PutUint32(mainHdr[0x18:], uint32(org))
	le.PutUint16(mainHdr[0x22:], 2) // SEGNUM
	le.PutUint16(mainHdr[0x28:], uint16(mainDispName))
	le.PutUint16(mainHdr[0x2A:], uint16(dispData))
	// LOADNAME = 10 zero bytes
	mainHdr[mainDispName+10] = byte(len(mainName))
	copy(mainHdr[mainDispName+11:], mainName)

	// --- ~ExpressLoad segment ---
	exName := "~ExpressLoad"
	exDispData := mainDispName + 10 + 1 + len(exName) // 0x43
	// directory(32) + header image 0x0C..0x2B (32) + loadname(10) + segname pstring
	exData := make([]byte, 32+32+10+1+len(mainName))
	le.PutUint16(exData[0x06:], 0x000A)
	le.PutUint16(exData[0x0E:], 2) // file segment number of "main"
	exByteCnt := exDispData + 5 + len(exData) + 1
	dataFileOffset := exByteCnt + dispData + 5 // start of main LCONST payload
	le.PutUint32(exData[0x10:], uint32(dataFileOffset))
	le.PutUint32(exData[0x14:], uint32(len(image)))
	if len(relocBytes) > 0 {
		le.PutUint32(exData[0x18:], uint32(dataFileOffset+len(image)))
		le.PutUint32(exData[0x1C:], uint32(len(relocBytes)))
	}
	copy(exData[0x20:], mainHdr[0x0C:0x2C]) // header copy (DISPNAME/DISPDATA zeroed below)
	// zero the DISPNAME/DISPDATA fields inside the copy except DISPNAME
	le.PutUint16(exData[0x20+(0x28-0x0C):], uint16(mainDispName))
	le.PutUint16(exData[0x20+(0x2A-0x0C):], 0)
	// LOADNAME zeros at 0x40..0x49, then segname pstring
	exData[0x4A] = byte(len(mainName))
	copy(exData[0x4B:], mainName)

	exHdr := make([]byte, exDispData)
	le.PutUint32(exHdr[0x00:], uint32(exByteCnt))
	le.PutUint32(exHdr[0x08:], uint32(len(exData)))
	exHdr[0x0E] = 4
	exHdr[0x0F] = 2
	le.PutUint16(exHdr[0x14:], 0x8001)
	le.PutUint16(exHdr[0x22:], 1)
	le.PutUint16(exHdr[0x28:], uint16(mainDispName))
	le.PutUint16(exHdr[0x2A:], uint16(exDispData))
	exHdr[mainDispName+10] = byte(len(exName))
	copy(exHdr[mainDispName+11:], exName)

	var out []byte
	out = append(out, exHdr...)
	out = append(out, 0xF2)
	var cnt [4]byte
	le.PutUint32(cnt[:], uint32(len(exData)))
	out = append(out, cnt[:]...)
	out = append(out, exData...)
	out = append(out, 0x00)

	out = append(out, mainHdr...)
	out = append(out, 0xF2)
	le.PutUint32(cnt[:], uint32(len(image)))
	out = append(out, cnt[:]...)
	out = append(out, image...)
	out = append(out, relocBytes...)
	out = append(out, 0x00)
	return out, nil
}

// relocRecords emits the patch list the way LinkIIGS 1.2 does: unshifted 2-
// and 3-byte patches are packed into SUPER RELOC2 and RELOC3 records, and
// what is left becomes a cRELOC when its offset and value both fit in two
// bytes, or a full RELOC otherwise. Width does not decide cRELOC -- a 4-byte
// patch at a low offset still compresses (oracle-verified).
func relocRecords(patches []relocPatch) []byte {
	var out []byte
	var super2, super3 []relocPatch
	for _, p := range patches {
		switch {
		case p.shift == 0 && p.size == 2:
			super2 = append(super2, p)
		case p.shift == 0 && p.size == 3:
			super3 = append(super3, p)
		case p.offset < 0x10000 && p.value < 0x10000:
			out = append(out, 0xF5, byte(p.size), byte(int8(p.shift)))
			out = append(out, byte(p.offset), byte(p.offset>>8))
			out = append(out, byte(p.value), byte(p.value>>8))
		default:
			out = append(out, 0xE2, byte(p.size), byte(int8(p.shift)))
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], uint32(p.offset))
			out = append(out, b[:]...)
			binary.LittleEndian.PutUint32(b[:], uint32(p.value))
			out = append(out, b[:]...)
		}
	}
	out = append(out, superReloc(super2, 0)...)
	return append(out, superReloc(super3, 1)...)
}

// superReloc packs unshifted patches of one width into a SUPER record. The
// body is a type byte then, per 256-byte page, the count-1 of patches in that
// page followed by their low offset bytes. A subrecord implicitly advances to
// the next page, so a $80|n byte skips n pages BEYOND that advance.
func superReloc(super []relocPatch, typ byte) []byte {
	if len(super) == 0 {
		return nil
	}
	body := []byte{typ}
	page := int64(0)
	for i := 0; i < len(super); {
		pg := super[i].offset >> 8
		for page < pg {
			skip := pg - page
			if skip > 0x7F {
				skip = 0x7F
			}
			body = append(body, byte(0x80|skip))
			page += skip
		}
		j := i
		for j < len(super) && super[j].offset>>8 == pg {
			j++
		}
		body = append(body, byte(j-i-1))
		for k := i; k < j; k++ {
			body = append(body, byte(super[k].offset&0xFF))
		}
		i = j
		page++
	}
	out := []byte{0xF7}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(len(body)))
	out = append(out, b[:]...)
	return append(out, body...)
}

// ---------- multi-segment (-lseg) linking ----------

// Group is one "-lseg NAME obj... obj(@seg)..." load segment: a name and the
// object segments that make it up, in order.
type Group struct {
	Name string
	Sels []Sel
}

// Sel selects a whole object file, or the segments carrying one load name
// when Seg is set. The "file(@name)" form the GS/OS makefiles use to split
// scm.obj across load segments names a SEG, not a PROC: "@oscall_seg" picks
// up every segment assembled under "SEG 'oscall_seg'".
type Sel struct {
	File *omf.File
	Seg  string // "" = every segment in the file
}

// LinkGroups links each group into its own load segment of one load file.
// Symbols are resolved across all groups, so a reference from one load
// segment to a label in another still finds it.
//
// apw selects the plain (APW) load-file form with no ~ExpressLoad segment.
func LinkGroups(groups []Group, apw bool) ([]byte, error) {
	_ = apw // a multi-segment file is always emitted in the plain form
	type built struct {
		name    string
		image   []byte
		org     int64
		kind    uint16
		patches []relocPatch
	}

	// First pass over every group: place segments and collect symbols. The
	// images cannot be patched yet because a later group may define a symbol
	// an earlier one references.
	globals := map[string]int64{}
	absolutes := map[string]int64{}
	byName := map[string]*objSeg{}
	var all [][]*objSeg
	var out []built
	for _, g := range groups {
		b := built{name: g.Name}
		var segs []*objSeg
		for _, sel := range g.Sels {
			for i := range sel.File.Segments {
				s := &sel.File.Segments[i]
				if sel.Seg != "" &&
					!strings.EqualFold(strings.TrimRight(s.LoadName, " "), sel.Seg) &&
					!strings.EqualFold(s.SegName, sel.Seg) {
					continue
				}
				os := &objSeg{name: s.SegName, base: int64(len(b.image)), seg: s}
				segs = append(segs, os)
				byName[s.SegName] = os
				if len(segs) == 1 {
					b.org, b.kind = int64(s.Org), s.Kind
				}
				img, err := segImage(s)
				if err != nil {
					return nil, err
				}
				if err := collectSymbols(s, os.base, globals, absolutes); err != nil {
					return nil, err
				}
				b.image = append(b.image, img...)
			}
		}
		if len(segs) == 0 {
			return nil, fmt.Errorf("load segment %q selected no object segments", g.Name)
		}
		all = append(all, segs)
		out = append(out, b)
	}

	// Second pass: patch, now that every symbol is known.
	for gi := range out {
		b := &out[gi]
		for _, os := range all[gi] {
			pc := os.base
			for _, r := range os.seg.Records {
				switch {
				case r.Op >= 0x01 && r.Op <= 0xDF:
					pc += int64(r.Op)
				case r.Op == omf.RecLconst, r.Op == omf.RecDS:
					pc += int64(binary.LittleEndian.Uint32(r.Raw[1:]))
				case r.Op == omf.RecLexpr || r.Op == omf.RecBexpr || r.Op == omf.RecExpr:
					size := int(r.Raw[1])
					val, shift, reloc, err := evalOMFExprReloc(r.Raw[2:], byName, globals, absolutes, os)
					if err != nil {
						return nil, fmt.Errorf("segment %s: %w", os.name, err)
					}
					if b.org != 0 || !reloc {
						v := val
						if reloc {
							v += b.org
						}
						if shift < 0 {
							v >>= uint(-shift)
						} else if shift > 0 {
							v <<= uint(shift)
						}
						putLE(b.image[pc:], v, size)
					} else {
						putLE(b.image[pc:], val, size)
						b.patches = append(b.patches, relocPatch{size: size, shift: shift, offset: pc, value: val})
					}
					pc += int64(size)
				case r.Op == omf.RecRelexpr:
					size := int(r.Raw[1])
					v, err := relBranch(r.Raw, pc, b.org, byName, globals, absolutes, os)
					if err != nil {
						return nil, fmt.Errorf("segment %s: %w", os.name, err)
					}
					putLE(b.image[pc:], v, size)
					pc += int64(size)
				case r.Op == omf.RecOrg:
					pc += int64(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
				case r.Op == omf.RecEnd || r.Op == omf.RecGlobal || r.Op == omf.RecGequ:
				default:
					return nil, fmt.Errorf("segment %s: unsupported record %s in linker",
						os.name, omf.RecName(r.Op))
				}
			}
		}
	}

	var file []byte
	for i := range out {
		b := &out[i]
		file = append(file, loadSegment(b.name, i+1, b.image, b.org, b.kind, b.patches)...)
	}
	return file, nil
}

// collectSymbols records a segment's GLOBAL and GEQU definitions.
func collectSymbols(s *omf.Segment, base int64, globals, absolutes map[string]int64) error {
	off := base
	for _, r := range s.Records {
		switch {
		case r.Op >= 0x01 && r.Op <= 0xDF:
			off += int64(r.Op)
		case r.Op == omf.RecLconst, r.Op == omf.RecDS:
			off += int64(binary.LittleEndian.Uint32(r.Raw[1:]))
		case r.Op == omf.RecLexpr, r.Op == omf.RecBexpr, r.Op == omf.RecExpr,
			r.Op == omf.RecRelexpr:
			off += int64(r.Raw[1])
		case r.Op == omf.RecOrg:
			off += int64(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
		case r.Op == omf.RecGlobal:
			n := int(r.Raw[1])
			globals[string(r.Raw[2:2+n])] = off
		case r.Op == omf.RecGequ:
			n := int(r.Raw[1])
			v, _, err := evalOMFExpr(r.Raw[2+n+4:], nil, nil, nil, nil)
			if err != nil {
				return fmt.Errorf("GEQU %s: %w", r.Raw[2:2+n], err)
			}
			absolutes[string(r.Raw[2:2+n])] = v
		}
	}
	return nil
}

// loadSegment emits one load-file segment carrying image plus its relocations.
func loadSegment(name string, segNum int, image []byte, org int64, kind uint16, patches []relocPatch) []byte {
	le := binary.LittleEndian
	dispData := mainDispName + 10 + 1 + len(name)
	relocBytes := relocRecords(patches)
	byteCnt := dispData + len(image) + 5 + len(relocBytes) + 1

	hdr := make([]byte, dispData)
	le.PutUint32(hdr[0x00:], uint32(byteCnt))
	le.PutUint32(hdr[0x08:], uint32(len(image)))
	hdr[0x0E] = 4
	hdr[0x0F] = 2
	le.PutUint32(hdr[0x10:], 0x10000)
	le.PutUint16(hdr[0x14:], kind)
	le.PutUint32(hdr[0x18:], uint32(org))
	le.PutUint16(hdr[0x22:], uint16(segNum))
	le.PutUint16(hdr[0x28:], uint16(mainDispName))
	le.PutUint16(hdr[0x2A:], uint16(dispData))
	hdr[mainDispName+10] = byte(len(name))
	copy(hdr[mainDispName+11:], name)

	out := append([]byte(nil), hdr...)
	out = append(out, 0xF2)
	var cnt [4]byte
	le.PutUint32(cnt[:], uint32(len(image)))
	out = append(out, cnt[:]...)
	out = append(out, image...)
	out = append(out, relocBytes...)
	return append(out, 0x00)
}

// groupByLoadName splits objects into one group per distinct load name, in
// the order the names first appear.
func groupByLoadName(objs []*omf.File) []Group {
	var order []string
	seen := map[string]bool{}
	for _, f := range objs {
		for i := range f.Segments {
			n := strings.TrimRight(f.Segments[i].LoadName, " ")
			if !seen[n] {
				seen[n] = true
				order = append(order, n)
			}
		}
	}
	if len(order) <= 1 {
		return nil
	}
	var gs []Group
	for _, n := range order {
		g := Group{Name: n}
		for _, f := range objs {
			g.Sels = append(g.Sels, Sel{File: f, Seg: n})
		}
		gs = append(gs, g)
	}
	return gs
}
