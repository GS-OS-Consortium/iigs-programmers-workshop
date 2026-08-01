// Package link reimplements the Apple MPW IIGS linker (LinkIIGS): it reads
// OMF v2 object files and produces ExpressLoad-style load files, matching
// LinkIIGS 1.2 output byte-for-byte (verified against the original under
// emulation).
package link

import (
	"encoding/binary"
	"fmt"

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
func Link(objs []*omf.File) ([]byte, error) {
	// place object segments sequentially
	var segs []*objSeg
	byName := map[string]*objSeg{}
	globals := map[string]int64{} // ENTRY symbols -> offset in the image
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
				val, shift, err := evalOMFExpr(r.Raw[2:], byName, globals, os)
				if err != nil {
					return nil, fmt.Errorf("segment %s: %w", os.name, err)
				}
				if org != 0 {
					// absolute segment: patch statically
					v := org + val
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
			case r.Op == omf.RecEnd || r.Op == omf.RecGlobal:
			default:
				return nil, fmt.Errorf("segment %s: unsupported record %s in linker", os.name, omf.RecName(r.Op))
			}
		}
	}

	return buildLoadFile(image, org, kind, patches)
}

// segImage extracts the raw code image of an object segment (expression
// bytes left as zeros to be patched).
func segImage(s *omf.Segment) ([]byte, error) {
	var img []byte
	for _, r := range s.Records {
		switch {
		case r.Op >= 0x01 && r.Op <= 0xDF:
			img = append(img, r.Raw[1:]...)
		case r.Op == omf.RecLconst:
			img = append(img, r.Raw[5:]...)
		case r.Op == omf.RecDS:
			img = append(img, make([]byte, binary.LittleEndian.Uint32(r.Raw[1:]))...)
		case r.Op == omf.RecLexpr || r.Op == omf.RecBexpr || r.Op == omf.RecExpr:
			img = append(img, make([]byte, r.Raw[1])...)
		case r.Op == omf.RecEnd || r.Op == omf.RecGlobal:
		default:
			return nil, fmt.Errorf("unsupported record %s", omf.RecName(r.Op))
		}
	}
	return img, nil
}

// evalOMFExpr evaluates an OMF expression (label +- consts, optional final
// shift) against object-segment bases. Returns (value, shift).
func evalOMFExpr(b []byte, byName map[string]*objSeg, globals map[string]int64, cur *objSeg) (int64, int64, error) {
	var stack []int64
	var shift int64
	pos := 0
	for pos < len(b) {
		tok := b[pos]
		pos++
		switch {
		case tok == 0x00:
			if len(stack) != 1 {
				return 0, 0, fmt.Errorf("bad expression stack depth %d", len(stack))
			}
			return stack[0], shift, nil
		case tok == 0x81 || tok == 0x80 || tok == 0x87: // numeric operand
			v := int64(int32(binary.LittleEndian.Uint32(b[pos:])))
			pos += 4
			stack = append(stack, v)
		case tok == 0x82 || tok == 0x83: // label reference
			n := int(b[pos])
			name := string(b[pos+1 : pos+1+n])
			pos += 1 + n
			if os, ok := byName[name]; ok {
				stack = append(stack, os.base)
			} else if off, ok := globals[name]; ok {
				stack = append(stack, off)
			} else {
				return 0, 0, fmt.Errorf("undefined label %q", name)
			}
		case tok == 0x01: // +
			if len(stack) < 2 {
				return 0, 0, fmt.Errorf("stack underflow")
			}
			stack[len(stack)-2] += stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		case tok == 0x02: // -
			if len(stack) < 2 {
				return 0, 0, fmt.Errorf("stack underflow")
			}
			stack[len(stack)-2] -= stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		case tok == 0x07: // shift (negative = right); operand is shift count
			if len(stack) < 2 {
				return 0, 0, fmt.Errorf("stack underflow")
			}
			shift = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		default:
			return 0, 0, fmt.Errorf("unsupported expression token $%02X", tok)
		}
	}
	return 0, 0, fmt.Errorf("unterminated expression")
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

// relocRecords emits shifted patches as cRELOC records followed by one SUPER
// RELOC2 record for plain 2-byte patches (LinkIIGS 1.2 order).
func relocRecords(patches []relocPatch) []byte {
	var out []byte
	var super []relocPatch
	for _, p := range patches {
		if p.shift == 0 && p.size == 2 {
			super = append(super, p)
			continue
		}
		if p.size == 2 && p.offset < 0x10000 && p.value < 0x10000 {
			out = append(out, 0xF5, byte(p.size), byte(int8(p.shift)))
			out = append(out, byte(p.offset), byte(p.offset>>8))
			out = append(out, byte(p.value), byte(p.value>>8))
		} else {
			out = append(out, 0xE2, byte(p.size), byte(int8(p.shift)))
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], uint32(p.offset))
			out = append(out, b[:]...)
			binary.LittleEndian.PutUint32(b[:], uint32(p.value))
			out = append(out, b[:]...)
		}
	}
	if len(super) > 0 {
		// SUPER RELOC2: per-256-byte-page subrecords: count-1 then offsets
		var body []byte
		body = append(body, 0x00) // type RELOC2
		page := int64(0)
		var pageOffsets []byte
		flushPage := func() {
			if len(pageOffsets) > 0 {
				body = append(body, byte(len(pageOffsets)-1))
				body = append(body, pageOffsets...)
				pageOffsets = nil
			}
		}
		for _, p := range super {
			pg := p.offset >> 8
			for page < pg {
				flushPage()
				// skip to next page: SUPER uses $80|skipcount to skip pages
				skip := pg - page
				if skip > 0x7F {
					skip = 0x7F
				}
				body = append(body, byte(0x80|skip))
				page += skip
			}
			pageOffsets = append(pageOffsets, byte(p.offset&0xFF))
		}
		flushPage()
		out = append(out, 0xF7)
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(len(body)))
		out = append(out, b[:]...)
		out = append(out, body...)
	}
	return out
}
