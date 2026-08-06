// Package link reimplements the Apple MPW IIGS linker (LinkIIGS): it reads
// OMF v2 object files and produces ExpressLoad-style load files, matching
// LinkIIGS 1.2 output byte-for-byte (verified against the original under
// emulation).
package link

import (
	"encoding/binary"
	"fmt"
	"os"
	stdos "os"
	"strconv"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

type objSeg struct {
	name  string
	group int   // index of the load segment (Group) this object segment landed in
	base  int64 // offset within the merged load segment image
	// abs is this object segment's absolute run address, or 0 if it floats
	// with the load address. Two things fix an address: an absolute load
	// segment (the loader is two of them, 'Loader' at $01A5D0 and
	// 'Loader_LC' at $01CFD0 -- resolving across them against the referrer's
	// own org put every such call $2A00 out), and a TEMPORG segment, which is
	// assembled for the address it will be copied to and run at.
	abs int64
	seg *omf.Segment
	// fileSegs maps segment names to segments of the SAME object file. A
	// label reference resolves there first: the four ATALK objects each
	// carry a DISP_TABLE whose LEXPRs name their OWN startup/open/read
	// segments, and a flat last-wins map pointed rpm's table at others'.
	// fileGlobals/fileAbs are the same-file GLOBAL and GEQU symbols: three
	// of the ATALK objects publish a SUP_NUM, and each one's code reads its
	// own.
	fileSegs    map[string]*objSeg
	fileGlobals map[string]gsym
	fileAbs     map[string]int64
}

// gsym is a relocatable published symbol: an offset within the image of one
// load segment (group).
type gsym struct {
	val   int64
	group int
}

type relocPatch struct {
	size   int
	shift  int64
	offset int64
	value  int64
	// interseg patches reference another load segment of the same file: the
	// reference from Tool015's MainTool through the ~JumpTable to its dynamic
	// PopUpProc segment is "segment 3, offset $12" rather than a value.
	interseg bool
	seg      int
	segoff   int64
}

// flatSym is one entry of the linker's cross-file symbol table. Only PUBLIC
// symbols enter it -- EXPORTed globals and GEQUs (private byte 0) and
// non-private segments (KIND bit $4000 clear) -- and a later registration
// replaces an earlier one whatever its kind (oracle-probed with colliding
// exported PROCs and EXPORT labels; Tool014's "shutdown" has a private PROC,
// an ENTRY, and an EXPORT, and every cross-file reference takes the EXPORT).
// Private segments and ENTRY symbols are visible only through the
// referencing file's own fileSegs/fileGlobals tier -- the oracle resolves a
// cross-file reference with only private definitions to ZERO with a
// "Missing symbol" warning.
type flatSym struct {
	val    int64
	isBase bool // image offset (load-address dependent) vs absolute value
	group  int  // owning load segment when isBase
}

// globalPrivate reads the private byte of a GLOBAL/GEQU record
// ([op][len][name][length:2][type:1][private:1]...).
func globalPrivate(raw []byte) byte {
	n := int(raw[1])
	return raw[2+n+3]
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
		return LinkGroups(gs, express)
	}
	// place object segments sequentially
	var segs []*objSeg
	byName := map[string]*objSeg{}
	globals := map[string]gsym{} // ENTRY symbols -> offset in the image
	// "EXPORT name:EQU" symbols: absolute values, not image offsets
	absolutes := map[string]int64{}
	flat := map[string]flatSym{}
	var image []byte
	var org int64
	var kind uint16 = 0x4000
	var banksize uint32
	var align int64 // load segment ALIGN = max member alignment
	// Per-file symbol scopes; a library pull carries per-MEMBER scopes (a
	// member's private ~arrays/~string0 must not shadow another's), so the
	// key is (file, LibMember).
	type fileTier struct {
		segs    map[string]*objSeg
		globals map[string]gsym
		abs     map[string]int64
	}
	tiers := map[int]*fileTier{}
	for fi, f := range objs {
		for i := range f.Segments {
			s := &f.Segments[i]
			tk := fi<<16 | s.LibMember
			tier := tiers[tk]
			if tier == nil {
				tier = &fileTier{segs: map[string]*objSeg{},
					globals: map[string]gsym{}, abs: map[string]int64{}}
				tiers[tk] = tier
			}
			fileSegs, fileGlobals, fileAbs := tier.segs, tier.globals, tier.abs
			// A TEMPORG segment is assembled for the address it will be
			// copied to and run at, so references into it are absolute and
			// need no relocation record. AD3.5's read1to1 is built for
			// $01BC00 and moved there before use; relocating its nibble
			// reader at load time left it spinning on the data register.
			// an ALIGNed object segment is padded out to its boundary
			// (AppleDisk5.25 page-aligns its IWM code with "PROC ALIGN 256")
			if a := int64(s.Align); a > 0 {
				if int64(len(image))%a != 0 {
					image = append(image, make([]byte, a-int64(len(image))%a)...)
				}
				if a > align {
					align = a
				}
			}
			os := &objSeg{name: s.SegName, base: int64(len(image)),
				abs: int64(s.TempOrg), seg: s, fileSegs: fileSegs,
				fileGlobals: fileGlobals, fileAbs: fileAbs}
			segs = append(segs, os)
			byName[s.SegName] = os
			fileSegs[s.SegName] = os
			if s.Kind&0x4000 == 0 {
				if os.abs != 0 {
					flat[s.SegName] = flatSym{os.abs, false, 0}
				} else {
					flat[s.SegName] = flatSym{os.base, true, 0}
				}
			}
			if len(segs) == 1 {
				org = int64(s.Org)
				kind = s.Kind
			}
			// the load segment's BANKSIZE is the largest any member asks
			// for (oracle: DOS3.3.FST's DS-only members carry 0, its code
			// $10000, and the load segment takes $10000; GSCalc's ~arrays
			// members are all 0 and the load segment stays 0)
			if s.BankSize > banksize {
				banksize = s.BankSize
			}
			img, err := segImage(s)
			if err != nil {
				return nil, err
			}
			// Record GLOBAL (ENTRY/EXPORT) definitions at their offsets in
			// the merged image so expressions can reference them by name.
			// A TEMPORG segment's symbols are fixed addresses instead.
			off := os.base
			isAbs := os.abs != 0
			if isAbs {
				off = os.abs
			}
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
					name := string(r.Raw[2 : 2+n])
					if isAbs {
						absolutes[name] = off
					} else {
						globals[name] = gsym{off, 0}
					}
					if globalPrivate(r.Raw) == 0 {
						flat[name] = flatSym{off, !isAbs, 0}
					}
					if !isAbs {
						fileGlobals[name] = gsym{off, 0}
					} else {
						fileAbs[name] = off
					}
				case r.Op == omf.RecGequ:
					// "EXPORT name:EQU" publishes a constant rather than a
					// location, so its value is absolute, not image-relative
					// -- except PascalIIGS's segment-relative GEQUs (see
					// gequSelfRef), which behave like GLOBALs.
					n := int(r.Raw[1])
					name := string(r.Raw[2 : 2+n])
					if disp, ok := gequSelfRef(r.Raw[2+n+4:], s.SegName); ok && !isAbs {
						globals[name] = gsym{os.base + disp, 0}
						fileGlobals[name] = gsym{os.base + disp, 0}
						if globalPrivate(r.Raw) == 0 {
							flat[name] = flatSym{os.base + disp, true, 0}
						}
						continue
					}
					v, _, err := evalOMFExpr(r.Raw[2+n+4:], nil, nil, nil, nil, nil)
					if err != nil {
						return nil, fmt.Errorf("GEQU %s: %w", name, err)
					}
					absolutes[name] = v
					fileAbs[name] = v
					if globalPrivate(r.Raw) == 0 {
						flat[name] = flatSym{v, false, 0}
					}
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
				val, shift, reloc, _, err := evalOMFExprReloc(r.Raw[2:], byName, globals, absolutes, flat, os)
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
				} else if kind&0x0100 != 0 && size == 2 && shift == 0 {
					// a BANK-RELATIVE segment ($0100) is loaded on a bank
					// boundary, so a 2-byte in-segment reference IS the
					// target's offset: resolved absolutely, no relocation
					// record (oracle-verified: the Finder's -lseg:$1100)
					putLE(image[pc:], val, size)
				} else {
					putLE(image[pc:], val, size)
					patches = append(patches, relocPatch{size: size, shift: shift, offset: pc, value: val})
				}
				pc += int64(size)
			case r.Op == omf.RecRelexpr:
				size := int(r.Raw[1])
				v, err := relBranch(r.Raw, pc, org, byName, globals, absolutes, flat, os)
				if err != nil {
					return nil, fmt.Errorf("segment %s: %w", os.name, err)
				}
				putLE(image[pc:], v, size)
				pc += int64(size)
			case r.Op == omf.RecOrg:
				pc += int64(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
			case r.Op == omf.RecEnd || r.Op == omf.RecGlobal || r.Op == omf.RecGequ,
				r.Op == omf.RecStrong, r.Op == omf.RecUsing:
			default:
				return nil, fmt.Errorf("segment %s: unsupported record %s in linker", os.name, omf.RecName(r.Op))
			}
		}
	}

	if !express {
		return loadSegment(mainName, 1, image, org, kind, banksize, align, patches), nil
	}
	return buildLoadFile(image, org, kind, banksize, align, patches)
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
		case r.Op == omf.RecEnd || r.Op == omf.RecGlobal || r.Op == omf.RecGequ,
			r.Op == omf.RecStrong, r.Op == omf.RecUsing:
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
func relBranch(raw []byte, pc, org int64, byName map[string]*objSeg, globals map[string]gsym, absolutes map[string]int64, flat map[string]flatSym, cur *objSeg) (int64, error) {
	origin := int64(int32(binary.LittleEndian.Uint32(raw[2:])))
	val, shift, reloc, _, err := evalOMFExprReloc(raw[6:], byName, globals, absolutes, flat, cur)
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
func evalOMFExpr(b []byte, byName map[string]*objSeg, globals map[string]gsym, absolutes map[string]int64, flat map[string]flatSym, cur *objSeg) (int64, int64, error) {
	v, sh, _, _, err := evalOMFExprReloc(b, byName, globals, absolutes, flat, cur)
	return v, sh, err
}

// evalOMFExprReloc also reports the load segment (group index) the
// relocatable result is an offset into, so a multi-segment link can turn a
// cross-segment reference into an interseg relocation.
func evalOMFExprReloc(b []byte, byName map[string]*objSeg, globals map[string]gsym, absolutes map[string]int64, flat map[string]flatSym, cur *objSeg) (int64, int64, bool, int, error) {
	var stack []int64
	var base []int64 // per-entry coefficient of the load address
	var grp []int    // per-entry owning group of the relocatable part
	var shift int64
	push := func(v, c int64, g int) { stack = append(stack, v); base = append(base, c); grp = append(grp, g) }
	pop2 := func() (int64, int64, int64, int64, int, int, bool) {
		if len(stack) < 2 {
			return 0, 0, 0, 0, 0, 0, false
		}
		x, y := stack[len(stack)-2], stack[len(stack)-1]
		cx, cy := base[len(base)-2], base[len(base)-1]
		gx, gy := grp[len(grp)-2], grp[len(grp)-1]
		stack, base, grp = stack[:len(stack)-1], base[:len(base)-1], grp[:len(grp)-1]
		return x, y, cx, cy, gx, gy, true
	}
	set := func(v, c int64, g int) { stack[len(stack)-1], base[len(base)-1], grp[len(grp)-1] = v, c, g }
	// the group of a combined term: whichever side still depends on a load
	// address wins; a cancelled result carries no group
	combine := func(cx, cy int64, gx, gy int) int {
		if cx != 0 {
			return gx
		}
		if cy != 0 {
			return gy
		}
		return -1
	}
	pos := 0
	for pos < len(b) {
		tok := b[pos]
		pos++
		switch {
		case tok == 0x00:
			if len(stack) != 1 {
				return 0, 0, false, -1, fmt.Errorf("bad expression stack depth %d", len(stack))
			}
			return stack[0], shift, base[0] != 0, grp[0], nil
		case tok == 0x81 || tok == 0x80 || tok == 0x87: // numeric operand
			push(int64(int32(binary.LittleEndian.Uint32(b[pos:]))), 0, -1)
			pos += 4
		case tok == 0x82 || tok == 0x83: // label reference
			n := int(b[pos])
			name := string(b[pos+1 : pos+1+n])
			pos += 1 + n
			if os.Getenv("LINKDEBUG") == name {
				src := "?"
				if cur != nil {
					src = cur.name
				}
				_, inFileSegs := cur.fileSegs[name]
				_, inFileGlob := cur.fileGlobals[name]
				bn, inByName := byName[name]
				gv, inGlob := globals[name]
				bnb := int64(-1)
				if inByName {
					bnb = bn.base
				}
				fmt.Fprintf(os.Stderr, "LDBG ref %s from %s fileSegs=%v fileGlob=%v byName=%v(base=%x) globals=%v(%x)\n",
					name, src, inFileSegs, inFileGlob, inByName, bnb, inGlob, gv.val)
			}
			// the referencing object file's own segments and published
			// symbols win over same-named ones from other files
			if cur != nil && cur.fileSegs != nil {
				if os, ok := cur.fileSegs[name]; ok {
					if os.abs != 0 {
						push(os.abs, 0, -1)
					} else {
						push(os.base, 1, os.group)
					}
					continue
				}
				if g, ok := cur.fileGlobals[name]; ok {
					push(g.val, 1, g.group)
					continue
				}
				if v, ok := cur.fileAbs[name]; ok {
					push(v, 0, -1)
					continue
				}
			}
			// Cross-file: the flat table of PUBLIC symbols, last
			// registration winning across kinds (see flatSym). The old
			// byName/globals/absolutes chain stays as a fallback for names
			// with no public definition; the gated corpus never exercises
			// it (the original zeroes such references with a warning).
			if fs, ok := flat[name]; ok {
				if fs.isBase {
					push(fs.val, 1, fs.group)
				} else {
					push(fs.val, 0, -1)
				}
			} else if os, ok := byName[name]; ok {
				if os.abs != 0 {
					push(os.abs, 0, -1)
				} else {
					push(os.base, 1, os.group)
				}
			} else if g, ok := globals[name]; ok {
				push(g.val, 1, g.group)
			} else if v, ok := absolutes[name]; ok {
				push(v, 0, -1) // an EQU symbol is absolute, not a location
			} else {
				// the original resolves a reference with no visible
				// definition to ZERO with a "Missing symbol" warning
				// (SetStart selects PLib(@main,...) without @~arrays, and
				// atof's _0float has nowhere to point)
				fmt.Fprintf(stdos.Stderr, "linkiigs: Missing symbol %s (resolved to zero)\n", name)
				push(0, 0, -1)
			}
		case tok == 0x01, tok == 0x02: // + -
			x, y, cx, cy, gx, gy, ok := pop2()
			if !ok {
				return 0, 0, false, -1, fmt.Errorf("stack underflow")
			}
			if tok == 0x01 {
				set(x+y, cx+cy, combine(cx, cy, gx, gy))
			} else {
				set(x-y, cx-cy, combine(cx, cy, gx, gy))
			}
		case tok >= 0x03 && tok <= 0x05, tok == 0x08, tok == 0x09, tok == 0x0A:
			// multiply, divide, mod, AND, OR, EOR
			x, y, cx, cy, gx, gy, ok := pop2()
			if !ok {
				return 0, 0, false, -1, fmt.Errorf("stack underflow")
			}
			c := cx | cy // still address-dependent if either side was
			switch tok {
			case 0x03:
				x *= y
			case 0x04:
				if y == 0 {
					return 0, 0, false, -1, fmt.Errorf("division by zero")
				}
				x /= y
			case 0x05:
				if y == 0 {
					return 0, 0, false, -1, fmt.Errorf("division by zero")
				}
				x %= y
			case 0x08:
				x &= y
			case 0x09:
				x |= y
			case 0x0A:
				x ^= y
			}
			set(x, c, combine(cx, cy, gx, gy))
		case tok == 0x07: // shift (negative = right); top of stack is the count
			if len(stack) < 2 {
				return 0, 0, false, -1, fmt.Errorf("stack underflow")
			}
			cnt := stack[len(stack)-1]
			stack, base, grp = stack[:len(stack)-1], base[:len(base)-1], grp[:len(grp)-1]
			if pos < len(b) && b[pos] != 0x00 {
				// mid-expression: a real binary shift, applied now. scm's
				// "(COMMON_INT_ENT<<8)+$5C" patches $255C -- deferring the
				// shift to the end computed ($9F25+$5C)<<8 instead
				// (oracle-verified).
				v := stack[len(stack)-1]
				if cnt < 0 {
					v >>= uint(-cnt)
				} else {
					v <<= uint(cnt)
				}
				stack[len(stack)-1] = v
			} else {
				// trailing shift: carried on the relocation record
				shift = cnt
			}
		default:
			return 0, 0, false, -1, fmt.Errorf("unsupported expression token $%02X", tok)
		}
	}
	return 0, 0, false, -1, fmt.Errorf("unterminated expression")
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
func buildLoadFile(image []byte, org int64, kind uint16, banksize uint32, align int64, patches []relocPatch) ([]byte, error) {
	return buildExpressFile([]exMember{{name: mainName, image: image, org: org,
		kind: kind, banksize: banksize, align: align, segNum: 2,
		relocs: relocRecords(patches)}}), nil
}

// exMember is one real load segment of an ExpressLoad file.
type exMember struct {
	name     string
	image    []byte
	org      int64
	kind     uint16
	banksize uint32
	align    int64
	segNum   int
	relocs   []byte
}

// segHeader builds a load-segment header (the DISPDATA prefix). The load
// segment's BANKSIZE is inherited from its FIRST member object segment
// (oracle-verified: GSCalc's ~arrays takes %GSCALC.arr's 0 while ~globals
// takes %GSCALC.glob's $10000); ~ExpressLoad carries 0.
func segHeader(name string, segNum, byteCnt, imageLen int, org int64, kind uint16, align int64, banksize uint32) []byte {
	le := binary.LittleEndian
	dispData := mainDispName + 10 + 1 + len(name)
	hdr := make([]byte, dispData)
	le.PutUint32(hdr[0x00:], uint32(byteCnt))
	le.PutUint32(hdr[0x08:], uint32(imageLen))
	hdr[0x0E] = 4
	hdr[0x0F] = 2
	// a DP/stack segment (type $12) carries BANKSIZE 0 whatever its members
	// say (oracle-verified against the Installer's ~direct)
	if kind&0x1F != 0x12 {
		le.PutUint32(hdr[0x10:], banksize)
	}
	le.PutUint16(hdr[0x14:], kind)
	le.PutUint32(hdr[0x18:], uint32(org))
	le.PutUint32(hdr[0x1C:], uint32(align))
	le.PutUint16(hdr[0x22:], uint16(segNum))
	le.PutUint16(hdr[0x28:], uint16(mainDispName))
	le.PutUint16(hdr[0x2A:], uint16(dispData))
	// LOADNAME = 10 zero bytes, then the segment name
	hdr[mainDispName+10] = byte(len(name))
	copy(hdr[mainDispName+11:], name)
	return hdr
}

// buildExpressFile emits a ~ExpressLoad directory segment followed by the
// member load segments. The directory layout (reverse-engineered from
// LinkIIGS 1.2 output, single- and multi-segment):
//
//	+0  long  0
//	+4  word  member count - 1
//	+6  per member, 8 bytes: [word: offset of its block, relative to THIS
//	    entry's position][3 zero words]
//	then one word per member: its file segment number
//	then per-member blocks:
//	  +0  long  file offset of the segment's LCONST payload
//	  +4  long  payload (image) length
//	  +8  long  file offset of its reloc records (0 if none)
//	  +12 long  reloc record byte length (0 if none)
//	  +16 the segment header bytes $0C..$2B, with DISPDATA zeroed
//	  +48 LOADNAME (10 zero bytes)
//	  +58 segment name p-string
func buildExpressFile(members []exMember) []byte {
	le := binary.LittleEndian
	exName := "~ExpressLoad"
	exDispData := mainDispName + 10 + 1 + len(exName)
	n := len(members)
	dispData := make([]int, n)
	byteCnt := make([]int, n)
	for i, m := range members {
		dispData[i] = mainDispName + 10 + 1 + len(m.name)
		byteCnt[i] = dispData[i] + 5 + len(m.image) + len(m.relocs) + 1
	}
	exDataLen := 6 + 8*n + 2*n
	blockPos := make([]int, n)
	for i, m := range members {
		blockPos[i] = exDataLen
		exDataLen += 58 + 1 + len(m.name)
	}
	exData := make([]byte, exDataLen)
	le.PutUint16(exData[4:], uint16(n-1))
	exByteCnt := exDispData + 5 + exDataLen + 1
	running := exByteCnt
	for i, m := range members {
		entryPos := 6 + 8*i
		le.PutUint16(exData[entryPos:], uint16(blockPos[i]-entryPos))
		le.PutUint16(exData[6+8*n+2*i:], uint16(m.segNum))
		blk := exData[blockPos[i]:]
		dataOff := running + dispData[i] + 5
		le.PutUint32(blk[0:], uint32(dataOff))
		le.PutUint32(blk[4:], uint32(len(m.image)))
		if len(m.relocs) > 0 {
			le.PutUint32(blk[8:], uint32(dataOff+len(m.image)))
			le.PutUint32(blk[12:], uint32(len(m.relocs)))
		}
		hdr := segHeader(m.name, m.segNum, byteCnt[i], len(m.image), m.org, m.kind, m.align, m.banksize)
		copy(blk[16:48], hdr[0x0C:0x2C])
		blk[16+(0x2A-0x0C)] = 0 // DISPDATA zeroed inside the copy
		blk[16+(0x2A-0x0C)+1] = 0
		blk[58] = byte(len(m.name))
		copy(blk[59:], m.name)
		running += byteCnt[i]
	}

	out := segHeader(exName, 1, exByteCnt, exDataLen, 0, 0x8001, 0, 0)
	out = append(out, 0xF2)
	var cnt [4]byte
	le.PutUint32(cnt[:], uint32(exDataLen))
	out = append(out, cnt[:]...)
	out = append(out, exData...)
	out = append(out, 0x00)
	for i, m := range members {
		out = append(out, segHeader(m.name, m.segNum, byteCnt[i], len(m.image), m.org, m.kind, m.align, m.banksize)...)
		out = append(out, 0xF2)
		le.PutUint32(cnt[:], uint32(len(m.image)))
		out = append(out, cnt[:]...)
		out = append(out, m.image...)
		out = append(out, m.relocs...)
		out = append(out, 0x00)
	}
	return out
}

// relocRecords emits the patch list the way LinkIIGS 1.2 does: unshifted 2-
// and 3-byte patches are packed into SUPER RELOC2 and RELOC3 records, and
// what is left becomes a cRELOC when its offset and value both fit in two
// bytes, or a full RELOC otherwise. Width does not decide cRELOC -- a 4-byte
// patch at a low offset still compresses (oracle-verified).
func relocRecords(patches []relocPatch) []byte {
	var out []byte
	var super2, super3 []relocPatch
	superIS := map[int][]relocPatch{} // SUPER INTERSEG lists by type byte
	for _, p := range patches {
		if p.interseg {
			switch {
			case p.shift == 0 && p.size == 3 && p.seg < 256 && p.segoff < 0x10000:
				// SUPER INTERSEG1 (type 2): file 1, 3-byte patches whose
				// image bytes carry [target offset word][target segment]
				superIS[2] = append(superIS[2], p)
			case p.shift == 0 && p.size == 2 && p.seg >= 1 && p.seg <= 12 && p.segoff < 0x10000:
				// SUPER INTERSEG13..24 (types 14..25): file 1, segment =
				// type-13, 2-byte patches carrying the target offset word
				superIS[13+p.seg] = append(superIS[13+p.seg], p)
			case p.shift == -16 && p.size == 2 && p.seg >= 1 && p.seg <= 12 && p.segoff < 0x10000:
				// SUPER INTERSEG25..36 (types 26..37): as 13..24 but the
				// patch takes the address's high word (shift -16); a -8
				// shift stays an explicit cINTERSEG (oracle: TS2's INIT)
				superIS[25+p.seg] = append(superIS[25+p.seg], p)
			case p.offset < 0x10000 && p.seg < 256 && p.segoff < 0x10000:
				out = append(out, 0xF6, byte(p.size), byte(int8(p.shift)))
				out = append(out, byte(p.offset), byte(p.offset>>8))
				out = append(out, byte(p.seg))
				out = append(out, byte(p.segoff), byte(p.segoff>>8))
			default:
				out = append(out, 0xE3, byte(p.size), byte(int8(p.shift)))
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(p.offset))
				out = append(out, b[:]...)
				out = append(out, 1, 0) // file number
				out = append(out, byte(p.seg), byte(p.seg>>8))
				binary.LittleEndian.PutUint32(b[:], uint32(p.segoff))
				out = append(out, b[:]...)
			}
			continue
		}
		// The value participates as a full unsigned 32-bit quantity: a
		// source constant can tag an address with a high flag bit
		// (NewCalls' "DInfoParms+$80000000"), and $80005225 neither packs
		// into a SUPER page (the value lives in 2 image bytes there) nor
		// fits a cRELOC -- the original emits a wide RELOC for BOTH halves
		// of the pea pair (oracle-verified in Tool014).
		v := p.value & 0xFFFFFFFF
		switch {
		case p.shift == 0 && p.size == 2 && v < 0x10000:
			super2 = append(super2, p)
		case p.shift == 0 && p.size == 3 && v < 0x1000000:
			super3 = append(super3, p)
		case p.offset < 0x10000 && v < 0x10000:
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
	out = append(out, superReloc(super3, 1)...)
	for typ := 2; typ <= 37; typ++ {
		out = append(out, superReloc(superIS[typ], byte(typ))...)
	}
	return out
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
	Name    string
	Sels    []Sel
	Dynamic bool // "-lseg:dynamic": mark the load segment dynamic
	// Kind is the load segment's OMF KIND when the -lseg option carried
	// attributes ("-lseg:code:nospecial:static"), which REPLACE the kind the
	// group would otherwise inherit from its first object segment rather than
	// adding to it (oracle-probed: a $4000 object under a bare -lseg stays
	// $4000, under "-lseg:code" becomes $0000, and under
	// "-lseg:code:nospecial:static" becomes $1000).
	Kind    uint16
	KindSet bool
}

// SegKindAttrs turns a "-lseg:" attribute list into an OMF KIND. The
// attributes REPLACE whatever kind the group would inherit from its first
// object segment (oracle-probed: a $4000 object becomes $0000 under
// "-lseg:code" and $1000 under "-lseg:code:nospecial:static"). A "$hhhh"
// token gives the KIND word directly: the shipped Tool.Setup "main" segment
// is exactly $3000 under "-lseg:$3000 main", TS2/TS3's "INIT" exactly $2000
// under "-lseg:$2000 INIT". The named flag bits are the standard OMF ones;
// only those the sources actually use are accepted, so a new one shows up as
// an error rather than silently doing nothing.
func SegKindAttrs(spec string) (uint16, bool, error) {
	var kind uint16
	dyn := false
	for _, a := range strings.Split(spec, ":") {
		a = strings.TrimSpace(a)
		if strings.HasPrefix(a, "$") {
			n, err := strconv.ParseUint(a[1:], 16, 16)
			if err != nil {
				return 0, false, fmt.Errorf("bad -lseg attribute %q", a)
			}
			kind |= uint16(n)
			if kind&0x8000 != 0 {
				dyn = true
			}
			continue
		}
		switch strings.ToLower(a) {
		case "", "code", "static", "public", "special", "reloadable":
			// type 0 and the cleared-flag spellings: nothing to set
		case "data":
			kind |= 0x0001
		case "dynamic":
			kind |= 0x8000
			dyn = true
		case "private":
			kind |= 0x4000
		case "nospecial":
			kind |= 0x1000
		case "posindependent", "pic":
			kind |= 0x2000
		case "bankrelative":
			kind |= 0x0100
		case "skip":
			kind |= 0x0200
		case "reload":
			kind |= 0x0400
		case "absolutebank":
			kind |= 0x0800
		default:
			return 0, false, fmt.Errorf("unknown -lseg attribute %q", a)
		}
	}
	return kind, dyn, nil
}

// Sel selects a whole object file, or the segments carrying one load name
// when Seg is set. The "file(@name)" form the GS/OS makefiles use to split
// scm.obj across load segments names a SEG, not a PROC: "@oscall_seg" picks
// up every segment assembled under "SEG 'oscall_seg'".
type Sel struct {
	File *omf.File
	Seg  string   // "" = every segment in the file
	Segs []string // an explicit list, as in "cursor.obj(SETCURSOR,SHIFTONE)"
	// Exact selects by load name only, case-sensitively: automatic
	// per-load-name grouping must keep the Installer's 'Main' and the
	// library default 'main' apart (the original linker does).
	Exact bool
}

// wants reports whether an object segment is covered by this selection.
func (s Sel) Wants(seg *omf.Segment) bool {
	if s.Seg == "" && len(s.Segs) == 0 {
		return true
	}
	names := s.Segs
	if s.Seg != "" {
		names = append([]string{s.Seg}, names...)
	}
	for _, n := range names {
		if n == "" {
			continue // a trailing comma in the source list
		}
		if s.Exact {
			if strings.TrimRight(seg.LoadName, " ") == n {
				return true
			}
			continue
		}
		if strings.EqualFold(strings.TrimRight(seg.LoadName, " "), n) ||
			strings.EqualFold(seg.SegName, n) {
			return true
		}
	}
	return false
}

// LinkGroups links each group into its own load segment of one load file.
// Symbols are resolved across all groups; a reference from one load segment
// to a label in another becomes an interseg relocation, and a reference into
// a DYNAMIC load segment is routed through a generated ~JumpTable segment
// whose entries the system loader patches at run time (oracle: Tool015's
// MainTool reaches its PopUpProc defproc via "JML ~JumpTable entry").
//
// express selects the ~ExpressLoad form (the default); LinkIIGS -x emits the
// plain form without it.
func LinkGroups(groups []Group, express bool) ([]byte, error) {
	type built struct {
		name     string
		image    []byte
		org      int64
		kind     uint16
		banksize uint32
		align    int64
		dynamic  bool
		patches  []relocPatch
	}

	// First pass over every group: place segments and collect symbols. The
	// images cannot be patched yet because a later group may define a symbol
	// an earlier one references.
	globals := map[string]gsym{}
	absolutes := map[string]int64{}
	byName := map[string]*objSeg{}
	flat := map[string]flatSym{}
	// per-object-file scopes: a label reference resolves to a segment or
	// published symbol of its own file before any same-named one elsewhere
	// (see objSeg.fileSegs). The same file may appear in several groups
	// (scm.obj is split across 17 load segments), so key by the parsed file.
	type fileScope struct {
		segs    map[string]*objSeg
		globals map[string]gsym
		abs     map[string]int64
	}
	// keyed by (file, LibMember): library pulls scope per member (private
	// names resolve within their member, not across the whole pull)
	type scopeKey struct {
		f *omf.File
		m int
	}
	fileMaps := map[scopeKey]*fileScope{}
	// A library named as a group input -- SetStart's
	// "PLib(@main,@PLib,@~globals)" -- pulls need-based like -lib, but only
	// from the selected load segments, and the pulls land in THIS group.
	// Replace each library Sel with its pulled segments before placement.
	{
		var roots []*omf.File
		seenFile := map[*omf.File]bool{}
		for _, g := range groups {
			for _, sel := range g.Sels {
				if !seenFile[sel.File] && !IsLibrary(sel.File) {
					seenFile[sel.File] = true
					roots = append(roots, sel.File)
				}
			}
		}
		for gi := range groups {
			for si := range groups[gi].Sels {
				sel := &groups[gi].Sels[si]
				if !IsLibrary(sel.File) {
					continue
				}
				pulled := SelectLibAllowed(roots, sel.File, sel.Wants)
				if pulled == nil {
					pulled = &omf.File{}
				}
				*sel = Sel{File: pulled}
			}
		}
	}
	var all [][]*objSeg
	var out []built
	for gi, g := range groups {
		b := built{name: g.Name, dynamic: g.Dynamic}
		var segs []*objSeg
		pos := int64(0)
		for _, sel := range g.Sels {
			for i := range sel.File.Segments {
				s := &sel.File.Segments[i]
				if !sel.Wants(s) {
					continue
				}
				fs := fileMaps[scopeKey{sel.File, s.LibMember}]
				if fs == nil {
					fs = &fileScope{segs: map[string]*objSeg{},
						globals: map[string]gsym{}, abs: map[string]int64{}}
					fileMaps[scopeKey{sel.File, s.LibMember}] = fs
				}
				// A SKIP segment ($0200 in KIND) is an assembly-time guard,
				// not content: b00segR's overflow check is an empty segment
				// ORGed at the top of its region purely so the link fails if
				// the code runs past it. It contributes no bytes and nothing
				// pads out to it -- but it still publishes its symbols, which
				// the loader's header segment refers to.
				skip := s.Kind&0x0200 != 0
				if a := int64(s.Align); a > 0 {
					if pos%a != 0 {
						pos += a - pos%a
					}
					if a > b.align {
						b.align = a
					}
				}
				at := pos
				if len(segs) == 0 {
					b.org, b.kind = int64(s.Org), s.Kind
				} else if s.Org != 0 && skip {
					at = int64(s.Org) - b.org
				} else if s.Org != 0 {
					// An object segment carrying an ORG sits at that address
					// within the load segment, padding out from the one
					// before. The GS/OS kernel builds every load segment as
					// "start_segN, body, end_segN", and the start stub's
					// SEG_N_PAD is an empty segment ORGed past the header
					// purely to leave that gap.
					pos = int64(s.Org) - b.org
					at = pos
				}
				if s.BankSize > b.banksize {
					// largest member BANKSIZE wins (see LinkOpts)
					b.banksize = s.BankSize
				}
				absAt := int64(0)
				if s.TempOrg != 0 {
					// a TEMPORG segment is assembled for the address it is
					// copied to at run time: gquit's LOAD_APP sits at
					// $E0D7C0 in the image but every symbol resolves to its
					// $1010 run address (oracle-verified in scm.lnk)
					absAt = int64(s.TempOrg)
				} else if b.org != 0 {
					absAt = b.org + at
				}
				os := &objSeg{name: s.SegName, group: gi, base: at, abs: absAt, seg: s,
					fileSegs: fs.segs, fileGlobals: fs.globals, fileAbs: fs.abs}
				segs = append(segs, os)
				byName[s.SegName] = os
				fs.segs[s.SegName] = os
				if s.Kind&0x4000 == 0 {
					if os.abs != 0 {
						flat[s.SegName] = flatSym{os.abs, false, gi}
					} else {
						flat[s.SegName] = flatSym{os.base, true, gi}
					}
				}
				img, err := segImage(s)
				if err != nil {
					return nil, err
				}
				// In an absolute load segment a published symbol has a fixed
				// address, so record it as one.
				symBase := os.base
				if os.abs != 0 {
					symBase = os.abs
				}
				if err := collectSymbols(s, symBase, gi, os.abs != 0, globals, absolutes, flat); err != nil {
					return nil, err
				}
				if err := collectSymbols(s, symBase, gi, os.abs != 0, fs.globals, fs.abs, nil); err != nil {
					return nil, err
				}
				if skip {
					continue
				}
				if pos > int64(len(b.image)) {
					b.image = append(b.image, make([]byte, pos-int64(len(b.image)))...)
				}
				if len(img) > 0 {
					if need := pos + int64(len(img)); need > int64(len(b.image)) {
						b.image = append(b.image, make([]byte, need-int64(len(b.image)))...)
					}
					copy(b.image[pos:], img)
					pos += int64(len(img))
				}
			}
		}
		if len(segs) == 0 {
			return nil, fmt.Errorf("load segment %q selected no object segments", g.Name)
		}
		// -lseg attributes replace the inherited kind outright
		if g.KindSet {
			b.kind = g.Kind
		}
		all = append(all, segs)
		out = append(out, b)
	}
	if os.Getenv("LINKIIGS_MAP") != "" {
		for gi := range out {
			fmt.Fprintf(os.Stderr, "MAP group %q kind=$%04X banksize=$%X\n", out[gi].name, out[gi].kind, out[gi].banksize)
			for _, s := range all[gi] {
				fmt.Fprintf(os.Stderr, "  %08X %s\n", s.base, s.name)
			}
		}
	}

	// A group is dynamic if the -lseg:dynamic flag or its object KIND says so.
	isDynamic := func(gi int) bool {
		return out[gi].dynamic || out[gi].kind&0x8000 != 0
	}

	// Prescan: find references from one group into a DYNAMIC group. Each
	// distinct (group, offset) target gets a ~JumpTable entry, in first-
	// reference order. The jump table's existence decides the final segment
	// numbering, so this must happen before any image bytes are patched.
	type jtKey struct {
		group  int
		offset int64
	}
	jtIndex := map[jtKey]int{}
	var jtOrder []jtKey
	for gi := range out {
		if out[gi].org != 0 {
			continue
		}
		for _, os := range all[gi] {
			for _, r := range os.seg.Records {
				if r.Op != omf.RecLexpr && r.Op != omf.RecBexpr && r.Op != omf.RecExpr {
					continue
				}
				val, _, reloc, tgt, err := evalOMFExprReloc(r.Raw[2:], byName, globals, absolutes, flat, os)
				if err != nil {
					return nil, fmt.Errorf("segment %s: %w", os.name, err)
				}
				if reloc && tgt >= 0 && tgt != gi && isDynamic(tgt) {
					k := jtKey{tgt, val}
					if _, ok := jtIndex[k]; !ok {
						jtIndex[k] = len(jtOrder)
						jtOrder = append(jtOrder, k)
					}
				}
			}
		}
	}

	// The load file is emitted [~ExpressLoad,] every STATIC group in
	// declaration order, ~JumpTable, then every DYNAMIC group in declaration
	// order -- the partition, not the declaration order, decides placement
	// (oracle QDAux: "-lseg MAINPart / -lseg:Dynamic Pictures / -lseg
	// CopyBits / ..." emits MAINPart, CopyBits, ~JumpTable, Pictures, ...).
	first := 1
	if express {
		first = 2
	}
	var statics, dynamics []int
	for gi := range out {
		if isDynamic(gi) {
			dynamics = append(dynamics, gi)
		} else {
			statics = append(statics, gi)
		}
	}
	order := append(append([]int(nil), statics...), dynamics...)
	segNum := make([]int, len(out))
	jtSegNum := 0
	{
		n := first
		for _, gi := range statics {
			segNum[gi] = n
			n++
		}
		if len(jtOrder) > 0 {
			jtSegNum = n
			n++
		}
		for _, gi := range dynamics {
			segNum[gi] = n
			n++
		}
	}

	// ~JumpTable image: 8 zero bytes, then a 14-byte entry per target --
	// userID(2) fileNum(2) segNum(2) offset(4) and an unpatched "JSL loader"
	// ($22 00 00 00) the loader fixes up -- then a 4-byte zero terminator.
	// A reference to the target becomes an interseg reloc to its entry's JSL.
	jtEntryOff := func(idx int) int64 { return 8 + 14*int64(idx) + 10 }
	var jtImage []byte
	if len(jtOrder) > 0 {
		jtImage = make([]byte, 8+14*len(jtOrder)+4)
		for i, k := range jtOrder {
			e := jtImage[8+14*i:]
			binary.LittleEndian.PutUint16(e[2:], 1) // file number
			binary.LittleEndian.PutUint16(e[4:], uint16(segNum[k.group]))
			binary.LittleEndian.PutUint32(e[6:], uint32(k.offset))
			e[10] = 0x22 // JSL
		}
	}

	// Second pass: patch, now that every symbol and segment number is known.
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
					val, shift, reloc, tgt, err := evalOMFExprReloc(r.Raw[2:], byName, globals, absolutes, flat, os)
					if err != nil {
						return nil, fmt.Errorf("segment %s: %w", os.name, err)
					}
					switch {
					case b.org != 0 || !reloc:
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
					case tgt >= 0 && tgt != gi &&
						out[tgt].kind&0x0100 != 0 && !isDynamic(tgt) &&
						size == 2 && shift == 0:
						// a 2-byte reference INTO a bank-relative segment is
						// the target's own bank offset -- absolute, no
						// relocation, from any segment (oracle-verified:
						// references into the Finder's FINDER group)
						putLE(b.image[pc:], val, size)
					case tgt >= 0 && tgt != gi:
						// cross-segment: an interseg relocation. A target in
						// a dynamic segment is reached through its ~JumpTable
						// entry instead of directly.
						seg, segoff := segNum[tgt], val
						if isDynamic(tgt) {
							seg, segoff = jtSegNum, jtEntryOff(jtIndex[jtKey{tgt, val}])
						}
						if size == 3 && shift == 0 && segoff < 0x10000 {
							// SUPER INTERSEG payload: the image word is the
							// target offset and the third byte its segment.
							putLE(b.image[pc:], segoff, 2)
							b.image[pc+2] = byte(seg)
						} else if size == 2 && shift == 0 && seg >= 1 && seg <= 12 && segoff < 0x10000 {
							// SUPER INTERSEG13..24 payload: the target offset
							putLE(b.image[pc:], segoff, size)
						} else if size == 2 && shift == -16 && seg >= 1 && seg <= 12 && segoff < 0x10000 {
							// SUPER INTERSEG25..36 payload: the target offset
							// word; the loader shifts after adding the base
							// (oracle: TS2's INIT bank-byte references)
							putLE(b.image[pc:], segoff, size)
						} else {
							// an explicit cINTERSEG/INTERSEG record carries
							// the target itself; the image bytes stay zero
							// (oracle: Tool016's shifted reference into Pics)
							putLE(b.image[pc:], 0, size)
						}
						b.patches = append(b.patches, relocPatch{size: size, shift: shift, offset: pc,
							interseg: true, seg: seg, segoff: segoff})
					default:
						putLE(b.image[pc:], val, size)
						// a BANK-RELATIVE load segment ($0100) sits on a bank
						// boundary: a 2-byte in-segment reference is the
						// target's own offset, absolute, with no relocation
						// (oracle-verified: the Finder's -lseg:$1100 FINDER)
						if b.kind&0x0100 == 0 || size != 2 || shift != 0 {
							b.patches = append(b.patches, relocPatch{size: size, shift: shift, offset: pc, value: val})
						}
					}
					pc += int64(size)
				case r.Op == omf.RecRelexpr:
					size := int(r.Raw[1])
					v, err := relBranch(r.Raw, pc, b.org, byName, globals, absolutes, flat, os)
					if err != nil {
						return nil, fmt.Errorf("segment %s: %w", os.name, err)
					}
					putLE(b.image[pc:], v, size)
					pc += int64(size)
				case r.Op == omf.RecOrg:
					pc += int64(int32(binary.LittleEndian.Uint32(r.Raw[1:])))
				case r.Op == omf.RecEnd || r.Op == omf.RecGlobal || r.Op == omf.RecGequ,
					r.Op == omf.RecStrong, r.Op == omf.RecUsing:
				default:
					return nil, fmt.Errorf("segment %s: unsupported record %s in linker",
						os.name, omf.RecName(r.Op))
				}
			}
		}
	}

	// Assemble the members in final order, splicing in the ~JumpTable.
	type member struct {
		name     string
		image    []byte
		org      int64
		kind     uint16
		banksize uint32
		align    int64
		patches  []relocPatch
		segNum   int
	}
	var members []member
	jtDone := false
	for _, gi := range order {
		b := &out[gi]
		if len(jtOrder) > 0 && !jtDone && isDynamic(gi) {
			members = append(members, member{name: "~JumpTable", image: jtImage, kind: 0x0002, banksize: 0x10000, segNum: jtSegNum})
			jtDone = true
		}
		kind := b.kind
		if b.dynamic {
			kind |= 0x8000
		}
		members = append(members, member{name: b.name, image: b.image, org: b.org,
			kind: kind, banksize: b.banksize, align: b.align, patches: b.patches, segNum: segNum[gi]})
	}
	if len(jtOrder) > 0 && !jtDone {
		members = append(members, member{name: "~JumpTable", image: jtImage, kind: 0x0002, banksize: 0x10000, segNum: jtSegNum})
	}

	if !express {
		var file []byte
		for _, m := range members {
			file = append(file, loadSegment(m.name, m.segNum, m.image, m.org, m.kind, m.banksize, m.align, m.patches)...)
		}
		return file, nil
	}
	exMembers := make([]exMember, len(members))
	for i, m := range members {
		exMembers[i] = exMember{name: m.name, image: m.image, org: m.org,
			kind: m.kind, banksize: m.banksize, align: m.align, segNum: m.segNum,
			relocs: relocRecords(m.patches)}
	}
	return buildExpressFile(exMembers), nil
}

// collectSymbols records a segment's GLOBAL and GEQU definitions. GLOBALs of
// a relocatable segment are offsets within load segment `group`; those of an
// absolute (org'd/TEMPORG) segment are fixed addresses and go to absolutes.
func collectSymbols(s *omf.Segment, base int64, group int, isAbs bool, globals map[string]gsym, absolutes map[string]int64, flat map[string]flatSym) error {
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
			name := string(r.Raw[2 : 2+n])
			if isAbs {
				absolutes[name] = off
			} else {
				globals[name] = gsym{off, group}
			}
			if flat != nil && globalPrivate(r.Raw) == 0 {
				flat[name] = flatSym{off, !isAbs, group}
			}
		case r.Op == omf.RecGequ:
			n := int(r.Raw[1])
			name := string(r.Raw[2 : 2+n])
			// A PascalIIGS GEQU may be RELOCATABLE: "GSCALC.arr equ
			// %GSCALC.arr+$418" publishes an offset into the segment that
			// carries the record. Such a symbol behaves like a GLOBAL at
			// (base+disp, group), not an absolute (oracle: GSCalc links).
			if disp, ok := gequSelfRef(r.Raw[2+n+4:], s.SegName); ok && !isAbs {
				globals[name] = gsym{base + disp, group}
				if flat != nil && globalPrivate(r.Raw) == 0 {
					flat[name] = flatSym{base + disp, true, group}
				}
				continue
			}
			v, _, err := evalOMFExpr(r.Raw[2+n+4:], nil, nil, nil, nil, nil)
			if err != nil {
				return fmt.Errorf("GEQU %s: %w", name, err)
			}
			if flat != nil && globalPrivate(r.Raw) == 0 {
				flat[name] = flatSym{v, false, -1}
			}
			absolutes[name] = v
		}
	}
	return nil
}

// gequSelfRef matches the one relocatable GEQU shape PascalIIGS emits: a
// reference to the CONTAINING segment's own name plus an optional constant
// ($83 <pstr segname> [$81 <disp:4> $01] $00), returning the displacement.
func gequSelfRef(b []byte, segName string) (int64, bool) {
	if len(b) < 2 || b[0] != 0x83 {
		return 0, false
	}
	n := int(b[1])
	if len(b) < 2+n || string(b[2:2+n]) != segName {
		return 0, false
	}
	rest := b[2+n:]
	if len(rest) >= 1 && rest[0] == 0x00 {
		return 0, true
	}
	if len(rest) >= 7 && rest[0] == 0x81 && rest[5] == 0x01 && rest[6] == 0x00 {
		return int64(binary.LittleEndian.Uint32(rest[1:])), true
	}
	return 0, false
}

// loadSegment emits one load-file segment carrying image plus its relocations.
func loadSegment(name string, segNum int, image []byte, org int64, kind uint16, banksize uint32, align int64, patches []relocPatch) []byte {
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
	le.PutUint32(hdr[0x1C:], uint32(align))
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
			g.Sels = append(g.Sels, Sel{File: f, Seg: n, Exact: true})
		}
		gs = append(gs, g)
	}
	return gs
}
