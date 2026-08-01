// Package omf reads and writes Apple IIgs Object Module Format (OMF) files:
// object files, load files, and libraries produced by the MPW IIGS / APW /
// ORCA toolchains, versions 1.0 through 2.1.
//
// References: GS/OS Reference Appendix F; Apple IIgs Programmer's Workshop
// Reference ch. 7; ORCA/M 2.0 manual Appendix B; CiderPress II OMF notes
// (which document errata in the Apple manuals).
package omf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Record opcodes.
const (
	RecEnd       = 0x00 // $01-$DF are CONST with length = opcode
	RecAlign     = 0xE0
	RecOrg       = 0xE1
	RecReloc     = 0xE2
	RecInterseg  = 0xE3
	RecUsing     = 0xE4
	RecStrong    = 0xE5
	RecGlobal    = 0xE6
	RecGequ      = 0xE7
	RecMem       = 0xE8
	RecExpr      = 0xEB
	RecZexpr     = 0xEC
	RecBexpr     = 0xED
	RecRelexpr   = 0xEE
	RecLocal     = 0xEF
	RecEqu       = 0xF0
	RecDS        = 0xF1
	RecLconst    = 0xF2
	RecLexpr     = 0xF3
	RecEntry     = 0xF4
	RecCReloc    = 0xF5
	RecCInterseg = 0xF6
	RecSuper     = 0xF7
)

var recNames = map[byte]string{
	RecEnd: "END", RecAlign: "ALIGN", RecOrg: "ORG", RecReloc: "RELOC",
	RecInterseg: "INTERSEG", RecUsing: "USING", RecStrong: "STRONG",
	RecGlobal: "GLOBAL", RecGequ: "GEQU", RecMem: "MEM", RecExpr: "EXPR",
	RecZexpr: "ZEXPR", RecBexpr: "BEXPR", RecRelexpr: "RELEXPR",
	RecLocal: "LOCAL", RecEqu: "EQU", RecDS: "DS", RecLconst: "LCONST",
	RecLexpr: "LEXPR", RecEntry: "ENTRY", RecCReloc: "cRELOC",
	RecCInterseg: "cINTERSEG", RecSuper: "SUPER",
}

// RecName returns the mnemonic for a record opcode.
func RecName(op byte) string {
	if op >= 0x01 && op <= 0xDF {
		return "CONST"
	}
	if n, ok := recNames[op]; ok {
		return n
	}
	return fmt.Sprintf("$%02X", op)
}

// Record is one raw record: the opcode plus its body bytes exactly as stored.
// Raw includes the opcode byte, so re-emitting Raw for every record followed
// by segment padding reproduces the segment body losslessly.
type Record struct {
	Op  byte
	Raw []byte // full record bytes including opcode
}

// Segment is one OMF segment: a parsed header plus its record stream.
type Segment struct {
	// Header fields (v2 names; v1 values are mapped where they differ).
	ByteCnt  uint32 // total size of segment in file, incl. header (v1: BLKCNT*512)
	ResSpc   uint32
	Length   uint32
	Kind     uint16 // v2 KIND; v1 KIND byte is mapped by the reader
	LabLen   byte
	NumLen   byte
	Version  byte // 1 or 2
	BankSize uint32
	Org      uint32
	Align    uint32
	NumSex   byte
	SegNum   uint16
	EntryPt  uint32
	DispName uint16
	DispData uint16
	TempOrg  uint32 // v2.1 only (present when DispName > 0x2C)
	LCBank   byte   // v1 only
	Revision uint16 // v1 only ("REVISION" field)
	LoadName string // 10 bytes, space padded
	SegName  string

	Records []Record

	// Raw header bytes (offset 0 .. DispData) exactly as read, so that
	// Write can reproduce unparsed/padding bytes losslessly.
	rawHeader []byte
	// Trailing bytes between the END record and ByteCnt boundary (padding).
	trailer []byte
}

// File is a parsed OMF file: one or more segments. Libraries and ExpressLoad
// files are also record-level parseable with this reader.
type File struct {
	Segments []Segment
}

type parseErr struct {
	off int
	msg string
}

func (e *parseErr) Error() string { return fmt.Sprintf("offset $%X: %s", e.off, e.msg) }

// Parse reads every segment in an OMF file.
func Parse(data []byte) (*File, error) {
	f := &File{}
	off := 0
	for off < len(data) {
		// Tolerate zero padding at EOF (some load files are block-padded).
		// A real segment can never be all zeros (BYTECNT would be 0).
		if rest := data[off:]; bytes.Count(rest, []byte{0}) == len(rest) {
			break
		}
		seg, n, err := parseSegment(data[off:])
		if err != nil {
			return f, &parseErr{off, err.Error()}
		}
		f.Segments = append(f.Segments, *seg)
		off += n
	}
	return f, nil
}

func parseSegment(data []byte) (*Segment, int, error) {
	if len(data) < 0x30 {
		return nil, 0, fmt.Errorf("truncated header (%d bytes)", len(data))
	}
	le := binary.LittleEndian
	s := &Segment{}
	s.Version = data[0x0F]
	s.LabLen = data[0x0D]
	s.NumLen = data[0x0E]
	if s.NumLen != 4 {
		return nil, 0, fmt.Errorf("unsupported NUMLEN %d", s.NumLen)
	}
	switch s.Version {
	case 1:
		blkCnt := le.Uint32(data[0x00:])
		s.ByteCnt = blkCnt * 512
		s.ResSpc = le.Uint32(data[0x04:])
		s.Length = le.Uint32(data[0x08:])
		s.Kind = uint16(data[0x0C]) // v1 KIND byte at $0C
		s.BankSize = le.Uint32(data[0x10:])
		s.Org = le.Uint32(data[0x14:])
		s.Align = le.Uint32(data[0x18:])
		s.NumSex = data[0x1C]
		s.LCBank = data[0x1D]
		s.SegNum = le.Uint16(data[0x1E:])
		s.EntryPt = le.Uint32(data[0x20:])
		s.DispName = le.Uint16(data[0x24:])
		s.DispData = le.Uint16(data[0x26:])
	case 2:
		s.ByteCnt = le.Uint32(data[0x00:])
		s.ResSpc = le.Uint32(data[0x04:])
		s.Length = le.Uint32(data[0x08:])
		s.BankSize = le.Uint32(data[0x10:])
		s.Kind = le.Uint16(data[0x14:])
		s.Org = le.Uint32(data[0x18:])
		s.Align = le.Uint32(data[0x1C:])
		s.NumSex = data[0x20]
		s.SegNum = le.Uint16(data[0x22:])
		s.EntryPt = le.Uint32(data[0x24:])
		s.DispName = le.Uint16(data[0x28:])
		s.DispData = le.Uint16(data[0x2A:])
		if s.DispName > 0x2C { // v2.1 adds TEMPORG at $2C
			s.TempOrg = le.Uint32(data[0x2C:])
		}
	default:
		return nil, 0, fmt.Errorf("unsupported VERSION %d", s.Version)
	}
	if int(s.ByteCnt) > len(data) || s.ByteCnt == 0 {
		return nil, 0, fmt.Errorf("BYTECNT $%X out of range (have $%X)", s.ByteCnt, len(data))
	}
	seg := data[:s.ByteCnt]

	// Names.
	nameOff := int(s.DispName)
	if nameOff+10 > len(seg) {
		return nil, 0, fmt.Errorf("DISPNAME $%X out of range", s.DispName)
	}
	s.LoadName = string(seg[nameOff : nameOff+10])
	segNameOff := nameOff + 10
	if s.LabLen == 0 {
		l := int(seg[segNameOff])
		s.SegName = string(seg[segNameOff+1 : segNameOff+1+l])
	} else {
		s.SegName = string(seg[segNameOff : segNameOff+int(s.LabLen)])
	}
	s.rawHeader = append([]byte(nil), seg[:s.DispData]...)

	// Record stream.
	p := &recParser{data: seg, off: int(s.DispData), labLen: s.LabLen, numLen: int(s.NumLen)}
	for {
		rec, err := p.next()
		if err != nil {
			return nil, 0, fmt.Errorf("segment %q: %w", s.SegName, err)
		}
		s.Records = append(s.Records, rec)
		if rec.Op == RecEnd {
			break
		}
	}
	s.trailer = append([]byte(nil), seg[p.off:]...)
	return s, int(s.ByteCnt), nil
}

type recParser struct {
	data   []byte
	off    int
	labLen byte
	numLen int
}

func (p *recParser) need(n int) error {
	if p.off+n > len(p.data) {
		return fmt.Errorf("record at $%X: need %d bytes past end", p.off, n)
	}
	return nil
}

// next consumes one record and returns it (Raw includes the opcode byte).
func (p *recParser) next() (Record, error) {
	start := p.off
	if err := p.need(1); err != nil {
		return Record{}, err
	}
	op := p.data[p.off]
	p.off++
	var err error
	switch {
	case op == RecEnd:
	case op >= 0x01 && op <= 0xDF: // CONST
		err = p.skip(int(op))
	case op == RecAlign, op == RecOrg, op == RecDS:
		err = p.skip(p.numLen)
	case op == RecReloc:
		err = p.skip(1 + 1 + p.numLen + p.numLen)
	case op == RecInterseg:
		err = p.skip(1 + 1 + p.numLen + 2 + 2 + p.numLen)
	case op == RecUsing, op == RecStrong:
		err = p.skipName()
	case op == RecGlobal, op == RecLocal:
		if err = p.skipName(); err == nil {
			err = p.skip(2 + 1 + 1)
		}
	case op == RecGequ, op == RecEqu:
		if err = p.skipName(); err == nil {
			if err = p.skip(2 + 1 + 1); err == nil {
				err = p.skipExpr()
			}
		}
	case op == RecMem:
		err = p.skip(p.numLen + p.numLen)
	case op == RecExpr, op == RecZexpr, op == RecBexpr, op == RecLexpr:
		if err = p.skip(1); err == nil {
			err = p.skipExpr()
		}
	case op == RecRelexpr:
		if err = p.skip(1 + p.numLen); err == nil {
			err = p.skipExpr()
		}
	case op == RecEntry:
		if err = p.skip(2 + p.numLen); err == nil {
			err = p.skipName()
		}
	case op == RecLconst:
		if err = p.need(4); err == nil {
			n := int(binary.LittleEndian.Uint32(p.data[p.off:]))
			err = p.skip(4 + n)
		}
	case op == RecCReloc:
		err = p.skip(1 + 1 + 2 + 2)
	case op == RecCInterseg:
		err = p.skip(1 + 1 + 2 + 1 + 2)
	case op == RecSuper:
		if err = p.need(4); err == nil {
			n := int(binary.LittleEndian.Uint32(p.data[p.off:]))
			err = p.skip(4 + n)
		}
	default:
		return Record{}, fmt.Errorf("unknown record $%02X at $%X", op, start)
	}
	if err != nil {
		return Record{}, err
	}
	return Record{Op: op, Raw: append([]byte(nil), p.data[start:p.off]...)}, nil
}

func (p *recParser) skip(n int) error {
	if err := p.need(n); err != nil {
		return err
	}
	p.off += n
	return nil
}

func (p *recParser) skipName() error {
	if p.labLen != 0 {
		return p.skip(int(p.labLen))
	}
	if err := p.need(1); err != nil {
		return err
	}
	l := int(p.data[p.off])
	return p.skip(1 + l)
}

// skipExpr consumes an OMF expression: operator/operand tokens ending in $00.
func (p *recParser) skipExpr() error {
	for {
		if err := p.need(1); err != nil {
			return err
		}
		tok := p.data[p.off]
		p.off++
		switch {
		case tok == 0x00:
			return nil
		case tok <= 0x1F: // operators
		case tok == 0x80, tok == 0x81, tok == 0x87: // numeric operands
			if err := p.skip(p.numLen); err != nil {
				return err
			}
		case tok >= 0x82 && tok <= 0x86: // label-name operands
			if err := p.skipName(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown expression token $%02X at $%X", tok, p.off-1)
		}
	}
}

// Write re-emits the file. For files that were parsed with Parse and not
// modified, the output is byte-identical to the input (raw header, raw
// records, and trailer are preserved verbatim).
func (f *File) Write() []byte {
	var out bytes.Buffer
	for i := range f.Segments {
		s := &f.Segments[i]
		out.Write(s.rawHeader)
		for _, r := range s.Records {
			out.Write(r.Raw)
		}
		out.Write(s.trailer)
	}
	return out.Bytes()
}

// SegmentImage returns a segment's initialized memory image: CONST/LCONST
// payloads concatenated, DS reservations zero-filled, expression slots
// zero-filled (they are patched by the linker).
func SegmentImage(s *Segment) []byte {
	var img []byte
	for _, r := range s.Records {
		switch {
		case r.Op >= 0x01 && r.Op <= 0xDF:
			img = append(img, r.Raw[1:]...)
		case r.Op == RecLconst:
			img = append(img, r.Raw[5:]...)
		case r.Op == RecDS:
			img = append(img, make([]byte, binary.LittleEndian.Uint32(r.Raw[1:]))...)
		case r.Op == RecLexpr || r.Op == RecBexpr || r.Op == RecExpr:
			img = append(img, make([]byte, r.Raw[1])...)
		}
	}
	return img
}

// Relocate applies a load segment's relocation dictionary to its image for a
// segment loaded at base.
//
// MakeBinIIGS's "-org" names the address the binary will run at, and the
// relocatable load file the linker produced still carries its dictionary: the
// bytes in the image hold segment-relative values until this runs. Skipping it
// leaves every absolute reference pointing into page zero -- ProDOS is built
// with "-org $2000" and jumped to $03xx instead of $23xx.
func Relocate(s *Segment, img []byte, base int64) {
	put := func(off, val int64, n int, shift int8) {
		if shift < 0 {
			val >>= uint(-shift)
		} else if shift > 0 {
			val <<= uint(shift)
		}
		for i := 0; i < n && off+int64(i) < int64(len(img)); i++ {
			img[off+int64(i)] = byte(val >> (8 * uint(i)))
		}
	}
	get := func(off int64, n int) int64 {
		var v int64
		for i := 0; i < n && off+int64(i) < int64(len(img)); i++ {
			v |= int64(img[off+int64(i)]) << (8 * uint(i))
		}
		return v
	}
	for _, r := range s.Records {
		switch r.Op {
		case RecReloc:
			n, shift := int(r.Raw[1]), int8(r.Raw[2])
			off := int64(binary.LittleEndian.Uint32(r.Raw[3:]))
			val := int64(binary.LittleEndian.Uint32(r.Raw[7:]))
			put(off, val+base, n, shift)
		case RecCReloc:
			n, shift := int(r.Raw[1]), int8(r.Raw[2])
			off := int64(binary.LittleEndian.Uint16(r.Raw[3:]))
			val := int64(binary.LittleEndian.Uint16(r.Raw[5:]))
			put(off, val+base, n, shift)
		case RecSuper:
			// The site's current contents are the segment-relative value.
			n, shift := superWidth(r.Raw[5])
			if n == 0 {
				continue
			}
			for _, off := range superOffsets(r.Raw[6 : 1+4+int(binary.LittleEndian.Uint32(r.Raw[1:]))]) {
				put(off, get(off, n)+base, n, shift)
			}
		}
	}
}

// superWidth gives the patch width and shift for a SUPER record type; 0 means
// a type this does not handle (the INTERSEG families, which a single-file
// load never produces).
func superWidth(typ byte) (int, int8) {
	switch typ {
	case 0: // SUPER_RELOC2
		return 2, 0
	case 1: // SUPER_RELOC3
		return 3, 0
	case 0x1B: // 2-byte bank reference, as the shipped 6.0.1 linker emits
		return 2, -16
	}
	return 0, 0
}

// superOffsets decodes a SUPER record body into image offsets. A subrecord
// implicitly advances one page; $80|n skips n pages beyond that.
func superOffsets(body []byte) []int64 {
	var out []int64
	page := int64(0)
	for i := 0; i < len(body); {
		b := body[i]
		if b&0x80 != 0 {
			page += int64(b & 0x7F)
			i++
			continue
		}
		n := int(b) + 1
		i++
		for k := 0; k < n && i+k < len(body); k++ {
			out = append(out, page<<8|int64(body[i+k]))
		}
		i += n
		page++
	}
	return out
}
