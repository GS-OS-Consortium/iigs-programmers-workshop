package asm

import "encoding/binary"

// Segment is one assembled OMF segment: header parameters plus the finished
// record stream (which already ends with the END record).
type Segment struct {
	Name     string
	LoadName string
	Org      int64
	Length   int64
	Records  []byte
}

// Object is a finished assembly: one segment per PROC.
type Object struct {
	Segments []Segment
}

// WriteOMF emits the object as an OMF v2 object file, matching the original
// AsmIIGS output byte-for-byte (header layout, KIND=$4000 private code,
// LOADNAME "main") as established against the oracle.
func (o *Object) WriteOMF() []byte {
	var out []byte
	for i := range o.Segments {
		out = append(out, o.Segments[i].writeSeg(i+1)...)
	}
	return out
}

func (s *Segment) writeSeg(segNum int) []byte {
	le := binary.LittleEndian
	name := s.Name
	if len(name) > 255 {
		name = name[:255]
	}
	dispName := 0x2C
	dispData := dispName + 10 + 1 + len(name)
	byteCnt := dispData + len(s.Records)

	hdr := make([]byte, dispData)
	le.PutUint32(hdr[0x00:], uint32(byteCnt))  // BYTECNT
	le.PutUint32(hdr[0x04:], 0)                // RESSPC
	le.PutUint32(hdr[0x08:], uint32(s.Length)) // LENGTH
	hdr[0x0D] = 0                              // LABLEN (pstrings)
	hdr[0x0E] = 4                              // NUMLEN
	hdr[0x0F] = 2                              // VERSION
	le.PutUint32(hdr[0x10:], 0x10000)          // BANKSIZE
	le.PutUint16(hdr[0x14:], 0x4000)           // KIND: private code
	le.PutUint32(hdr[0x18:], uint32(s.Org))    // ORG
	le.PutUint32(hdr[0x1C:], 0)                // ALIGN
	hdr[0x20] = 0                              // NUMSEX
	le.PutUint16(hdr[0x22:], uint16(segNum))   // SEGNUM
	le.PutUint32(hdr[0x24:], 0)                // ENTRY
	le.PutUint16(hdr[0x28:], uint16(dispName))
	le.PutUint16(hdr[0x2A:], uint16(dispData))
	ln := s.LoadName
	if ln == "" {
		ln = "main"
	}
	copy(hdr[dispName:], "          ")
	copy(hdr[dispName:], ln)
	hdr[dispName+10] = byte(len(name))
	copy(hdr[dispName+11:], name)

	return append(hdr, s.Records...)
}
