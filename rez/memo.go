package rez

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/text/encoding/charmap"
)

// The 128-byte rFileMemo of a resource file that came off a Macintosh through
// DuplicateIIGS -mac carries a copy of the Mac File Manager's record for the
// file. RezIIGS itself leaves it zero (see Build). Offsets are within the memo,
// which starts 12 bytes into the fork:
//
//	[0:36]     zero
//	[36]       file name length, then the name (MacRoman)
//	           one pad byte follows an EVEN-length name, rounding the field
//	           (1+n bytes) up to an even size
//	           a long, = 2 in every shipped file
//	           copy 1: file type (4) + creator (4), then the 8-byte FInfo
//	           tail when the 16-byte record ends at or before offset 70
//	           a 2-byte marker 10 bytes past copy 1's type/creator, when it
//	           ends at or before offset 70
//	[70:78]    copy 2 of file type + creator, always here
//	[78:86]    copy 2 of the FInfo tail
//	[86:88]    a 2-byte field
//	[88:102]   zero
//	[102:106]  creation time, Mac epoch (seconds since 1904), BIG-endian
//	[106:110]  a long, big-endian, usually zero
//	[110:114]  the fork's length, big-endian
//	[114:128]  zero
//
// The big-endian fields are the 68K host's own, never byte-swapped.
const (
	memoStart      = 12
	memoSize       = 128
	memoNameOff    = 36
	memoCopy2Off   = 70
	memoTail2Off   = 86
	memoCreatedOff = 102
	memoUnknownOff = 106
	memoForkLenOff = 110
	memoMarkerRel  = 10
)

// Memo is the File Manager record DuplicateIIGS -mac leaves in rFileMemo.
// Name, FileType, Creator and Created describe the file; the rest are host
// values with no known source, zero unless a caller knows better.
type Memo struct {
	Name     string
	FileType [4]byte // see FileTypeField
	Creator  [4]byte // "pdos" for every ProDOS file
	Created  uint32  // seconds since 1 Jan 1904, local time
	Const    uint32  // 2 in every shipped file
	NamePad  byte
	Tail     [8]byte // FInfo flags/location/folder, mirrored in both copies
	Tail2    [2]byte
	Marker   [2]byte
	Unknown  uint32
}

// FileTypeField is the 4-byte file type a ProDOS file carries in the memo:
// "F9  " (two hex digits and two spaces) for aux type 0, otherwise 'p', the
// type byte and the aux type, little-endian -- the ProDOS-on-HFS convention.
func FileTypeField(fileType byte, auxType uint16) [4]byte {
	if auxType == 0 {
		var f [4]byte
		copy(f[:], fmt.Sprintf("%02X  ", fileType))
		return f
	}
	return [4]byte{'p', fileType, byte(auxType), byte(auxType >> 8)}
}

// StampMemo writes m into fork's rFileMemo, as DuplicateIIGS -mac does.
func StampMemo(fork []byte, m Memo) error {
	if len(fork) < memoStart+memoSize {
		return fmt.Errorf("resource fork too short (%d bytes) for a memo", len(fork))
	}
	name, err := charmap.Macintosh.NewEncoder().Bytes([]byte(m.Name))
	if err != nil {
		return fmt.Errorf("memo name %q: %w", m.Name, err)
	}
	if len(name) > 127 {
		return fmt.Errorf("memo name %q longer than 127 bytes", m.Name)
	}
	memo := make([]byte, memoSize)
	off := memoNameOff
	memo[off] = byte(len(name))
	off++
	off += copy(memo[off:], name)
	if len(name)%2 == 0 {
		memo[off] = m.NamePad
		off++
	}
	binary.LittleEndian.PutUint32(memo[off:], m.Const)
	off += 4
	copy1End := off + 8
	if copy1End > memoCopy2Off {
		return fmt.Errorf("memo name %q too long: type/creator would overlap copy 2", m.Name)
	}
	copy(memo[off:], m.FileType[:])
	copy(memo[off+4:], m.Creator[:])
	if copy1End+8 <= memoCopy2Off {
		copy(memo[copy1End:], m.Tail[:])
	}
	if marker := copy1End + memoMarkerRel; marker+2 <= memoCopy2Off {
		copy(memo[marker:], m.Marker[:])
	}
	copy(memo[memoCopy2Off:], m.FileType[:])
	copy(memo[memoCopy2Off+4:], m.Creator[:])
	copy(memo[memoCopy2Off+8:], m.Tail[:])
	copy(memo[memoTail2Off:], m.Tail2[:])
	be := binary.BigEndian
	be.PutUint32(memo[memoCreatedOff:], m.Created)
	be.PutUint32(memo[memoUnknownOff:], m.Unknown)
	be.PutUint32(memo[memoForkLenOff:], uint32(len(fork)))
	copy(fork[memoStart:], memo)
	return nil
}
