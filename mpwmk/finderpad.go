package mpwmk

import "encoding/binary"

// finderPad is the six bytes Main.aii plants at the front of the FINDER
// segment (":CFFA5") ahead of a DS hole. The hole pushes the real startup
// (phk/plb) off offset 0. Public LinkIIGS leaves the segment entry at 0 for
// that object — the object header entry is 0, and there is no ENTRY record
// to drop — so the loader would begin in the hole. The 6.0.4 Finder's entry
// is the first byte after the hole. patchFinderStartup writes that entry
// into the load file after the link. It is not part of link.Link: the oracle
// replay of the link command must stay byte-identical to LinkIIGS.
var finderPad = []byte{0x3A, 0x43, 0x46, 0x46, 0x41, 0x35}

// patchFinderStartup sets the FINDER segment's entry to the first byte after
// its leading pad, and the same field in the ~ExpressLoad directory copy of
// the header. A load file without that pad is returned unchanged.
func patchFinderStartup(data []byte) []byte {
	off, entry, ok := finderEntry(data)
	if !ok {
		return data
	}
	out := append([]byte(nil), data...)
	// The directory copy is header bytes $0C..$2B with DISPDATA zeroed, so
	// the entry long sits $18 into that copy. Capture the copy before the
	// segment header itself changes.
	window := append([]byte(nil), out[off+0x0C:off+0x2C]...)
	window[0x2A-0x0C] = 0
	window[0x2A-0x0C+1] = 0
	binary.LittleEndian.PutUint32(out[off+0x24:], uint32(entry))
	if i := findWindow(out, window); i >= 0 {
		binary.LittleEndian.PutUint32(out[i+(0x24-0x0C):], uint32(entry))
	}
	return out
}

// finderEntry reports the file offset of the FINDER segment header and the
// entry offset of the first byte after a leading pad.
func finderEntry(data []byte) (header int, entry int, ok bool) {
	off := 0
	for off+0x30 <= len(data) && (data[off+0x0F] == 1 || data[off+0x0F] == 2) {
		bytecnt := int(binary.LittleEndian.Uint32(data[off:]))
		if bytecnt < 0x30 || off+bytecnt > len(data) {
			break
		}
		dispName := int(binary.LittleEndian.Uint16(data[off+0x28:]))
		dispData := int(binary.LittleEndian.Uint16(data[off+0x2A:]))
		if dispName+11 < bytecnt && dispData < bytecnt {
			nl := int(data[off+dispName+10])
			name := data[off+dispName+11 : off+dispName+11+nl]
			if string(name) == "FINDER" {
				if e, yes := padEntry(segmentImage(data[off:off+bytecnt], dispData)); yes {
					return off, e, true
				}
			}
		}
		off += bytecnt
	}
	return 0, 0, false
}

// padEntry is the offset of the first nonzero byte after the signature and
// the zero hole. No hole means there is nothing to skip.
func padEntry(image []byte) (int, bool) {
	if len(image) < len(finderPad) || string(image[:len(finderPad)]) != string(finderPad) {
		return 0, false
	}
	i := len(finderPad)
	for i < len(image) && image[i] == 0 {
		i++
	}
	if i == len(finderPad) || i >= len(image) {
		return 0, false
	}
	return i, true
}

// segmentImage reads the memory image out of one segment. The linker emits a
// single LCONST; DS and CONST are accepted so a hand-built segment works too.
func segmentImage(seg []byte, dispData int) []byte {
	p := dispData
	var img []byte
	for p < len(seg) {
		op := seg[p]
		if op == 0 {
			break
		}
		if op >= 1 && op <= 0xDF {
			img = append(img, seg[p+1:p+1+int(op)]...)
			p += 1 + int(op)
			continue
		}
		if op == 0xF2 && p+5 <= len(seg) {
			n := int(binary.LittleEndian.Uint32(seg[p+1:]))
			img = append(img, seg[p+5:p+5+n]...)
			p += 5 + n
			continue
		}
		if op == 0xF1 && p+5 <= len(seg) {
			n := int(binary.LittleEndian.Uint32(seg[p+1:]))
			img = append(img, make([]byte, n)...)
			p += 5
			continue
		}
		// Relocation records follow the image. The bytes gathered so far
		// are the memory image; the dictionary is not part of it.
		return img
	}
	return img
}

func findWindow(data, window []byte) int {
	if len(window) == 0 || len(window) > len(data) {
		return -1
	}
	for i := 0; i+len(window) <= len(data); i++ {
		match := true
		for j := range window {
			if data[i+j] != window[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
