package mpwmk

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

// runMakeLib reimplements MakeLibIIGS ("-l lib -r member.obj ..."), verified
// byte-identical against the original on the MSDos objects. The library is
// a dictionary segment followed by every member object verbatim with SEGNUM
// renumbered sequentially. The dictionary (KIND $0008, load name
// "XXXXXXXXXX", empty segment name, LENGTH 0) holds three LCONSTs:
//
//	1. filename table: [fileNum:2][pstring UPPERCASED path] per member
//	2. symbol entries: [nameDisp:4][fileNum:2][flags:2][libOffset:4] --
//	   flags is KIND & $4000 for a segment's own name and the GLOBAL/GEQU
//	   private byte for published symbols; libOffset is the file offset of
//	   the DEFINING segment within the library
//	3. names: the symbols' pstrings, in encounter order (segment name
//	   first, then its GLOBAL/GEQUs in record order)
func (e *Env) runMakeLib(args []string) error {
	var out string
	var members []string
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "-l":
			i++
			out = e.HostPath(args[i])
		case "-r":
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("makelibiigs: unsupported option %q", args[i])
			}
			members = append(members, e.HostPath(args[i]))
		}
	}
	if out == "" || len(members) == 0 {
		return fmt.Errorf("makelibiigs: need -l lib and members")
	}

	le := binary.LittleEndian
	type memberFile struct {
		path string
		data []byte
	}
	var files []memberFile
	for _, m := range members {
		d, err := os.ReadFile(m)
		if err != nil {
			return err
		}
		files = append(files, memberFile{m, d})
	}
	segments := func(d []byte) [][2]int {
		var out [][2]int
		for i := 0; i+4 <= len(d); {
			bc := int(le.Uint32(d[i:]))
			if bc == 0 {
				break
			}
			out = append(out, [2]int{i, bc})
			i += bc
		}
		return out
	}

	var fntab []byte
	for fi, f := range files {
		p := strings.ToUpper(f.path)
		fntab = le.AppendUint16(fntab, uint16(fi+1))
		fntab = append(fntab, byte(len(p)))
		fntab = append(fntab, p...)
	}

	const hdrLen = 0x37
	var names, entries []byte
	collect := func(dictSize int) {
		names, entries = nil, nil
		off := dictSize
		for fi, f := range files {
			for _, se := range segments(f.data) {
				seg := f.data[se[0] : se[0]+se[1]]
				kind := le.Uint16(seg[0x14:])
				dispName := int(le.Uint16(seg[0x28:]))
				dispData := int(le.Uint16(seg[0x2A:]))
				segOff := off + se[0]
				add := func(name []byte, flags uint16) {
					nd := len(names)
					names = append(append(names, byte(len(name))), name...)
					entries = le.AppendUint32(entries, uint32(nd))
					entries = le.AppendUint16(entries, uint16(fi+1))
					entries = le.AppendUint16(entries, flags)
					entries = le.AppendUint32(entries, uint32(segOff))
				}
				n := int(seg[dispName+10])
				add(seg[dispName+11:dispName+11+n], kind&0x4000)
				// GLOBAL/GEQU records inside the segment
				b := seg[dispData:]
				for j := 0; j < len(b) && b[j] != 0x00; {
					op := b[j]
					switch {
					case op >= 0x01 && op <= 0xDF:
						j += 1 + int(op)
					case op == 0xF2:
						j += 5 + int(le.Uint32(b[j+1:]))
					case op == 0xF1 || op == 0xE1:
						j += 5
					case op == 0xF3 || op == 0xED || op == 0xEB || op == 0xEE:
						k := j + 2
						if op == 0xEE {
							k = j + 6
						}
						for b[k] != 0x00 {
							switch b[k] {
							case 0x81, 0x80, 0x87:
								k += 5
							case 0x82, 0x83:
								k += 2 + int(b[k+1])
							default:
								k++
							}
						}
						j = k + 1
					case op == 0xE6:
						nl := int(b[j+1])
						add(b[j+2:j+2+nl], uint16(b[j+2+nl+3]))
						j += 2 + nl + 4
					case op == 0xE7:
						nl := int(b[j+1])
						k := j + 2 + nl + 4
						for b[k] != 0x00 {
							switch b[k] {
							case 0x81, 0x80, 0x87:
								k += 5
							case 0x82, 0x83:
								k += 2 + int(b[k+1])
							default:
								k++
							}
						}
						add(b[j+2:j+2+nl], uint16(b[j+2+nl+3]))
						j = k + 1
					default:
						j++
					}
				}
			}
			if se := segments(f.data); len(se) > 0 {
				off += se[len(se)-1][0] + se[len(se)-1][1]
			}
		}
	}
	dictSize := 0
	for range [4]int{} {
		collect(dictSize)
		n := hdrLen + (5 + len(fntab)) + (5 + len(entries)) + (5 + len(names)) + 1
		if n == dictSize {
			break
		}
		dictSize = n
	}

	hdr := make([]byte, hdrLen)
	le.PutUint32(hdr[0x00:], uint32(dictSize))
	hdr[0x0E] = 4
	hdr[0x0F] = 2
	le.PutUint16(hdr[0x14:], 0x0008)
	le.PutUint16(hdr[0x22:], 1)
	le.PutUint16(hdr[0x28:], 0x2C)
	le.PutUint16(hdr[0x2A:], hdrLen)
	copy(hdr[0x2C:], "XXXXXXXXXX")
	lib := append([]byte(nil), hdr...)
	for _, blob := range [][]byte{fntab, entries, names} {
		lib = append(lib, 0xF2)
		lib = le.AppendUint32(lib, uint32(len(blob)))
		lib = append(lib, blob...)
	}
	lib = append(lib, 0x00)
	segnum := 2
	for _, f := range files {
		d := append([]byte(nil), f.data...)
		total := 0
		for _, se := range segments(d) {
			le.PutUint16(d[se[0]+0x22:], uint16(segnum))
			segnum++
			total = se[0] + se[1]
		}
		lib = append(lib, d[:total]...)
	}
	_ = omf.RecEnd
	return os.WriteFile(out, lib, 0644)
}
