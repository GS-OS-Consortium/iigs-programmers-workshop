// makebiniigs converts an OMF load file into a flat memory-image binary
// (the MPW IIGS MakeBinIIGS tool). ~ExpressLoad directory segments are
// skipped; each remaining segment's initialized image is emitted, DS
// reservations zero-filled. -org sets the base address for placement.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

func main() {
	var inputs []string
	var out string
	var orgFlag int64 = -1
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-o":
			i++
			if i >= len(args) {
				die("missing argument to -o")
			}
			out = args[i]
		case a == "-org":
			i++
			if i >= len(args) {
				die("missing argument to -org")
			}
			v, err := parseNum(args[i])
			if err != nil {
				die("bad -org: %v", err)
			}
			orgFlag = v
		case strings.HasPrefix(a, "-"):
			die("unsupported option %q", a)
		default:
			inputs = append(inputs, a)
		}
	}
	if len(inputs) != 1 || out == "" {
		die("usage: makebiniigs [-org $addr] file -o binfile")
	}
	data, err := os.ReadFile(inputs[0])
	if err != nil {
		die("%v", err)
	}
	f, err := omf.Parse(data)
	if err != nil {
		die("%s: %v", inputs[0], err)
	}

	base := int64(-1)
	var img []byte
	for i := range f.Segments {
		s := &f.Segments[i]
		if s.SegName == "~ExpressLoad" {
			continue
		}
		org := int64(s.Org)
		if orgFlag >= 0 && base < 0 {
			org = orgFlag
		}
		if base < 0 {
			base = org
		}
		off := org - base
		seg := segImage(s)
		if need := off + int64(len(seg)); need > int64(len(img)) {
			img = append(img, make([]byte, need-int64(len(img)))...)
		}
		copy(img[off:], seg)
	}
	if err := os.WriteFile(out, img, 0644); err != nil {
		die("%v", err)
	}
}

func segImage(s *omf.Segment) []byte {
	var img []byte
	for _, r := range s.Records {
		switch {
		case r.Op >= 0x01 && r.Op <= 0xDF:
			img = append(img, r.Raw[1:]...)
		case r.Op == omf.RecLconst:
			img = append(img, r.Raw[5:]...)
		case r.Op == omf.RecDS:
			img = append(img, make([]byte, binary.LittleEndian.Uint32(r.Raw[1:]))...)
		}
	}
	return img
}

func parseNum(s string) (int64, error) {
	if strings.HasPrefix(s, "$") {
		return strconv.ParseInt(s[1:], 16, 64)
	}
	return strconv.ParseInt(s, 10, 64)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
