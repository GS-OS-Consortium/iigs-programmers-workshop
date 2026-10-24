// reziigs is a from-scratch reimplementation of the Apple MPW IIGS resource
// compiler (RezIIGS). It reads Rez source and writes an Apple IIgs resource
// file.
//
// The compiled resources belong in the file's RESOURCE fork. Since most
// modern filesystems have no forks, the fork is written to a sidecar
// "<output>.rsrc"; the data fork (usually empty) is written to <output>
// itself. tools/make-disk.py pairs the two back up as NAPS when building a
// disk image.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/rez"
)

func main() {
	var input, out string
	var incDirs, defines []string
	var memo *rez.Memo
	var fileType [4]byte
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-o":
			i++
			if i >= len(args) {
				die("missing argument to -o")
			}
			out = args[i]
		case a == "-i":
			i++
			if i >= len(args) {
				die("missing argument to -i")
			}
			incDirs = append(incDirs, strings.Split(args[i], ",")...)
		case a == "-t":
			// ProDOS type: file metadata, not fork content -- unless -memo
			// stamps it into rFileMemo the way DuplicateIIGS -mac did
			i++
			if i >= len(args) {
				die("missing argument to -t")
			}
			if t, err := strconv.ParseUint(strings.TrimPrefix(args[i], "$"), 16, 8); err == nil && strings.HasPrefix(args[i], "$") {
				fileType = rez.FileTypeField(byte(t), 0)
			} else {
				copy(fileType[:], fmt.Sprintf("%-4s", args[i]))
			}
		case a == "-c":
			i++ // creator: file metadata, not fork content
		case a == "-memo":
			// "-memo NAME" fills rFileMemo as DuplicateIIGS -mac NAME would
			i++
			if i >= len(args) {
				die("missing argument to -memo")
			}
			memo = &rez.Memo{Name: args[i], Creator: [4]byte{'p', 'd', 'o', 's'}, Const: 2}
		case a == "-memodate":
			// Mac-epoch seconds (decimal or $hex) for the memo's creation time
			i++
			if i >= len(args) {
				die("missing argument to -memodate")
			}
			if memo == nil {
				die("-memodate needs -memo first")
			}
			s := args[i]
			base := 10
			if strings.HasPrefix(s, "$") {
				s, base = s[1:], 16
			}
			v, err := strconv.ParseUint(s, base, 32)
			if err != nil {
				die("bad -memodate %q", args[i])
			}
			memo.Created = uint32(v)
		case a == "-d":
			i++
			if i >= len(args) {
				die("missing argument to -d")
			}
			defines = append(defines, args[i])
		case a == "-rd" || a == "-p" || a == "-ov":
			// -rd: no redeclaration warnings; -p: progress; -ov: overwrite
		case strings.HasPrefix(a, "-"):
			die("unsupported option %q", a)
		default:
			input = a
		}
	}
	if input == "" || out == "" {
		die("usage: reziigs [-i dir] file.r -o outfile")
	}

	res, err := rez.Compile(input, incDirs, defines...)
	if err != nil {
		die("%v", err)
	}
	fork := rez.Build(res)
	if memo != nil {
		memo.FileType = fileType
		if err := rez.StampMemo(fork, *memo); err != nil {
			die("%v", err)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		if err := os.WriteFile(out+".rsrc", fork, 0644); err != nil {
			die("%v", err)
		}
		return
	}
	if err := os.WriteFile(out, nil, 0644); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(out+".rsrc", fork, 0644); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "reziigs: "+format+"\n", args...)
	os.Exit(1)
}
