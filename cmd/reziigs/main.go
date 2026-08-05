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
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/rez"
)

func main() {
	var input, out string
	var incDirs, defines []string
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
		case a == "-t" || a == "-c":
			i++ // ProDOS type / creator: file metadata, not fork content
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
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		if err := os.WriteFile(out+".rsrc", rez.Build(res), 0644); err != nil {
			die("%v", err)
		}
		return
	}
	if err := os.WriteFile(out, nil, 0644); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(out+".rsrc", rez.Build(res), 0644); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "reziigs: "+format+"\n", args...)
	os.Exit(1)
}
