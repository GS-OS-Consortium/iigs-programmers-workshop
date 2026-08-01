// asmiigs is a from-scratch reimplementation of the Apple MPW IIGS 65816
// cross-assembler. Byte-compatibility with the original is developed by
// continuous diffing against AsmIIGS 1.2 under emulation.
//
// Like the original MPW tool, options may appear anywhere on the command line.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dagenbrock/iigs-tools/asm"
)

func main() {
	var inputs []string
	var incDirs []string
	var out string
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
		case a == "-h" || a == "-wt" || a == "-wi" || a == "-w" || a == "-t" || a == "-unsafe":
			// accepted, no behavioral difference implemented yet
		case strings.HasPrefix(a, "-"):
			die("unsupported option %q", a)
		default:
			inputs = append(inputs, a)
		}
	}
	if len(inputs) != 1 || out == "" {
		die("usage: asmiigs [options] file.aii -o file.obj")
	}
	obj, err := asm.AssembleFile(inputs[0], incDirs...)
	if err != nil {
		die("%s:\n%v", inputs[0], err)
	}
	if err := os.WriteFile(out, obj.WriteOMF(), 0644); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
