// linkiigs is a from-scratch reimplementation of the Apple MPW IIGS linker.
// Options may appear anywhere (MPW convention).
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dagenbrock/iigs-tools/link"
	"github.com/dagenbrock/iigs-tools/omf"
)

func main() {
	var inputs []string
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
		case strings.HasPrefix(a, "-"):
			die("unsupported option %q", a)
		default:
			inputs = append(inputs, a)
		}
	}
	if len(inputs) == 0 || out == "" {
		die("usage: linkiigs file.obj... -o file")
	}
	var objs []*omf.File
	for _, p := range inputs {
		data, err := os.ReadFile(p)
		if err != nil {
			die("%v", err)
		}
		f, err := omf.Parse(data)
		if err != nil {
			die("%s: %v", p, err)
		}
		objs = append(objs, f)
	}
	res, err := link.Link(objs)
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(out, res, 0644); err != nil {
		die("%v", err)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
