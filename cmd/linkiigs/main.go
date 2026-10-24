// linkiigs is a from-scratch reimplementation of the Apple MPW IIGS linker.
// Options may appear anywhere (MPW convention).
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/link"
	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

func main() {
	var inputs []string
	var out string
	var groups []link.Group
	var aliases map[string]string

	express := true
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-o":
			i++
			if i >= len(args) {
				die("missing argument to -o")
			}
			out = args[i]
		case a == "-lseg":
			// "-lseg NAME obj..." starts a named load segment
			i++
			if i >= len(args) {
				die("missing argument to -lseg")
			}
			groups = append(groups, link.Group{Name: args[i]})
		case strings.HasPrefix(strings.ToLower(a), "-lseg:"):
			// "-lseg:attr[:attr...] NAME" starts a load segment whose KIND
			// the attributes define outright ("-lseg:dynamic", "-lseg:$3000")
			kind, dyn, err := link.SegKindAttrs(a[len("-lseg:"):])
			if err != nil {
				die("linkiigs %s: %v", a, err)
			}
			i++
			if i >= len(args) {
				die("missing argument to %s", a)
			}
			groups = append(groups, link.Group{Name: args[i], Dynamic: dyn,
				Kind: kind, KindSet: true})
		case a == "-a":
			// "-a old=new" aliases a symbol REFERENCE (link.SetAliases)
			i++
			if i >= len(args) {
				die("Alias missing after -a option")
			}
			old, new, ok := strings.Cut(args[i], "=")
			if !ok {
				die("Unknown option (-A %s) specified", args[i])
			}
			if aliases == nil {
				aliases = map[string]string{}
			}
			aliases[old] = new
		case a == "-apw": // accepted, no output-form effect

		case a == "-x":
			express = false // no ~ExpressLoad segment
		case a == "-l":
			// listing flag: no effect on the image
		case a == "-relocs":
			// "-relocs 1.2" reproduces the public LinkIIGS 1.2 encoding
			i++
			if i >= len(args) {
				die("missing argument to -relocs")
			}
			enc, err := link.ParseRelocEncoding(args[i])
			if err != nil {
				die("linkiigs: %v", err)
			}
			link.SetRelocEncoding(enc)
		case a == "-version":
			fmt.Printf("linkiigs %s\n", link.Version)
			return
		case strings.HasPrefix(a, "-"):
			die("unsupported option %q", a)
		case len(groups) > 0:
			sel, err := parseSel(a)
			if err != nil {
				die("%v", err)
			}
			groups[len(groups)-1].Sels = append(groups[len(groups)-1].Sels, sel)
		default:
			inputs = append(inputs, a)
		}
	}
	link.SetAliases(aliases)
	if out == "" || (len(inputs) == 0 && len(groups) == 0) {
		die("usage: linkiigs file.obj... -o file")
	}
	if len(groups) > 0 {
		res, err := link.LinkGroups(groups, express)
		if err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(out, res, 0644); err != nil {
			die("%v", err)
		}
		return
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
	res, err := link.LinkOpts(objs, express)
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(out, res, 0644); err != nil {
		die("%v", err)
	}
}

// parseSel reads an input spec, which may select one segment of an object
// file: "scm.obj(@oscall_seg)". One parsed *omf.File is shared across all
// selections of the same path so the linker's own-file symbol tier sees the
// whole file.
var selCache = map[string]*omf.File{}

func parseSel(a string) (link.Sel, error) {
	name, seg := a, ""
	if i := strings.Index(a, "("); i >= 0 && strings.HasSuffix(a, ")") {
		name = a[:i]
		seg = strings.TrimPrefix(a[i+1:len(a)-1], "@")
	}
	if f, ok := selCache[name]; ok {
		return link.Sel{File: f, Seg: seg}, nil
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return link.Sel{}, err
	}
	f, err := omf.Parse(data)
	if err != nil {
		return link.Sel{}, fmt.Errorf("%s: %w", name, err)
	}
	selCache[name] = f
	return link.Sel{File: f, Seg: seg}, nil
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
