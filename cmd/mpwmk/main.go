// mpwmk runs Apple MPW makefiles (the GS/OS build files) natively.
//
//	mpwmk -f MakeFiles/make.pro.fst -vars Scripts/GSOSvariables -set GSOS=... [target...]
//
// Options:
//
//	-f file      makefile to run (required)
//	-vars file   MPW variables script to load first (repeatable)
//	-set N=V     set a variable (repeatable)
//	-C dir       working directory
//	-n           dry run: print commands without running them
//	-v           verbose: print targets and commands
//	-list        list the makefile's targets and exit
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/mpwmk"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	var makefile, dir string
	var varFiles, sets, targets multi
	verbose, dryRun, list := false, false, false

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-f":
			i++
			makefile = need(args, i)
		case "-vars":
			i++
			varFiles.Set(need(args, i))
		case "-set":
			i++
			sets.Set(need(args, i))
		case "-C":
			i++
			dir = need(args, i)
		case "-n":
			dryRun = true
		case "-v":
			verbose = true
		case "-list":
			list = true
		case "-e", "-s", "-p", "-r", "-t", "-u", "-w", "-y", "-d":
			// accepted MPW Make flags with no effect here
		default:
			if strings.HasPrefix(a, "-") {
				die("unsupported option %q", a)
			}
			targets.Set(a)
		}
	}
	if makefile == "" {
		die("usage: mpwmk -f makefile [-vars file] [-set N=V] [-C dir] [-n] [-v] [target...]")
	}
	if dir == "" {
		dir = filepath.Dir(makefile)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		die("%v", err)
	}

	env := mpwmk.NewEnv(abs)
	env.Verbose = verbose || dryRun
	env.DryRun = dryRun
	for _, vf := range varFiles {
		if err := env.LoadVariables(vf); err != nil {
			die("loading %s: %v", vf, err)
		}
	}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			die("bad -set %q (want NAME=VALUE)", s)
		}
		env.Set(k, v)
	}

	data, err := os.ReadFile(makefile)
	if err != nil {
		die("%v", err)
	}
	mf, err := mpwmk.ParseMakefile(mpwmk.DecodeText(data))
	if err != nil {
		die("%s: %v", makefile, err)
	}
	b := mpwmk.NewBuilder(env, mf)

	if list {
		for _, t := range b.Targets() {
			fmt.Printf("%-40s -> %s\n", t, env.HostPath(t))
		}
		return
	}
	if len(targets) == 0 {
		t := b.DefaultTarget()
		if t == "" {
			die("%s: no rules", makefile)
		}
		targets = multi{t}
	}
	for _, t := range targets {
		if err := b.Build(t); err != nil {
			die("%v", err)
		}
	}
}

func need(args []string, i int) string {
	if i >= len(args) {
		die("missing argument after %q", args[i-1])
	}
	return args[i]
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
