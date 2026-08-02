package mpwmk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dagenbrock/iigs-tools/asm"
	"github.com/dagenbrock/iigs-tools/link"
	"github.com/dagenbrock/iigs-tools/omf"
)

// dispatch runs one command: MPW built-ins and the IIgs cross tools.
func (e *Env) dispatch(name string, args []string, out io.Writer) error {
	switch name {
	// ---- MPW shell built-ins ----
	case "echo":
		fmt.Fprintln(out, strings.Join(args, " "))
		return nil
	case "directory":
		if len(args) == 0 {
			fmt.Fprintln(out, e.Dir)
			return nil
		}
		e.Dir = e.HostPath(args[0])
		return nil
	case "newfolder", "mkdir":
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if err := os.MkdirAll(e.HostPath(a), 0755); err != nil {
				return err
			}
		}
		return nil
	case "delete":
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			os.RemoveAll(e.HostPath(a))
		}
		return nil
	case "duplicate", "dup", "duplicateiigs":
		return e.duplicate(args)
	case "catenate":
		return e.catenate(args, out)
	case "rename":
		var ps []string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				ps = append(ps, e.HostPath(a))
			}
		}
		if len(ps) != 2 {
			return fmt.Errorf("rename needs two paths")
		}
		return os.Rename(ps[0], ps[1])
	case "setfile", "setfileiigs", "rez", "setversion", "backup", "target",
		"open", "beep", "alert", "search", "addmenu", "unset", "export",
		"exists", "confirm", "date", "files":
		// no object-file effect for our builds (metadata/UI/VCS commands)
		return nil
	case "set":
		if len(args) >= 2 {
			e.Set(args[0], strings.Join(args[1:], " "))
		}
		return nil
	case "exit":
		return nil

	// ---- IIgs cross tools ----
	case "asmiigs":
		return e.runAsm(args)
	case "linkiigs":
		return e.runLink(args)
	case "makebiniigs":
		return e.runMakeBin(args)
	case "reziigs", "dereziigs", "expressiigs", "makelibiigs", "overlayiigs",
		"pascaliigs", "ciigs", "tmlpascal", "asmmatiigs":
		return fmt.Errorf("%s: not implemented yet", name)
	}
	return fmt.Errorf("unknown command %q", name)
}

// logAsm appends one assembly to the file named by MPWMK_TOOLLOG, with every
// path already resolved to the host filesystem. It exists so a build can be
// replayed against the original AsmIIGS with the arguments the makefiles
// actually produced: assembling a source "naively" gets its include paths and
// -d defines wrong, and a byte-diff against that is meaningless.
//
// Record: input, output, then "-i dir" / "-d define" pairs and any other
// flags verbatim, tab-separated. The other flags matter: hfs.fst.main only
// assembles under "-unsafe".
func (e *Env) logAsm(input, output string, incDirs, defines, extras []string) {
	path := os.Getenv("MPWMK_TOOLLOG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	rec := []string{"asm", input, output}
	for _, d := range incDirs {
		rec = append(rec, "-i", d)
	}
	for _, d := range defines {
		rec = append(rec, "-d", d)
	}
	rec = append(rec, extras...)
	fmt.Fprintln(f, strings.Join(rec, "\t"))
}

// logLink records a link the same way as logAsm, with every input path
// resolved and the "-lseg NAME file(@seg)" grouping preserved: the GS/OS
// kernel's shape comes entirely from that grouping, so replaying it verbatim
// is the only way to check our linker against the original.
func (e *Env) logLink(rec []string) {
	path := os.Getenv("MPWMK_TOOLLOG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, strings.Join(append([]string{"link"}, rec...), "\t"))
}

func (e *Env) duplicate(args []string) error {
	var ps []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		ps = append(ps, a)
	}
	if len(ps) < 2 {
		return fmt.Errorf("duplicate needs source and destination")
	}
	dst := e.HostPath(ps[len(ps)-1])
	for _, src := range ps[:len(ps)-1] {
		sp := e.HostPath(src)
		data, err := os.ReadFile(sp)
		if err != nil {
			return err
		}
		target := dst
		if fi, err := os.Stat(dst); err == nil && fi.IsDir() {
			target = filepath.Join(dst, filepath.Base(sp))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func (e *Env) catenate(args []string, out io.Writer) error {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		data, err := os.ReadFile(e.HostPath(a))
		if err != nil {
			return err
		}
		if _, err := out.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// ---- tool front ends (same option grammar as the MPW tools) ----

func (e *Env) runAsm(args []string) error {
	var input, output string
	var incDirs []string
	var defines []string
	var extras []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; strings.ToLower(a) {
		case "-o":
			i++
			output = e.HostPath(args[i])
		case "-i":
			i++
			for _, d := range strings.Split(args[i], ",") {
				incDirs = append(incDirs, e.HostPath(d))
			}
		case "-d":
			i++
			defines = append(defines, args[i])
		case "-l", "-m", "-lo", "-pagesize", "-font", "-print":
			i++ // listing options with an argument: ignored
		case "-t", "-h", "-w", "-wt", "-wi", "-unsafe", "-c":
			extras = append(extras, a) // no argument; recorded for replay
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("asmiigs: unsupported option %q", a)
			}
			input = e.HostPath(a)
		}
	}
	if input == "" {
		return fmt.Errorf("asmiigs: no input file")
	}
	if output == "" {
		output = input + ".obj" // AsmIIGS default output name
	}
	// The real AsmIIGS finds the toolbox interface files through the
	// {AIIGSIncludes} shell variable; make that automatic.
	if d := e.Get("aiigsincludes"); d != "" {
		incDirs = append(incDirs, e.HostPath(d))
	}
	e.logAsm(input, output, incDirs, defines, extras)
	obj, err := asm.AssembleFileOpts(input, incDirs, defines)
	if err != nil {
		return fmt.Errorf("asmiigs %s: %w", filepath.Base(input), err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	return os.WriteFile(output, obj.WriteOMF(), 0644)
}

// linkSel resolves an input spec that may select one segment of an object
// file: "{Object}scm.obj(@oscall_seg)".
func (e *Env) linkSel(a string) (link.Sel, error) {
	name, seg := a, ""
	if i := strings.Index(a, "("); i >= 0 && strings.HasSuffix(a, ")") {
		name, seg = a[:i], strings.TrimPrefix(a[i+1:len(a)-1], "@")
	}
	p := e.HostPath(name)
	data, err := os.ReadFile(p)
	if err != nil {
		return link.Sel{}, err
	}
	f, err := omf.Parse(data)
	if err != nil {
		return link.Sel{}, fmt.Errorf("%s: %w", filepath.Base(p), err)
	}
	return link.Sel{File: f, Seg: seg}, nil
}

func (e *Env) runLink(args []string) error {
	var inputs []string
	var output string
	var groups []link.Group
	var log []string
	apw := false
	express := true
	for i := 0; i < len(args); i++ {
		switch a := args[i]; strings.ToLower(a) {
		case "-o":
			i++
			output = e.HostPath(args[i])
			log = append(log, "-o", output)
		case "-lseg":
			// "-lseg NAME obj..." starts a named load segment
			i++
			groups = append(groups, link.Group{Name: args[i]})
			log = append(log, "-lseg", args[i])
		case "-apw":
			apw = true
			log = append(log, "-apw")
		case "-t", "-at", "-org", "-lib", "-s":
			i++ // consume the option's argument (type/aux stamping is metadata)
		case "-x":
			express = false // no ~ExpressLoad segment
			log = append(log, "-x")
		case "-w", "-l":
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("linkiigs: unsupported option %q", a)
			}
			if len(groups) > 0 {
				sel, err := e.linkSel(a)
				if err != nil {
					return fmt.Errorf("linkiigs: %w", err)
				}
				groups[len(groups)-1].Sels = append(groups[len(groups)-1].Sels, sel)
				name, seg := a, ""
				if j := strings.Index(a, "("); j >= 0 && strings.HasSuffix(a, ")") {
					name, seg = a[:j], a[j:]
				}
				log = append(log, e.HostPath(name)+seg)
				continue
			}
			inputs = append(inputs, e.HostPath(a))
			log = append(log, e.HostPath(a))
		}
	}
	e.logLink(log)
	if output == "" || (len(inputs) == 0 && len(groups) == 0) {
		return fmt.Errorf("linkiigs: need inputs and -o output")
	}
	if len(groups) > 0 {
		res, err := link.LinkGroups(groups, apw)
		if err != nil {
			return fmt.Errorf("linkiigs: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
			return err
		}
		return os.WriteFile(output, res, 0644)
	}
	var objs []*omf.File
	for _, p := range inputs {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := omf.Parse(data)
		if err != nil {
			return fmt.Errorf("linkiigs %s: %w", filepath.Base(p), err)
		}
		objs = append(objs, f)
	}
	res, err := link.LinkOpts(objs, express)
	if err != nil {
		return fmt.Errorf("linkiigs: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	return os.WriteFile(output, res, 0644)
}

func (e *Env) runMakeBin(args []string) error {
	var input, output string
	org := int64(-1)
	for i := 0; i < len(args); i++ {
		switch a := args[i]; strings.ToLower(a) {
		case "-o":
			i++
			output = e.HostPath(args[i])
		case "-org":
			i++
			v, err := parseMPWNum(args[i])
			if err != nil {
				return err
			}
			org = v
		case "-t":
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("makebiniigs: unsupported option %q", a)
			}
			input = e.HostPath(a)
		}
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	f, err := omf.Parse(data)
	if err != nil {
		return err
	}
	// A load file with several load segments becomes one .bin per segment:
	// "scm.bin", "scm.bin.2", "scm.bin.3", ... which is how make.os then
	// catenates the pieces of GS.OS together.
	var segs []*omf.Segment
	for i := range f.Segments {
		if f.Segments[i].SegName != "~ExpressLoad" {
			segs = append(segs, &f.Segments[i])
		}
	}
	if len(segs) > 1 {
		if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
			return err
		}
		for i, s := range segs {
			name := output
			if i > 0 {
				name = fmt.Sprintf("%s.%d", output, i+1)
			}
			img := omf.SegmentImage(s)
			at := int64(s.Org)
			if org >= 0 {
				at = org
			}
			omf.Relocate(s, img, at)
			if err := os.WriteFile(name, img, 0644); err != nil {
				return err
			}
		}
		return nil
	}
	img, base := flatten(f, org)
	_ = base
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	return os.WriteFile(output, img, 0644)
}

func flatten(f *omf.File, orgFlag int64) ([]byte, int64) {
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
		seg := omf.SegmentImage(s)
		omf.Relocate(s, seg, org)
		if need := off + int64(len(seg)); need > int64(len(img)) {
			img = append(img, make([]byte, need-int64(len(img)))...)
		}
		copy(img[off:], seg)
	}
	return img, base
}

func parseMPWNum(s string) (int64, error) {
	if strings.HasPrefix(s, "$") {
		return strconv.ParseInt(s[1:], 16, 64)
	}
	return strconv.ParseInt(s, 10, 64)
}
