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
			// flags without arguments
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
	apw := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; strings.ToLower(a) {
		case "-o":
			i++
			output = e.HostPath(args[i])
		case "-lseg":
			// "-lseg NAME obj..." starts a named load segment
			i++
			groups = append(groups, link.Group{Name: args[i]})
		case "-apw":
			apw = true
		case "-t", "-at", "-org", "-lib", "-s":
			i++ // consume the option's argument (type/aux stamping is metadata)
		case "-x", "-w", "-l":
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
				continue
			}
			inputs = append(inputs, e.HostPath(a))
		}
	}
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
	res, err := link.Link(objs)
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
			if err := os.WriteFile(name, omf.SegmentImage(s), 0644); err != nil {
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
