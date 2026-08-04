package mpwmk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/asm"
	"github.com/dagenbrock/iigs-programmers-workshop/link"
	"github.com/dagenbrock/iigs-programmers-workshop/omf"
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
	case "overlayiigs":
		// "OverlayIIGS src dst -a $off" copies src over dst at file offset
		// off, extending dst as needed -- make.p8 assembles the P8 image
		// this way (the $0C80 loader boundary matches mlisrc's own assert).
		// The tool is not in the recovered MPW IIGS set; the shipped P8
		// byte-validates these semantics.
		var ps []string
		off := int64(-1)
		for i := 0; i < len(args); i++ {
			if strings.ToLower(args[i]) == "-a" && i+1 < len(args) {
				v, err := parseMPWNum(args[i+1])
				if err != nil {
					return err
				}
				off = v
				i++
				continue
			}
			if !strings.HasPrefix(args[i], "-") {
				ps = append(ps, e.HostPath(args[i]))
			}
		}
		if len(ps) != 2 || off < 0 {
			return fmt.Errorf("overlayiigs: need src dst -a offset")
		}
		src, err := os.ReadFile(ps[0])
		if err != nil {
			return err
		}
		dst, err := os.ReadFile(ps[1])
		if err != nil {
			return err
		}
		if need := off + int64(len(src)); need > int64(len(dst)) {
			dst = append(dst, make([]byte, need-int64(len(dst)))...)
		}
		copy(dst[off:], src)
		return os.WriteFile(ps[1], dst, 0644)
	case "makelibiigs":
		return e.runMakeLib(args)
	case "reziigs", "dereziigs", "expressiigs",
		"pascaliigs", "ciigs", "tmlpascal", "asmmatiigs":
		return fmt.Errorf("%s: not implemented yet", name)

	// ---- the Aristotle display.0 patch (make.aristotle) ----
	// PatchTool is a MAC-side MPW C tool whose whole job is three writes
	// (NetBoot/AristotlePatch/main.c); its build chain (the 68K "C" and
	// "Link") only exists to produce it, so stub those and do the patch
	// natively when the tool is invoked.
	case "c":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return os.WriteFile(e.HostPath(a)+".o", nil, 0644)
			}
		}
		return nil
	case "link":
		for i := 0; i < len(args); i++ {
			if strings.ToLower(args[i]) == "-o" && i+1 < len(args) {
				return os.WriteFile(e.HostPath(args[i+1]), nil, 0644)
			}
		}
		return nil
	}
	if strings.EqualFold(filepath.Base(strings.ReplaceAll(name, ":", "/")), "patchtool") {
		return e.patchTool(args)
	}
	return fmt.Errorf("unknown command %q", name)
}

// patchTool reimplements NetBoot/AristotlePatch/main.c: patch the jump at
// offset 1 to CodeAddr $6B92, stamp version "1.0.1 " at $5DB0, and copy the
// patch code over the file starting at $6392.
func (e *Env) patchTool(args []string) error {
	var ps []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			ps = append(ps, e.HostPath(a))
		}
	}
	if len(ps) != 2 {
		return fmt.Errorf("patchtool: need oldfile and patchfile")
	}
	old, err := os.ReadFile(ps[0])
	if err != nil {
		return err
	}
	patch, err := os.ReadFile(ps[1])
	if err != nil {
		return err
	}
	const codeAddr, versionLoc, codeOffset = 0x6B92, 0x5DB0, 0x6392
	if need := codeOffset + len(patch); need > len(old) {
		old = append(old, make([]byte, need-len(old))...)
	}
	old[1] = byte(codeAddr & 0xFF)
	old[2] = byte(codeAddr >> 8)
	copy(old[versionLoc:], "1.0.1 ")
	copy(old[codeOffset:], patch)
	return os.WriteFile(ps[0], old, 0644)
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
	var outIsDir bool
	var incDirs []string
	var defines []string
	var extras []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; strings.ToLower(a) {
		case "-o":
			i++
			outIsDir = strings.HasSuffix(args[i], ":")
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
	} else if outIsDir {
		// "-o :objs:" names a directory: the object keeps its default name
		// there (QDAux assembles every source with "asmiigs -o :objs: X.asm")
		output = filepath.Join(output, filepath.Base(input)+".obj")
	}
	// The real AsmIIGS finds the toolbox interface files through the
	// {AIIGSIncludes} shell variable; make that automatic.
	if d := e.Get("aiigsincludes"); d != "" {
		incDirs = append(incDirs, e.HostPath(d))
	}
	e.logAsm(input, output, incDirs, defines, extras)
	obj, err := asm.AssembleFileWith(input, asm.FileOpts{
		IncDirs: incDirs,
		Defines: defines,
		CurDir:  e.Dir,
		Getenv:  e.Get,
	})
	if err != nil {
		return fmt.Errorf("asmiigs %s: %w", filepath.Base(input), err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	return os.WriteFile(output, obj.WriteOMF(), 0644)
}

// linkSel resolves an input spec that may select one segment of an object
// file: "{Object}scm.obj(@oscall_seg)". The cache keeps one parsed *omf.File
// per path across a link's selections: the linker's own-file symbol tier is
// keyed by file identity, and gquit.obj(@seg_e0) must see the DISPLAY_MSG
// that gquit.obj(@seg_b0) carries, not a same-named segment from another
// file (oracle-verified in scm.lnk).
func (e *Env) linkSel(a string, cache map[string]*omf.File) (link.Sel, error) {
	name, segs := splitSelSpec(a)
	p := e.HostPath(name)
	if f, ok := cache[p]; ok {
		return link.Sel{File: f, Segs: segs}, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return link.Sel{}, err
	}
	f, err := omf.Parse(data)
	if err != nil {
		return link.Sel{}, fmt.Errorf("%s: %w", filepath.Base(p), err)
	}
	cache[p] = f
	return link.Sel{File: f, Segs: segs}, nil
}

// splitSelSpec splits an input spec into its path and the segment names it
// selects. Both MPW forms are accepted: the GS/OS makefiles' single
// "scm.obj(@oscall_seg)" and the toolbox's comma list,
// "cursor.obj(SETCURSOR,SHIFTONE,...)" -- MIDISynth and the MIDI tools pull
// named segments out of shared objects that way. A trailing comma is allowed.
func splitSelSpec(a string) (string, []string) {
	i := strings.Index(a, "(")
	if i < 0 || !strings.HasSuffix(a, ")") {
		return a, nil
	}
	var segs []string
	for _, n := range strings.Split(a[i+1:len(a)-1], ",") {
		if n = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "@")); n != "" {
			segs = append(segs, n)
		}
	}
	return a[:i], segs
}

func (e *Env) runLink(args []string) error {
	var inputs, rawInputs []string
	var libs []string
	var output string
	var groups []link.Group
	var log []string
	selCache := map[string]*omf.File{}
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
			// accepted for compatibility; the oracle emits the same
			// ~ExpressLoad form with or without it (scm.lnk replay)
			log = append(log, "-apw")
		case "-lib":
			i++
			libs = append(libs, e.HostPath(args[i]))
			log = append(log, "-lib", e.HostPath(args[i]))
		case "-t", "-at", "-org", "-s":
			i++ // consume the option's argument (type/aux stamping is metadata)
		case "-x":
			express = false // no ~ExpressLoad segment
			log = append(log, "-x")
		case "-w", "-l":
		default:
			// "-lseg:attr[:attr...] NAME" starts a load segment whose KIND the
			// attributes define outright (see segKindAttrs)
			if strings.HasPrefix(strings.ToLower(a), "-lseg:") {
				kind, dyn, err := segKindAttrs(a[len("-lseg:"):])
				if err != nil {
					return fmt.Errorf("linkiigs %s: %w", a, err)
				}
				i++
				groups = append(groups, link.Group{Name: args[i], Dynamic: dyn,
					Kind: kind, KindSet: true})
				log = append(log, a, args[i])
				continue
			}
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("linkiigs: unsupported option %q", a)
			}
			if len(groups) > 0 {
				sel, err := e.linkSel(a, selCache)
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
			rawInputs = append(rawInputs, a)
			log = append(log, e.HostPath(a))
		}
	}
	e.logLink(log)
	if output == "" || (len(inputs) == 0 && len(groups) == 0) {
		return fmt.Errorf("linkiigs: need inputs and -o output")
	}
	if len(groups) > 0 && len(rawInputs) > 0 {
		// objects listed before any -lseg form an implicit leading "main"
		// load segment (oracle: Tool016's six ungrouped objects)
		main := link.Group{Name: "main"}
		for _, a := range rawInputs {
			sel, err := e.linkSel(a, selCache)
			if err != nil {
				return fmt.Errorf("linkiigs: %w", err)
			}
			main.Sels = append(main.Sels, sel)
		}
		groups = append([]link.Group{main}, groups...)
	}
	if len(groups) > 0 {
		res, err := link.LinkGroups(groups, express)
		if err != nil {
			return fmt.Errorf("linkiigs: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
			return err
		}
		return os.WriteFile(output, res, 0644)
	}
	// An ungrouped input may still select segments -- MIDISynth links
	// "cursor.obj(SETCURSOR,SHIFTONE,...)" straight into the main segment --
	// so filter the parsed file down to what was named.
	var objs []*omf.File
	for _, spec := range inputs {
		p, segs := splitSelSpec(spec)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := omf.Parse(data)
		if err != nil {
			return fmt.Errorf("linkiigs %s: %w", filepath.Base(p), err)
		}
		if len(segs) > 0 {
			sel := link.Sel{Segs: segs}
			kept := &omf.File{}
			for i := range f.Segments {
				if sel.Wants(&f.Segments[i]) {
					kept.Segments = append(kept.Segments, f.Segments[i])
				}
			}
			f = kept
		}
		objs = append(objs, f)
	}
	// "-lib X.lib": pull the library segments the objects need
	for _, p := range libs {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := omf.Parse(data)
		if err != nil {
			return fmt.Errorf("linkiigs %s: %w", filepath.Base(p), err)
		}
		if sel := link.SelectLib(objs, f); sel != nil {
			objs = append(objs, sel)
		}
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
	if output == "" {
		// "MakeBinIIGS file" with no -o converts the load file IN PLACE
		// (make.atinit does this to ATINIT).
		output = input
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

// segKindAttrs turns a "-lseg:" attribute list into an OMF KIND. The
// attributes REPLACE whatever kind the group would inherit from its first
// object segment (oracle-probed: a $4000 object becomes $0000 under
// "-lseg:code" and $1000 under "-lseg:code:nospecial:static"). The flag bits
// are the standard OMF ones; only those the sources actually use are
// accepted, so a new one shows up as an error rather than silently doing
// nothing.
func segKindAttrs(spec string) (uint16, bool, error) {
	var kind uint16
	dyn := false
	for _, a := range strings.Split(spec, ":") {
		switch strings.ToLower(strings.TrimSpace(a)) {
		case "", "code", "static", "public", "special", "reloadable":
			// type 0 and the cleared-flag spellings: nothing to set
		case "data":
			kind |= 0x0001
		case "dynamic":
			kind |= 0x8000
			dyn = true
		case "private":
			kind |= 0x4000
		case "nospecial":
			kind |= 0x1000
		case "posindependent", "pic":
			kind |= 0x2000
		case "bankrelative":
			kind |= 0x0100
		case "skip":
			kind |= 0x0200
		case "reload":
			kind |= 0x0400
		case "absolutebank":
			kind |= 0x0800
		default:
			return 0, false, fmt.Errorf("unknown -lseg attribute %q", a)
		}
	}
	return kind, dyn, nil
}
