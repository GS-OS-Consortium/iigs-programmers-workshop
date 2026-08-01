// Package asm is a from-scratch reimplementation of the Apple MPW IIGS
// assembler (AsmIIGS): MPW-syntax 65816 macro assembler emitting OMF v2
// object files. Behavior is developed by byte-diffing against the original
// assembler running under emulation; oracle-established rules are noted
// throughout.
package asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------- actions (pass 1 output, pass 2 input) ----------

type actKind int

const (
	aBytes  actKind = iota // fully resolved bytes
	aBranch                // relative branch to a label (resolved in pass 2)
	aExpr                  // OMF expression record reference (label +- const)
	aDS                    // reserve space (DS record)
	aDefer                 // expression that failed pass-1 eval (forward refs
	//                        in non-linear contexts); re-evaluated in pass 2
	aRec // raw OMF record bytes (e.g. GLOBAL from ENTRY), zero code size
)

type action struct {
	kind   actKind
	bytes  []byte
	target Val    // aBranch/aExpr: label value (possibly forward)
	size   int    // aBranch: displacement width; aExpr/aDefer: value width
	rec    byte   // aExpr/aDefer: omf.RecLexpr or omf.RecBexpr
	shift  int64  // aExpr/aDefer: shift amount (negative = right), 0 = none
	count  int64  // aDS
	pcNext int64  // aBranch: pc after the instruction (for displacement)
	expr   string // aDefer / deferred aBranch: expression text
	pcAt   int64  // aDefer: pc for '*' during pass-2 evaluation
	segAt  int    // aDefer: segment index for '*'
	line   int
	file   string
}

type segState struct {
	name     string
	loadName string
	imports  map[string]bool // IMPORTs are scoped to the declaring segment
	org      int64           // segment header ORG (from "PROC ORG expr")
	// OMF v2.1 TEMPORG (from "PROC TEMPORG expr"): assembly-time origin that
	// does not become the load address
	tempOrg    int64
	hasTempOrg bool
	align      int64 // PROC ALIGN n (segment alignment)
	actions    []action
	endPC      int64
}

// ---------- assembler state ----------

type symEntry struct {
	val Val
}

type asmState struct {
	localScope int // bumped at each non-local code label; scopes @locals
	cpu        int
	longA      bool
	longI      bool
	msb        bool
	strMode    string // "ASIS" or "PASCAL"

	syms map[string]Val
	// All definitions of each name in source order. A one-pass assembler
	// binds a forward reference to the NEXT definition, so duplicated
	// labels (common in this corpus) must not collapse to the last one.
	symSeq   map[string][]Val
	defSeq   int64           // monotonically increasing definition counter
	imports  map[string]bool // IMPORTed external symbols
	entries  map[string]bool // ENTRY labels awaiting definition
	loadName string          // current SEG name for new PROCs
	segs     []*segState
	cur      *segState
	pc       int64

	// RECORD ... ENDR template mode
	inRecord bool
	recPC    int64
	recName  string // RECORD label, for qualified RECORD.FIELD references
	recDown  bool   // RECORD ...,decrement: fields grow downward

	// preprocessor state (conditionals, macros, set-vars) lives in preproc.go
	pp *ppState

	curFile string
	curLine int
	ended   bool
	errs    []string
}

func (st *asmState) errf(format string, args ...any) {
	st.errs = append(st.errs, fmt.Sprintf("%s:%d: %s", st.curFile, st.curLine, fmt.Sprintf(format, args...)))
}

func (st *asmState) curSegIndex() int { return len(st.segs) - 1 }

func (st *asmState) lookup(name string) Val {
	if strings.HasPrefix(name, "@") {
		name = st.scopedLocal(name)
	}
	// An IMPORT declared in the current segment makes the symbol external
	// there, even when another segment in the same file defines it.
	if st.cur != nil && st.cur.imports[name] {
		return fwdVal(name)
	}
	if v, ok := st.syms[name]; ok {
		// Tag with the symbol's own name/offset so cross-segment references
		// can be emitted by name; same-segment backward refs still use
		// segment+offset (see exprRef).
		if len(v.Pos) == 1 && len(v.Neg) == 0 && v.Pos[0].fwd == "" && v.Pos[0].name == "" {
			v.Pos = []term{{seg: v.Pos[0].seg, name: name, symOff: v.C}}
		}
		return v
	}
	f := fwdVal(name)
	f.Pos[0].atSeq = st.defSeq // bind to the next definition after this point
	return f
}

func (st *asmState) scopedLocal(name string) string {
	return fmt.Sprintf("%s#%d", name, st.localScope)
}

func (st *asmState) define(name string, v Val) {
	name = strings.ToUpper(name)
	if strings.HasPrefix(name, "@") {
		name = st.scopedLocal(name)
	} else {
		// any non-local label delimits @local scopes (incl. X EQU *)
		st.localScope++
	}
	st.syms[name] = v
	st.defSeq++
	v.defSeq = st.defSeq
	st.symSeq[name] = append(st.symSeq[name], v)
}

// ---------- line model ----------

type line struct {
	label string
	op    string
	rest  string
}

// splitLine parses "[label] op operands-and-comment". Column-one '*' or ';'
// lines are comments; ';' begins a comment anywhere outside a string.
func splitLine(s string) line {
	if s != "" && (s[0] == '*' || s[0] == ';') {
		return line{}
	}
	inStr := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			inStr = !inStr
		} else if s[i] == ';' && !inStr {
			s = s[:i]
			break
		}
	}
	if strings.TrimSpace(s) == "" {
		return line{}
	}
	var l line
	i := 0
	if s[0] != ' ' && s[0] != '\t' {
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		l.label = strings.TrimSuffix(s[:i], ":")
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := i
	for j < len(s) && s[j] != ' ' && s[j] != '\t' {
		j++
	}
	l.op = s[i:j]
	// an indented token ending in ':' is a label, not an opcode
	if l.label == "" && strings.HasSuffix(l.op, ":") {
		l.label = strings.TrimSuffix(l.op, ":")
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		i = j
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		l.op = s[i:j]
	}
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	l.rest = strings.TrimRight(s[j:], " \t")
	return l
}

// operandOnly trims a trailing bare comment: the operand field ends at the
// first whitespace outside quotes/parens/brackets.
func operandOnly(s string) string {
	depth := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inStr = !inStr
		case '(', '[':
			if !inStr {
				depth++
			}
		case ')', ']':
			if !inStr {
				depth--
			}
		case ' ', '\t':
			if !inStr && depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// ---------- entry points ----------

// AssembleFile assembles a source file (CR or LF line endings); incDirs are
// searched for INCLUDE files after the including file's own directory.
func AssembleFile(path string, incDirs ...string) (*Object, error) {
	return AssembleFileOpts(path, incDirs, nil)
}

// AssembleFileOpts assembles with include directories and command-line
// symbol definitions ("-D NAME=VALUE", as the makefiles pass them).
func AssembleFileOpts(path string, incDirs, defines []string) (*Object, error) {
	st := newState()
	st.pp.incDirs = incDirs
	// A single -d flag may carry a comma-separated list, e.g. "-d &type,type=0"
	var flat []string
	for _, d := range defines {
		flat = append(flat, strings.Split(d, ",")...)
	}
	for _, d := range flat {
		name, val, ok := strings.Cut(d, "=")
		if !ok {
			val = "1"
		}
		name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "&"))
		v, err := evalNum(strings.TrimSpace(val), &exprCtx{st: st})
		if err != nil {
			// non-numeric define: keep as a macro-language string variable
			st.pp.globals[strings.ToUpper(name)] = strings.TrimSpace(val)
			continue
		}
		st.define(name, num(v))
		st.pp.globals[strings.ToUpper(name)] = strings.TrimSpace(val)
	}
	// absolutize so MPW '::' (parent-dir) include paths resolve correctly
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if err := st.pp.processFile(path); err != nil {
		return nil, err
	}
	return st.finish()
}

// AssembleSource assembles in-memory source; dir is used for INCLUDE resolution.
func AssembleSource(src, dir string) (*Object, error) {
	st := newState()
	st.pp.processSource(src, filepath.Join(dir, "(source)"))
	return st.finish()
}

func newState() *asmState {
	st := &asmState{
		cpu:      cpu65816,
		longA:    true,
		longI:    true,
		msb:      false,
		strMode:  "ASIS",
		syms:     map[string]Val{},
		symSeq:   map[string][]Val{},
		imports:  map[string]bool{},
		entries:  map[string]bool{},
		loadName: "main",
	}
	st.pp = newPP(st)
	return st
}

func (st *asmState) finish() (*Object, error) {
	obj := &Object{}
	for _, seg := range st.segs {
		s, err := st.emitSegment(seg)
		if err != nil {
			st.errs = append(st.errs, err.Error())
			continue
		}
		obj.Segments = append(obj.Segments, *s)
	}
	if len(st.errs) > 0 {
		max := len(st.errs)
		if max > 25 {
			max = 25
		}
		return obj, fmt.Errorf("%s", strings.Join(st.errs[:max], "\n"))
	}
	return obj, nil
}

// ---------- pass-1 line dispatch (called by the preprocessor) ----------

func (st *asmState) doLine(l line) {
	if st.ended {
		return
	}
	op := strings.ToLower(l.op)

	if st.inRecord {
		st.doRecordLine(op, l)
		return
	}

	switch op {
	case "proc":
		name := strings.ToUpper(l.label)
		if name == "" {
			st.errf("PROC requires a label")
			return
		}
		seg := &segState{name: name, loadName: st.loadName, imports: map[string]bool{}}
		// PROC operands are comma- or space-separated options:
		//   EXPORT | PRIVATE | ENTRY | DYNAMIC   (linkage attributes)
		//   ORG addr | TEMPORG addr | ALIGN n
		for _, opt := range splitArgs(strings.TrimSpace(l.rest)) {
			f := strings.Fields(strings.TrimSpace(opt))
			if len(f) == 0 {
				continue
			}
			kw := strings.ToLower(f[0])
			if len(f) == 1 {
				switch kw {
				case "export", "private", "entry", "dynamic":
					continue // no effect on the emitted object
				}
				st.errf("unsupported PROC operand %q", opt)
				continue
			}
			v, err := evalNum(strings.Join(f[1:], " "), &exprCtx{st: st})
			if err != nil {
				st.errf("PROC %s: %v", f[0], err)
				continue
			}
			switch kw {
			case "org":
				seg.org = v
			case "temporg":
				// OMF v2.1 TEMPORG: assembly-time origin only
				seg.tempOrg, seg.hasTempOrg = v, true
			case "align":
				seg.align = v
			default:
				st.errf("unsupported PROC operand %q", opt)
			}
		}
		st.segs = append(st.segs, seg)
		st.cur = seg
		st.pc = 0
		st.define(name, segVal(st.curSegIndex(), 0))
		return
	case "endp", "endproc":
		if st.cur != nil {
			st.cur.endPC = st.pc
		}
		st.cur = nil
		return
	case "procname":
		// names the enclosing procedure for the debugger; the label (if any)
		// marks the current location
		if l.label != "" {
			st.defineCodeLabel(l.label)
		}
		return
	case "end":
		if st.cur != nil {
			st.cur.endPC = st.pc
			st.cur = nil
		}
		st.ended = true
		return
	case "":
		if l.label != "" {
			st.defineCodeLabel(l.label)
		}
		return
	case "anop":
		if l.label != "" {
			st.errf("a label is not allowed on ANOP")
		}
		return
	case "equ":
		v, err := evalExpr(operandOnly(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("EQU: %v", err)
			return
		}
		if v.hasFwd() {
			st.errf("EQU: undefined forward symbol in %q", l.rest)
			return
		}
		st.define(l.label, v)
		return
	case "record":
		st.inRecord = true
		st.recDown = false
		v := int64(0)
		if r := operandOnly(l.rest); r != "" {
			// "RECORD start[,increment|decrement]": decrement grows fields
			// downward from the start offset
			for i, part := range splitArgs(r) {
				part = strings.TrimSpace(part)
				switch strings.ToLower(part) {
				case "decrement":
					st.recDown = true
					continue
				case "increment", "export", "private", "entry", "":
					continue // attributes: no effect on field offsets
				}
				if i > 0 {
					continue
				}
				n, err := evalNum(part, &exprCtx{st: st})
				if err != nil {
					st.errf("RECORD: %v", err)
				} else {
					v = n
				}
			}
		}
		st.recPC = v
		st.recName = strings.ToUpper(l.label)
		if l.label != "" {
			st.define(l.label, num(v))
		}
		return
	case "machine":
		switch strings.ToLower(operandOnly(l.rest)) {
		case "m6502":
			st.cpu = cpu6502
			st.longA, st.longI = false, false
		case "m65c02":
			st.cpu = cpu65C02
			st.longA, st.longI = false, false
		case "m65816":
			st.cpu = cpu65816
		default:
			st.errf("unknown MACHINE %q", l.rest)
		}
		return
	case "longa":
		st.longA = strings.EqualFold(operandOnly(l.rest), "on")
		return
	case "longi":
		st.longI = strings.EqualFold(operandOnly(l.rest), "on")
		return
	case "msb":
		st.msb = strings.EqualFold(operandOnly(l.rest), "on")
		return
	case "string":
		st.strMode = strings.ToUpper(operandOnly(l.rest))
		return
	case "title", "eject", "print", "space", "page", "pagesize", "blanks",
		"list", "nolist", "case", "trace", "err", "obj", "noobj", "ttl":
		return // listing/diagnostic control: no object-file effect
	case "with", "endwith":
		return // record fields are defined globally here
	case "seg":
		name := operandOnly(l.rest)
		if u, err := unquote(name); err == nil && strings.HasPrefix(name, "'") {
			name = u
		}
		st.loadName = name
		return
	case "import":
		for _, a := range splitArgs(operandOnly(l.rest)) {
			// strip an optional :TYPE suffix
			nm := strings.ToUpper(strings.TrimSpace(strings.SplitN(a, ":", 2)[0]))
			if nm == "" {
				continue
			}
			st.imports[nm] = true // union, for resolve()
			if st.cur != nil {
				st.cur.imports[nm] = true
			}
		}
		return
	case "entry", "export":
		// Both publish a symbol to the linker: a GLOBAL record is emitted
		// where the label is defined, and references use the symbol name.
		for _, a := range splitArgs(operandOnly(l.rest)) {
			// an optional ":TYPE" suffix (e.g. "cmd_tbl:data") is a hint only
			nm := strings.ToUpper(strings.TrimSpace(strings.SplitN(a, ":", 2)[0]))
			if nm != "" {
				st.entries[nm] = true
			}
		}
		return
	case "writeln":
		fmt.Fprintln(os.Stderr, l.rest)
		return
	case "org":
		v, err := evalNum(operandOnly(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("ORG: %v", err)
			return
		}
		if st.cur == nil {
			st.errf("ORG outside PROC")
			return
		}
		if v < st.pc {
			st.errf("ORG backwards ($%X < $%X)", v, st.pc)
			return
		}
		if v > st.pc {
			st.addAction(action{kind: aDS, count: v - st.pc})
			st.pc = v
		}
		return
	case "ds", "ds.b", "ds.w", "ds.l":
		size := int64(1)
		switch op {
		case "ds.w":
			size = 2
		case "ds.l":
			size = 4
		}
		if l.label != "" {
			st.defineCodeLabel(l.label)
		}
		n, err := evalNum(operandOnly(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("DS: %v", err)
			return
		}
		if n > 0 {
			st.addAction(action{kind: aDS, count: n * size})
			st.pc += n * size
		}
		return
	case "dc", "dc.b", "dc.w", "dc.l", "dc.a":
		st.doDC(op, l)
		return
	case "dcb", "dcb.b", "dcb.w", "dcb.l", "dcb.a":
		st.doDCB(op, l)
		return
	case "dci", "endr":
		if op == "endr" {
			st.errf("ENDR without RECORD")
		} else {
			st.errf("undefined macro or opcode: %s", strings.ToUpper(l.op))
		}
		return
	}

	if _, isInst := opTable[op]; isInst {
		if l.label != "" {
			st.defineCodeLabel(l.label)
		}
		st.doInst(op, operandOnly(l.rest))
		return
	}
	st.errf("unknown opcode/directive %q", l.op)
}

// resumeSegment reopens the most recent segment when code or data appears
// after its ENDP (several drivers continue their data that way).
func (st *asmState) resumeSegment() bool {
	if st.cur != nil {
		return true
	}
	if st.ended || len(st.segs) == 0 {
		return false
	}
	st.cur = st.segs[len(st.segs)-1]
	st.pc = st.cur.endPC
	return true
}

func (st *asmState) defineCodeLabel(name string) {
	if !st.resumeSegment() {
		st.errf("label %q outside PROC", name)
		return
	}
	st.define(name, segVal(st.curSegIndex(), st.pc))
	if u := strings.ToUpper(name); st.entries[u] {
		// ENTRY label definition emits a GLOBAL record (oracle-verified:
		// name, length=0, type 'M', attr 1)
		rec := []byte{0xE6, byte(len(u))}
		rec = append(rec, u...)
		rec = append(rec, 0x00, 0x00, 'M', 0x01)
		st.addAction(action{kind: aRec, bytes: rec})
	}
}

// doRecordLine handles lines inside RECORD ... ENDR: a template that only
// defines constants (field offsets); nothing is emitted.
func (st *asmState) doRecordLine(op string, l line) {
	// field labels are visible plain and as RECORD.FIELD
	defField := func(name string, v Val) {
		st.define(name, v)
		if st.recName != "" && name != "" {
			st.define(st.recName+"."+strings.ToUpper(name), v)
		}
	}
	switch op {
	case "endr", "endp", "end":
		// MPW closes a RECORD template with ENDR or ENDP (both appear in the
		// GS/OS sources); END closes everything.
		st.inRecord = false
		st.recName = ""
		if op == "end" {
			st.ended = true
		}
		return
	case "org":
		v, err := evalNum(operandOnly(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("RECORD ORG: %v", err)
			return
		}
		st.recPC = v
		return
	case "ds", "ds.b", "ds.w", "ds.l":
		size := int64(1)
		switch op {
		case "ds.w":
			size = 2
		case "ds.l":
			size = 4
		}
		if l.label != "" {
			defField(l.label, num(st.recPC))
		}
		n, err := evalNum(operandOnly(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("RECORD DS: %v", err)
			return
		}
		if st.recDown {
			st.recPC -= n * size
		} else {
			st.recPC += n * size
		}
		return
	case "equ":
		v, err := evalExpr(operandOnly(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("EQU: %v", err)
			return
		}
		st.define(l.label, v)
		return
	case "", "anop":
		if l.label != "" {
			defField(l.label, num(st.recPC))
		}
		return
	case "dc", "dc.b", "dc.w", "dc.l", "dc.a", "dcb", "dcb.b":
		// Inside a RECORD template, DC directives only size the field: the
		// label takes the current template offset and no bytes are emitted.
		if l.label != "" {
			defField(l.label, num(st.recPC))
		}
		unit := int64(1)
		switch op {
		case "dc.w":
			unit = 2
		case "dc.a":
			unit = 3
		case "dc.l":
			unit = 4
		}
		items := splitArgs(l.rest)
		n := int64(len(items))
		if op == "dcb" || op == "dcb.b" {
			unit = 1
			n = 0
			if len(items) > 0 {
				if c, err := evalNum(strings.TrimSpace(items[0]), &exprCtx{st: st}); err == nil {
					n = c
				}
			}
		} else {
			for _, it := range items {
				if it = strings.TrimSpace(it); strings.HasPrefix(it, "'") {
					if u, err := unquote(it); err == nil {
						n += int64(len(u)) - 1
					}
				}
			}
		}
		if st.recDown {
			st.recPC -= n * unit
		} else {
			st.recPC += n * unit
		}
		return
	case "title", "eject", "print", "with", "endwith":
		return
	}
	st.errf("unsupported directive %q inside RECORD", l.op)
}

func (st *asmState) addAction(a action) {
	if !st.resumeSegment() {
		st.errf("code outside PROC")
		return
	}
	a.line, a.file = st.curLine, st.curFile
	st.cur.actions = append(st.cur.actions, a)
}

// emitBytes appends one emission unit (an instruction or one DC item).
// Units are kept separate: the original assembler's CONST/LCONST chunking
// flushes at unit boundaries when the next unit would cross 255 bytes.
func (st *asmState) emitBytes(b ...byte) {
	if !st.resumeSegment() {
		st.errf("code outside PROC")
		return
	}
	st.addAction(action{kind: aBytes, bytes: b})
	st.pc += int64(len(b))
}

// ---------- DC / DCB ----------

func (st *asmState) doDC(op string, l line) {
	if l.label != "" {
		st.defineCodeLabel(l.label)
	}
	size := 1
	switch op {
	case "dc.w":
		size = 2
	case "dc.a":
		size = 3
	case "dc.l":
		size = 4
	}
	for _, item := range splitArgs(l.rest) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item[0] == '\'' { // string constant
			s, err := unquote(item)
			if err != nil {
				st.errf("DC: %v", err)
				return
			}
			b := []byte(s)
			if st.msb {
				for i := range b {
					b[i] |= 0x80
				}
			}
			if st.strMode == "PASCAL" {
				b = append([]byte{byte(len(b))}, b...)
			}
			st.emitBytes(b...)
			continue
		}
		shift, expr := splitExtractor(item)
		v, err := evalExpr(expr, &exprCtx{st: st})
		if err != nil {
			st.addAction(action{kind: aDefer, expr: expr, size: size,
				rec: byte(recLexpr), shift: shift, pcAt: st.pc, segAt: st.curSegIndex()})
			st.pc += int64(size)
			continue
		}
		if v.isNum() {
			c := applyShift(v.C, shift)
			var b []byte
			for i := 0; i < size; i++ {
				b = append(b, byte(c>>(8*i)))
			}
			st.emitBytes(b...)
		} else {
			st.addAction(action{kind: aExpr, target: v, size: size, rec: byte(recLexpr), shift: shift})
			st.pc += int64(size)
		}
	}
}

func (st *asmState) doDCB(op string, l line) {
	if l.label != "" {
		st.defineCodeLabel(l.label)
	}
	args := splitArgs(l.rest)
	if len(args) != 2 {
		st.errf("DCB.B needs count,value")
		return
	}
	n, err1 := evalNum(strings.TrimSpace(args[0]), &exprCtx{st: st})
	v, err2 := evalNum(strings.TrimSpace(args[1]), &exprCtx{st: st})
	if err1 != nil || err2 != nil {
		st.errf("DCB.B: bad operands")
		return
	}
	unit := int64(1)
	switch op {
	case "dcb.w":
		unit = 2
	case "dcb.a":
		unit = 3
	case "dcb.l":
		unit = 4
	}
	if v == 0 && n*unit > 5 {
		// zero fills longer than a DS record are emitted as DS
		st.addAction(action{kind: aDS, count: n * unit})
		st.pc += n * unit
		return
	}
	b := make([]byte, 0, n*unit)
	for i := int64(0); i < n; i++ {
		for k := int64(0); k < unit; k++ {
			b = append(b, byte(v>>(8*k)))
		}
	}
	st.emitBytes(b...)
}

func unquote(s string) (string, error) {
	if len(s) < 2 || s[0] != '\'' {
		return "", fmt.Errorf("bad string %q", s)
	}
	var out []byte
	i := 1
	for i < len(s) {
		if s[i] == '\'' {
			if i+1 < len(s) && s[i+1] == '\'' {
				out = append(out, '\'')
				i += 2
				continue
			}
			return string(out), nil
		}
		out = append(out, s[i])
		i++
	}
	return "", fmt.Errorf("unterminated string %q", s)
}

// splitExtractor strips a leading byte-extraction operator from an operand
// expression: < (low), > (high, shift -8), ^ (bank, shift -16).
func splitExtractor(s string) (int64, string) {
	if s == "" {
		return 0, s
	}
	switch s[0] {
	case '>':
		return -8, s[1:]
	case '^':
		return -16, s[1:]
	case '<':
		return 0, s[1:] // low byte: truncation via record size
	}
	return 0, s
}

func applyShift(v, shift int64) int64 {
	switch {
	case shift < 0:
		return v >> uint(-shift)
	case shift > 0:
		return v << uint(shift)
	}
	return v
}

// splitArgs splits on commas not inside quotes or parens/brackets.
func splitArgs(s string) []string {
	var out []string
	depth, start := 0, 0
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inStr = !inStr
		case '(', '[':
			if !inStr {
				depth++
			}
		case ')', ']':
			if !inStr {
				depth--
			}
		case ',':
			if !inStr && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// ---------- instructions ----------

func (st *asmState) doInst(mn, operand string) {
	mode, exprStr, err := parseOperand(mn, operand)
	if err != nil {
		st.errf("%s: %v", mn, err)
		return
	}

	var shift int64
	forced := 0
	if mode == ImmM {
		shift, exprStr = splitExtractor(exprStr)
	} else if exprStr != "" {
		switch exprStr[0] {
		case '|', '!':
			forced = 2
			exprStr = exprStr[1:]
		case '>':
			forced = 3
			exprStr = exprStr[1:]
		case '<':
			forced = 1
			exprStr = exprStr[1:]
		}
	}

	// Evaluate the operand: mode selection is value-driven for constants;
	// label references always use the 2-byte absolute form (oracle rule).
	// Expressions that fail because of forward symbols in non-linear
	// contexts (e.g. FWDLABEL*256) are deferred to pass 2.
	val := num(0)
	deferred := false
	if exprStr != "" && mode != Move {
		v, err := evalExpr(exprStr, &exprCtx{st: st})
		if err != nil {
			deferred = true
			v = fwdVal("") // treat as label-like for sizing
		}
		val = v
	}
	sizeNeeded := 0
	if exprStr != "" {
		sizeNeeded = 1
	}
	if val.isLabel() {
		sizeNeeded = 2
	} else if val.C >= 0x10000 || val.C < -0x8000 {
		sizeNeeded = 3
	} else if val.C >= 0x100 || val.C < -0x80 {
		sizeNeeded = 2
	}
	if forced != 0 {
		sizeNeeded = forced
	}

	chain := modeChain(mode)
	var info opInfo
	var found bool
	var chosen Mode
	for _, m := range chain {
		if oi, ok := ops[opKey{mn, m}]; ok && oi.cpu <= st.cpu {
			switch m {
			case Rel8, Rel16, ImmM, ImmX, Imm8, Move:
			default:
				if modeLen(m) < sizeNeeded {
					continue
				}
			}
			info, found, chosen = oi, true, m
			break
		}
	}
	if !found {
		// no mode is wide enough: the original truncates to the widest
		// available (e.g. LDA $E1xxxx,y -> 16-bit abs,y with DBR)
		for i := len(chain) - 1; i >= 0; i-- {
			if oi, ok := ops[opKey{mn, chain[i]}]; ok && oi.cpu <= st.cpu {
				info, found, chosen = oi, true, chain[i]
				break
			}
		}
	}
	if !found {
		st.errf("%s does not support this addressing mode", mn)
		return
	}

	if chosen == Move {
		// MVN/MVP src,dst: operands are addresses; bank bytes emitted as
		// opcode, dstbank, srcbank (oracle-verified).
		parts := splitArgs(exprStr)
		if len(parts) != 2 {
			st.errf("%s: need two operands", mn)
			return
		}
		src, err1 := evalNumLenient(parts[0], &exprCtx{st: st})
		dst, err2 := evalNumLenient(parts[1], &exprCtx{st: st})
		if err1 != nil || err2 != nil {
			st.errf("%s: bad operands", mn)
			return
		}
		st.emitBytes(info.code, byte(dst>>16), byte(src>>16))
		return
	}

	// operand width
	n := modeLen(chosen)
	switch chosen {
	case ImmM:
		n = 1
		if st.longA {
			n = 2
		}
	case ImmX:
		n = 1
		if st.longI {
			n = 2
		}
	}

	switch {
	case deferred:
		rec := byte(recLexpr)
		if (mn == "jmp" || mn == "jsr") && chosen == Abs {
			rec = recBexpr // bank-truncated; indirect/long forms use LEXPR
		}
		if chosen == Rel8 || chosen == Rel16 {
			st.emitBytes(info.code)
			st.addAction(action{kind: aBranch, target: val, size: n,
				pcNext: st.pc + int64(n), expr: exprStr, pcAt: st.pc - 1, segAt: st.curSegIndex()})
			st.pc += int64(n)
			return
		}
		st.emitBytes(info.code)
		st.addAction(action{kind: aDefer, expr: exprStr, size: n, rec: rec,
			shift: shift, pcAt: st.pc - 1, segAt: st.curSegIndex()})
		st.pc += int64(n)
	case chosen == Rel8 || chosen == Rel16:
		st.emitBytes(info.code)
		st.addAction(action{kind: aBranch, target: val, size: n, pcNext: st.pc + int64(n)})
		st.pc += int64(n)
	case val.isLabel():
		// expression record: BEXPR for 2-byte jmp/jsr targets (bank-
		// truncated), LEXPR for data refs and long transfers
		rec := byte(recLexpr)
		if (mn == "jmp" || mn == "jsr") && chosen == Abs {
			rec = recBexpr
		}
		st.emitBytes(info.code)
		st.addAction(action{kind: aExpr, target: val, size: n, rec: rec, shift: shift})
		st.pc += int64(n)
	default:
		b := []byte{info.code}
		c := applyShift(val.C, shift)
		for i := 0; i < n; i++ {
			b = append(b, byte(c>>(8*i)))
		}
		st.emitBytes(b...)
	}
}

// modeChain returns candidate table modes in preference order for a
// syntactic mode (e.g. plain operand tries DP, Abs, AbsL).
func modeChain(m Mode) []Mode {
	switch m {
	case ImmM:
		return []Mode{ImmM, ImmX, Imm8}
	case DP:
		return []Mode{DP, Abs, AbsL, Rel8, Rel16}
	case DPX:
		return []Mode{DPX, AbsX, AbsLX}
	case DPY:
		return []Mode{DPY, AbsY}
	case DPInd:
		return []Mode{DPInd, AbsInd}
	case DPIndX:
		return []Mode{DPIndX, AbsIndX}
	case DPIndL:
		return []Mode{DPIndL, AbsIndL}
	}
	return []Mode{m}
}

// parseOperand classifies operand syntax; returns the syntactic mode and the
// expression text.
func parseOperand(mn, s string) (Mode, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Implied, "", nil
	}
	if strings.EqualFold(s, "a") {
		return Accum, "", nil
	}
	if s[0] == '#' {
		return ImmM, s[1:], nil
	}
	low := strings.ToLower(s)
	switch {
	case s[0] == '(':
		inner := matchParen(s)
		if inner == "" {
			return 0, "", fmt.Errorf("bad operand %q", s)
		}
		suffix := strings.ToLower(strings.TrimSpace(s[len(inner)+2:]))
		in := strings.ToLower(inner)
		switch {
		case strings.HasSuffix(in, ",x"):
			return DPIndX, inner[:len(inner)-2], nil
		case strings.HasSuffix(in, ",s") && suffix == ",y":
			return SRIndY, inner[:len(inner)-2], nil
		case suffix == ",y":
			return DPIndY, inner, nil
		case suffix == "":
			return DPInd, inner, nil
		}
		return 0, "", fmt.Errorf("bad indirect operand %q", s)
	case s[0] == '[':
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return 0, "", fmt.Errorf("bad operand %q", s)
		}
		inner := s[1:end]
		if strings.EqualFold(strings.TrimSpace(s[end+1:]), ",y") {
			return DPIndLY, inner, nil
		}
		return DPIndL, inner, nil
	case strings.HasSuffix(low, ",x"):
		return DPX, s[:len(s)-2], nil
	case strings.HasSuffix(low, ",y"):
		return DPY, s[:len(s)-2], nil
	case strings.HasSuffix(low, ",s"):
		return SR, s[:len(s)-2], nil
	}
	if mn == "mvn" || mn == "mvp" {
		return Move, s, nil
	}
	return DP, s, nil
}

// matchParen returns the text inside the leading balanced parens of s.
func matchParen(s string) string {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i]
			}
		}
	}
	return ""
}
