// Package asm is a from-scratch reimplementation of the Apple MPW IIGS
// assembler (AsmIIGS): MPW-syntax 65816 macro assembler emitting OMF v2
// object files. Behavior is developed by byte-diffing against the original
// assembler running under emulation; oracle-established rules are noted
// throughout.
package asm

import (
	"encoding/binary"
	"fmt"
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
	aOrg // OMF ORG record: move the location counter by a signed amount
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
	global string // aRec GLOBAL: the published name (see globalNth)
	gseq   int    // aRec GLOBAL: which definition of that name this is
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
	align      int64  // PROC ALIGN n (segment alignment)
	kind       uint16 // OMF KIND ($4001 for a data segment from bare RECORD)
	kindSet    bool   // kind was set explicitly (PROC EXPORT clears to $0000)
	skip       bool   // OMF KIND SKIP bit ($0200), from the sticky PROC SKIP mode
	actions    []action
	endPC      int64
	// storage marks the one-line data segment a file-scope storage
	// declaration opens; the NEXT storage line must open its own, not
	// resume this one.
	storage bool
}

// bareField remembers a symbol a RECORD template's field name shadowed.
type bareField struct {
	key    string
	val    Val
	had    bool
	seqLen int
}

// ---------- assembler state ----------

type symEntry struct {
	val Val
}

type asmState struct {
	// @local scoping is a CHAIN of scopes (oracle-probed, AppleShare's
	// trysub and the SCSI drivers): a macro expansion pushes a fresh scope
	// and pops it at ENDM, so consecutive expansions keep their @labels
	// apart while the caller's scope -- with its @labels -- resumes after
	// the call. Every non-local code label REPLACES the innermost scope.
	// References resolve innermost-outward, and a forward reference binds
	// to the next definition made in any scope that was on the chain when
	// the reference was made (a macro argument like "pushword
	// |@deref_handle" is evaluated inside the expansion but its label is
	// defined later in the caller's scope). localScopeMax is a monotonic id
	// generator; scope ids are never reused.
	scopeChain    []int
	localScopeMax int
	// labelRedirect, one entry per open macro expansion: when the
	// invocation's label is an @-local ("@hitReturn _RestoreTextState"),
	// the body's "&lab" definition belongs to the CALLER's scope, not the
	// expansion's -- the outer "beq @hitReturn" must reach it.
	labelRedirect []labelRedirect
	cpu        int
	longA      bool
	longI      bool
	msb        bool
	strMode    string // "ASIS" or "PASCAL"
	// blanksOff is BLANKS OFF: the operand field ends at the first blank
	// after a complete operand. The DEFAULT is BLANKS ON (oracle-probed),
	// where the field runs to the ';' comment or end of line -- hfs.fst.btree
	// pops its registers with "lda #(f_d0+...) << 2<tab>; comment" and the
	// shift is part of the operand.
	blanksOff bool

	syms map[string]Val
	// All definitions of each name in source order. A one-pass assembler
	// binds a forward reference to the NEXT definition, so duplicated
	// labels (common in this corpus) must not collapse to the last one.
	symSeq  map[string][]Val
	defSeq  int64           // monotonically increasing definition counter
	imports map[string]bool // IMPORTed external symbols
	entries map[string]bool // ENTRY/EXPORT labels awaiting definition
	// entryPriv is the GLOBAL record's private byte: ENTRY publishes 1,
	// EXPORT 0. entryEqu holds the names declared "name:EQU", which resolve
	// to a constant and so are published as GEQU rather than GLOBAL.
	entryPriv map[string]byte
	entryEqu  map[string]bool
	// fileWide names escape segment scope: ENTRY/EXPORT symbols and the PROC
	// labels that name the segments themselves.
	fileWide map[string]bool
	segNames map[string]bool // segment labels, which do fold in differences
	// A published name emits exactly one GLOBAL record. globalNth numbers the
	// definitions as they are seen, entrySeg says which segment the ENTRY or
	// EXPORT directive pinned it to (-1 = file scope, unpinned), pubGseq is
	// the definition finally chosen, and lastPubSeq is its defSeq.
	globalNth  map[string]int
	entrySeg   map[string]int
	pubGseq    map[string]int
	lastPubSeq map[string]int64
	loadName   string // current SEG name for new PROCs
	segs       []*segState
	cur        *segState
	pc         int64

	// pendingRecs holds records produced before any segment exists (an
	// "export k:equ" whose equate sits at file scope); the original puts them
	// at the head of the first segment.
	pendingRecs [][]byte

	// scopeSeg overrides the symbol scope during pass 2, when st.cur no
	// longer reflects the segment a deferred expression came from (-1 = use
	// the current segment).
	scopeSeg int

	// RECORD ... ENDR template mode
	inRecord bool
	recPC    int64
	recName  string // RECORD label, for qualified RECORD.FIELD references
	recHigh  int64  // highest offset reached, for a bare ORG "reset to max"
	segHigh  int64  // same, for the location counter inside a segment
	// recSize/recFields describe finished RECORD templates so that
	// "label DS <record>" can reserve the right size and alias the fields.
	recSize   map[string]int64
	recFields map[string]map[string]int64
	// recEqus marks which recFields entries are EQUates rather than
	// ds-declared fields: an instance ("label ds <rec>", "import
	// name:<rec>", WITH) aliases a FIELD to instance+offset but an EQU
	// stays the plain constant. MSDos' "ldy #bpb_size-1" folds to $12 even
	// under "with bios_parm_block" (oracle-verified).
	recEqus map[string]map[string]bool
	recDown bool // RECORD ...,decrement: fields grow downward
	// recImport is "name RECORD IMPORT": the storage lives in another file
	// (AppleShare's data.aii declares SPWrite with RECORD EXPORT, flush.aii
	// re-declares the layout with RECORD IMPORT). No segment or bytes are
	// emitted; the name becomes an external symbol and each ds-declared
	// field resolves to import+offset, reachable only as RECORD.FIELD
	// (bare field names outside are Undefined ID -- oracle-probed, and an
	// addend folds into the offset constant: SPWrite.ComAddr+2 emits
	// "SPWRITE, $0D, add").
	recImport bool
	// recBare records what the open template's unqualified field names hid,
	// so ENDR can put it back (see doRecordLine).
	recBare []bareField
	// withs are the record instances named by WITH, innermost last; a bare
	// field name is looked up through them before the plain symbol table.
	withs []string
	// dataChk/codeChk select BEXPR over LEXPR for 2-byte absolute references
	// (oracle-probed); CODECHK defaults on, DATACHK off.
	dataChk bool
	codeChk bool
	// caseSens is CASE ON: symbols are case-sensitive and keep their spelling.
	caseSens bool
	// skipMode is PROC SKIP: a sticky mode, not a per-segment attribute --
	// once a PROC carries SKIP every later segment keeps the KIND bit until a
	// PROC carries NOSKIP (oracle-probed).
	skipMode bool

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

// sym canonicalises a symbol name. Names fold to upper case unless CASE ON is
// in effect, which makes the assembler case-sensitive and preserves the
// spelling in the object's GLOBAL and segment names. Only the System Loader
// asks for it, and it does: its call table publishes "LoaderInit", not
// "LOADERINIT".
func (st *asmState) sym(name string) string {
	if st.caseSens {
		return name
	}
	return strings.ToUpper(name)
}

// scopePrefix is the symbol-table prefix for definitions made at this point.
//
// Labels and equates declared inside a code PROC belong to that segment alone --
// the original assembler reports "Undefined ID" for them in a second PROC,
// which is how a file can reuse a name like "done" in every routine. Symbols
// defined outside a PROC are visible file-wide, as are RECORD fields (a
// template defines offsets, not storage), the fields of a RECORD data
// segment, and anything published with ENTRY/EXPORT.
func (st *asmState) scopePrefix() string {
	if st.scopeSeg >= 0 {
		return fmt.Sprintf("%d\x00", st.scopeSeg)
	}
	// A data segment's PLAIN field names are scoped to the segment like any
	// PROC label (oracle-probed: "sta save1" from another segment is
	// "Undefined ID", or "IMPORT assumed" under -unsafe). Only EXPORTed
	// fields and the qualified RECORD.FIELD form reach across segments --
	// hfs.fst.main relies on the IMPORT-assumed form for save_gbuf_ptr1.
	if st.cur == nil || st.inRecord {
		return ""
	}
	return fmt.Sprintf("%d\x00", st.curSegIndex())
}

func (st *asmState) lookup(name string) Val {
	if strings.HasPrefix(name, "@") {
		// Backward: innermost chain scope first (an expansion's @label
		// shadows the caller's). Forward: remember the whole chain -- the
		// definition may land in any scope that encloses this reference.
		for i := len(st.scopeChain) - 1; i >= 0; i-- {
			key := fmt.Sprintf("%s#%d", name, st.scopeChain[i])
			if v, ok := st.syms[key]; ok {
				return v
			}
		}
		f := fwdVal(name)
		f.Pos[0].atSeq = st.defSeq
		f.Pos[0].chain = append([]int(nil), st.scopeChain...)
		return f
	}
	// A WITH'd record instance qualifies a bare field name; the most recent
	// Tag with the symbol's own name/offset so cross-segment references
	// can be emitted by name; same-segment backward refs still use
	// segment+offset (see exprRef).
	tag := func(v Val) Val {
		if len(v.Pos) == 1 && len(v.Neg) == 0 && v.Pos[0].fwd == "" && v.Pos[0].name == "" {
			t := term{seg: v.Pos[0].seg, name: name, symOff: v.C, defSeq: v.defSeq}
			t.pub = st.publishedAt(t)
			v.Pos = []term{t}
		}
		return v
	}
	// WITH wins -- even over an IMPORT of the same name in the same segment
	// (oracle-probed: AppleShare's PreProcess does "with dp,mydata" AND
	// "import my_fork_bitmap", and the reference emits MYDATA+offset; nothing
	// ever publishes MY_FORK_BITMAP by name). Its result is tagged like any
	// other lookup: hfs.fst.main reaches its data segment's fields through
	// "with data", and the EXPORTed ones must still emit by name, not as
	// DATA+offset.
	for i := len(st.withs) - 1; i >= 0; i-- {
		if v, ok := st.syms[st.withs[i]+"."+name]; ok {
			v = tag(v)
			if len(v.Pos) == 1 {
				v.Pos = append([]term(nil), v.Pos...)
				v.Pos[0].viaWith = true
			}
			return v
		}
	}
	// An IMPORT declared in the current segment makes the symbol external
	// there, even when another segment in the same file defines it.
	if st.cur != nil && st.cur.imports[name] {
		return fwdVal(name)
	}
	scope := st.scopePrefix()
	for _, key := range [2]string{scope + name, name} {
		v, ok := st.syms[key]
		if !ok {
			continue
		}
		return tag(v)
	}
	f := fwdVal(name)
	f.Pos[0].scope = scope
	f.Pos[0].atSeq = st.defSeq // bind to the next definition after this point
	return f
}

type labelRedirect struct {
	name     string // canonicalized @-label from the invocation ("" = none)
	chainIdx int    // the caller's slot in scopeChain
}

func (st *asmState) scopedLocal(name string) string {
	if n := len(st.labelRedirect); n > 0 {
		if r := st.labelRedirect[n-1]; r.name != "" && st.sym(name) == r.name &&
			r.chainIdx < len(st.scopeChain) {
			return fmt.Sprintf("%s#%d", name, st.scopeChain[r.chainIdx])
		}
	}
	return fmt.Sprintf("%s#%d", name, st.scopeChain[len(st.scopeChain)-1])
}

func (st *asmState) define(name string, v Val) {
	name = st.sym(name)
	key := name
	if strings.HasPrefix(name, "@") {
		key = st.scopedLocal(name)
	} else {
		// any non-local label delimits @local scopes (incl. X EQU *)
		st.localScopeMax++
		st.scopeChain[len(st.scopeChain)-1] = st.localScopeMax
		// ENTRY/EXPORT symbols stay file-wide; everything else is scoped to
		// the segment being assembled.
		if !st.entries[name] && !st.fileWide[name] {
			key = st.scopePrefix() + name
		}
	}
	st.defSeq++
	v.defSeq = st.defSeq
	st.syms[key] = v
	st.symSeq[key] = append(st.symSeq[key], v)
	// A published name is also recorded under its defining segment's scope,
	// so that a reference from inside that segment reaches the definition
	// standing right there rather than the one the GLOBAL declares. ProDOS.FST
	// has a local clear_index in flush_file and a published one much later;
	// flush_file branches to its own, everyone else calls the published one.
	if key == name && !strings.HasPrefix(name, "@") {
		if scoped := st.scopePrefix() + name; scoped != name {
			st.symSeq[scoped] = append(st.symSeq[scoped], v)
		}
	}
}

// symbolList splits an IMPORT/EXPORT operand into its symbols. The list may
// be parenthesized with the type applying to all of them, as in
// "import (InitParm,TitLine):code".
func symbolList(rest string) []string {
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "(") {
		return splitArgs(rest)
	}
	end := strings.Index(rest, ")")
	if end < 0 {
		return splitArgs(rest)
	}
	kind := strings.TrimPrefix(strings.TrimSpace(rest[end+1:]), ":")
	var out []string
	for _, n := range splitArgs(rest[1:end]) {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n+":"+kind)
		}
	}
	return out
}

// redefine assigns a SET symbol. Unlike define it replaces the symbol's value
// instead of recording another definition: a dummy PC is reassigned dozens of
// times, and each one is meant to be read immediately, not to become another
// candidate for a forward reference to bind to.
func (st *asmState) redefine(name string, v Val) {
	name = strings.ToUpper(name)
	key := name
	if !st.entries[name] && !st.fileWide[name] {
		key = st.scopePrefix() + name
	}
	st.defSeq++
	v.defSeq = st.defSeq
	st.syms[key] = v
	st.symSeq[key] = []Val{v}
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
//
// An operand that is syntactically incomplete continues past the blanks --
// "entry alloc_mem,<tab>do_alloc" is one list, and "|mode.page_number +x" is
// one expression. Only a blank that follows a complete operand ends the field.
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
			if inStr || depth != 0 {
				continue
			}
			// look past a run of blanks to the last real character
			j := i
			for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
				j--
			}
			if j > 0 && continuesOperand(s[j-1]) {
				continue
			}
			// The expression may also resume after the blanks:
			// Device.Dispatcher has "lda |temp_load_addr<tab>+2", and the
			// original reads it as one operand. Only a sign directly against
			// a value counts, so a "-" or "*" opening a trailing comment
			// still ends the field.
			k := i
			for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			if k+1 < len(s) && (s[k] == '+' || s[k] == '-') && resumesOperand(s[k+1]) {
				continue
			}
			return s[:i]
		}
	}
	return s
}

// operandField cuts the operand from the rest of a line under the current
// BLANKS mode. BLANKS ON (the default): the field runs to the ';' comment or
// end of line, so "#(mask) << 2" keeps its shift. BLANKS OFF: the field ends
// at the first blank after a complete operand (operandOnly). DC operands
// always end at the first blank outside quotes regardless of mode
// (oracle-verified in hfs.fst.main, a BLANKS ON file), so the DC path calls
// operandOnly directly.
func (st *asmState) operandField(s string) string {
	if st.blanksOff {
		return operandOnly(s)
	}
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inStr = !inStr
		case ';':
			if !inStr {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return strings.TrimRight(s, " \t")
}

// dcOperand cuts a DC item list from the rest of a line. DC operands end at
// the first blank outside quotes even under BLANKS ON ("DC.L ctree_idx_rec
// 'ptr to..." carries a bare comment opening with an apostrophe,
// oracle-verified in hfs.fst.main) -- EXCEPT that the expression continues
// when an operator adjoins the blank on either side: DOS3.3.FST builds its
// fill_param tables with "dc.w access<tab>- g". Under BLANKS OFF the plain
// first-blank rule applies.
func (st *asmState) dcOperand(s string) string {
	if st.blanksOff {
		return operandOnly(s)
	}
	inStr := false
	depth := 0
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
			if inStr || depth != 0 {
				continue
			}
			// last real character before the blanks
			j := i
			for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
				j--
			}
			if j > 0 && continuesOperand(s[j-1]) {
				continue
			}
			// first real character after the blanks
			k := i
			for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			// "++"/"--"/"**"/"<<" are the word-form OR/XOR/AND and shift
			// operators, so a doubled character continues too (DOS3.3's
			// copy_tbl is "dc.w 0 ++ \" continued over 16 "copy << n ++"
			// lines).
			if k < len(s) && strings.IndexByte("+-*/&|^<>=", s[k]) >= 0 {
				continue
			}
			return s[:i]
		case ';':
			if !inStr {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return s
}

// continuesOperand reports whether an operand ending in c is incomplete, so
// that following blanks are separators rather than the end of the field.
func continuesOperand(c byte) bool {
	return strings.IndexByte(",+-*/&|^<>=", c) >= 0
}

// resumesOperand reports whether c can begin the value after a "+" or "-"
// that follows blanks.
func resumesOperand(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c == '$' || c == '%' || c == '(' || c == '&' || c == '_'
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
	return AssembleFileWith(path, FileOpts{IncDirs: incDirs, Defines: defines})
}

// FileOpts carries the invocation context beyond the source itself. CurDir
// is the MPW current directory (a DUMP operand like ':obj:equates.dump' is
// relative to it); Getenv answers &GETENV from the MPW shell's variables.
type FileOpts struct {
	IncDirs []string
	Defines []string
	CurDir  string
	Getenv  func(string) string
}

func AssembleFileWith(path string, o FileOpts) (*Object, error) {
	st := newState()
	st.pp.incDirs = o.IncDirs
	st.pp.curDir = o.CurDir
	st.pp.getenv = o.Getenv
	st.pp.defines = o.Defines
	for _, d := range o.Defines {
		st.applyDefine(d)
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

// applyDefine handles one -d flag, which may carry a comma-separated list,
// e.g. "-d &type,type=0". Also used when a LOADed dump stub replays the
// defines its source was originally assembled under.
func (st *asmState) applyDefine(define string) {
	for _, d := range strings.Split(define, ",") {
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
}

// AssembleSource assembles in-memory source; dir is used for INCLUDE resolution.
func AssembleSource(src, dir string) (*Object, error) {
	st := newState()
	st.pp.processSource(src, filepath.Join(dir, "(source)"))
	return st.finish()
}

func newState() *asmState {
	st := &asmState{
		cpu:        cpu65816,
		longA:      true,
		longI:      true,
		msb:        false,
		strMode:    "ASIS",
		syms:       map[string]Val{},
		symSeq:     map[string][]Val{},
		imports:    map[string]bool{},
		entries:    map[string]bool{},
		entryPriv:  map[string]byte{},
		codeChk:    true,
		globalNth:  map[string]int{},
		entrySeg:   map[string]int{},
		pubGseq:    map[string]int{},
		lastPubSeq: map[string]int64{},
		fileWide:   map[string]bool{},
		segNames:   map[string]bool{},
		scopeSeg:   -1,
		scopeChain: []int{0},
		recSize:    map[string]int64{},
		recFields:  map[string]map[string]int64{},
		recEqus:    map[string]map[string]bool{},
		entryEqu:   map[string]bool{},
		loadName:   "main",
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
	case "proc", "func":
		// FUNC is PROC under another name: the original emits the same
		// KIND $4000 segment for both.
		name := st.sym(l.label)
		if name == "" {
			st.errf("%s requires a label", strings.ToUpper(op))
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
				case "export":
					// clears the segment's PRIVATE bit (oracle-verified:
					// plain PROC is KIND $4000, PROC EXPORT is $0000)
					seg.kind = 0x0000
					seg.kindSet = true
					continue
				case "skip":
					st.skipMode = true
					continue
				case "noskip":
					st.skipMode = false
					continue
				case "private", "entry", "dynamic":
					continue // no effect on the emitted object
				}
				st.errf("unsupported %s operand %q", strings.ToUpper(op), opt)
				continue
			}
			v, err := evalNum(strings.Join(f[1:], " "), &exprCtx{st: st})
			if err != nil {
				st.errf("%s %s: %v", strings.ToUpper(op), f[0], err)
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
				st.errf("unsupported %s operand %q", strings.ToUpper(op), opt)
			}
		}
		seg.skip = st.skipMode
		st.openSegment(seg)
		return
	case "endp", "endproc", "endf":
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
	case "equ", "set":
		// SET is EQU for a symbol that may be redefined; the DSect/BYTE/WORD/
		// LONG macros walk a dummy PC that way to lay out parameter records.
		v, err := evalExpr(st.operandField(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("%s: %v", strings.ToUpper(op), err)
			return
		}
		// An EQU of an IMPORTed symbol is an alias -- MSDos.Calls does
		// "check_cluster equ entries_checked" against an Import, and every
		// reference to the alias reaches the external by name. Only a
		// forward LOCAL symbol is an error (oracle-probed).
		if v.hasUnresolvedFwd(st) {
			st.errf("%s: undefined forward symbol in %q", strings.ToUpper(op), l.rest)
			return
		}
		v = v.foldPub()
		// An EQU yields an absolute: apply deferred trailing constants now
		// (Cache's "c_data_len equ end_of_data-start_of_data-1", where the
		// published pair folds and the -1 rode along as a Post op).
		if v.isNum() && len(v.Post) > 0 {
			v = num(applyPost(v.C, v.Post))
		}
		if op == "set" {
			st.redefine(l.label, v)
			return
		}
		st.define(l.label, v)
		// An equate inside a RECORD data segment is reachable through WITH
		// (and DATA.NAME), like the segment's DS fields -- hfs.fst.main's
		// len_params. Its plain name stays scoped to the segment
		// (oracle-probed: cross-segment "ldy #diff" is IMPORT assumed).
		if st.cur != nil && st.cur.kind&0x1F == 0x01 {
			if u := st.sym(l.label); u != "" && u != st.cur.name {
				q := st.cur.name + "." + u
				st.fileWide[q] = true
				st.define(q, v)
			}
		}
		if u := st.sym(l.label); st.entryEqu[u] && v.isNum() {
			// deferred trailing constants (Cache's "end-start-1") apply here
			rec := gequRec(u, st.entryPriv[u], applyPost(v.C, v.Post))
			if st.cur == nil && len(st.segs) == 0 {
				st.pendingRecs = append(st.pendingRecs, rec)
			} else {
				st.addAction(action{kind: aRec, bytes: rec})
			}
		}
		return
	case "aerror":
		st.errf("AERROR %s", strings.TrimSpace(l.rest))
		return
	case "record":
		st.recDown = false
		v := int64(0)
		hasStart := false
		export := false
		imported := false
		if r := operandOnly(l.rest); r != "" {
			// "RECORD start[,increment|decrement]": decrement grows fields
			// downward from the start offset
			for i, part := range splitArgs(r) {
				part = strings.TrimSpace(part)
				switch strings.ToLower(part) {
				case "decrement":
					st.recDown = true
					continue
				case "export":
					export = true
					continue
				case "import":
					imported = true
					continue
				case "increment", "private", "entry", "":
					continue // attributes: no effect on field offsets
				}
				if i > 0 {
					continue
				}
				n, err := evalNum(part, &exprCtx{st: st})
				if err != nil {
					st.errf("RECORD: %v", err)
				} else {
					v, hasStart = n, true
				}
			}
		}
		if !hasStart {
			// "RECORD IMPORT" is the reference side of a RECORD EXPORT in
			// another file: a template whose base is an external symbol.
			if imported {
				name := st.sym(l.label)
				if name == "" {
					st.errf("RECORD IMPORT requires a label")
					return
				}
				st.imports[name] = true
				st.inRecord = true
				st.recImport = true
				st.recHigh = 0
				st.recPC = 0
				st.recName = name
				return
			}
			// A RECORD with no start offset is not a template at all: it
			// opens a data segment (oracle-verified KIND $4001), which is how
			// these sources define tables like Character.FST's cmd_tbl that
			// other segments reach through IMPORT. EXPORT clears its PRIVATE
			// bit exactly as it does for a PROC, giving KIND $0001 (Init1's
			// std_buffer).
			kind := uint16(0x4001)
			if export {
				kind = 0x0001
			}
			st.beginSegment(l.label, kind)
			return
		}
		st.inRecord = true
		st.recHigh = v
		st.recPC = v
		st.recName = st.sym(l.label)
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
	case "case":
		st.caseSens = strings.EqualFold(strings.TrimSpace(operandOnly(l.rest)), "on")
		return
	case "blanks":
		st.blanksOff = strings.EqualFold(strings.TrimSpace(operandOnly(l.rest)), "off")
		return
	case "title", "eject", "print", "space", "page", "pagesize",
		"list", "nolist", "trace", "err", "obj", "noobj", "ttl":
		return // listing/diagnostic control: no object-file effect
	case "datachk", "codechk":
		on := strings.EqualFold(strings.TrimSpace(operandOnly(l.rest)), "on")
		if op == "datachk" {
			st.dataChk = on
		} else {
			st.codeChk = on
		}
		return
	case "with":
		// WITH brings a record instance's fields into scope unqualified. For a
		// template that changes nothing (its fields are plain offsets defined
		// globally), but for an instance -- Init4 does "import
		// jn_parms:jn_parmBlock" then "with jn_parms" -- a bare field name has
		// to mean jn_parms.field, an external reference, not the bare offset.
		for _, a := range splitArgs(operandOnly(l.rest)) {
			if a = st.sym(strings.TrimSpace(a)); a != "" {
				st.withs = append(st.withs, a)
			}
		}
		return
	case "endwith":
		st.withs = nil
		return
	case "seg":
		name := operandOnly(l.rest)
		if u, err := unquote(name); err == nil && strings.HasPrefix(name, "'") {
			name = u
		}
		st.loadName = name
		return
	case "import":
		for _, a := range symbolList(operandOnly(l.rest)) {
			name, kind, _ := strings.Cut(a, ":")
			nm := st.sym(strings.TrimSpace(name))
			if nm == "" {
				continue
			}
			st.imports[nm] = true // union, for resolve()
			if st.cur != nil {
				st.cur.imports[nm] = true
			}
			// The ":TYPE" suffix may name a RECORD template, which makes the
			// external symbol's fields reachable as NAME.FIELD (Start.aii
			// does "import FSTInfoParms:tFSTInfo" then "FSTInfoParms.fst_num").
			rec := st.sym(strings.TrimSpace(kind))
			for f, off := range st.recFields[rec] {
				v := fwdVal(nm)
				v.C = off
				if st.recEqus[rec][f] {
					// a template EQU is a constant, not an instance field
					v = num(off)
				}
				// file-wide BEFORE defining: define() consults fileWide to
				// decide whether to scope the key to the current segment
				st.fileWide[nm+"."+f] = true
				st.define(nm+"."+f, v)
			}
		}
		return
	case "entry", "export":
		// Both publish a symbol to the linker: a record is emitted where the
		// symbol is defined, and references use the symbol name. They differ
		// only in the private byte (ENTRY 1, EXPORT 0).
		priv := byte(0)
		if op == "entry" {
			priv = 1
		}
		for _, a := range symbolList(operandOnly(l.rest)) {
			// optional ":TYPE" suffix, e.g. "cmd_tbl:data" or "c_len_len:EQU"
			name, kind, _ := strings.Cut(a, ":")
			nm := st.sym(strings.TrimSpace(name))
			if nm == "" {
				continue
			}
			st.entries[nm] = true
			st.fileWide[nm] = true
			// EXPORT wins over ENTRY whichever order they come in: scm
			// declares "export fst_count" once and "entry fst_count" twice
			// more, and the GLOBAL is still public (oracle-probed).
			if _, seen := st.entryPriv[nm]; priv == 0 || !seen {
				st.entryPriv[nm] = priv
			}
			// A directive inside a segment pins the publication to the
			// definition standing in that segment; one at file scope leaves
			// it to the first definition seen.
			if st.cur != nil {
				st.entrySeg[nm] = st.curSegIndex()
			} else if _, seen := st.entrySeg[nm]; !seen {
				st.entrySeg[nm] = -1
			}
			if strings.EqualFold(strings.TrimSpace(kind), "equ") {
				st.entryEqu[nm] = true
			}
		}
		return
	case "write", "writeln", "writehex":
		// listing-directed output; no effect on the object
		return
	case "org":
		if st.cur == nil {
			st.errf("ORG outside PROC")
			return
		}
		// A bare ORG restores the location counter to its high-water mark.
		if st.operandField(l.rest) == "" {
			if st.pc > st.segHigh {
				st.segHigh = st.pc
			}
			if st.segHigh > st.pc {
				st.addAction(action{kind: aDS, count: st.segHigh - st.pc})
				st.pc = st.segHigh
			}
			return
		}
		// The operand may name a label in this segment: AD3.5.data does
		// "ORG trk_ctr" to overlay a later field on earlier storage.
		val, err := evalExpr(st.operandField(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("ORG: %v", err)
			return
		}
		v := val.C
		if !val.isNum() {
			if len(val.Pos) != 1 || len(val.Neg) != 0 || val.Pos[0].fwd != "" ||
				val.Pos[0].seg != st.curSegIndex() {
				st.errf("ORG: expression must be constant: %q", l.rest)
				return
			}
		}
		if st.pc > st.segHigh {
			st.segHigh = st.pc
		}
		if v < st.pc {
			// Moving back to overlay storage already reserved: the original
			// emits an OMF ORG record carrying the signed displacement
			// rather than rewriting the bytes.
			st.addAction(action{kind: aOrg, count: v - st.pc})
			st.pc = v
			return
		}
		if v > st.pc {
			st.addAction(action{kind: aDS, count: v - st.pc})
			st.pc = v
		}
		return
	case "ds", "ds.b", "ds.w", "ds.l":
		// A bare DS counts WORDS, not bytes: the device dispatcher reserves
		// its 32-character replacement name with "ds 32" and gets 64 bytes.
		size := int64(2)
		switch op {
		case "ds.b":
			size = 1
		case "ds.l":
			size = 4
		}
		if !st.storageLine(l.label) && l.label != "" {
			st.defineCodeLabel(l.label)
		}
		// "POpen ds openParms" reserves one instance of a RECORD template and
		// makes its fields reachable as POpen.field. In a data segment the
		// qualified names stay file-wide (the Loader reads Header.DispName
		// from its Globals record across segments), like RECORD.FIELD.
		if rec := st.sym(st.operandField(l.rest)); st.recSize[rec] != 0 {
			base := st.pc
			if l.label != "" {
				for f, off := range st.recFields[rec] {
					q := st.sym(l.label) + "." + f
					if st.cur.kind&0x1F == 0x01 {
						st.fileWide[q] = true
					}
					if st.recEqus[rec][f] {
						st.define(q, num(off))
						continue
					}
					st.define(q, segVal(st.curSegIndex(), base+off))
				}
			}
			st.addAction(action{kind: aDS, count: st.recSize[rec]})
			st.pc += st.recSize[rec]
			return
		}
		n, err := evalNum(st.operandField(l.rest), &exprCtx{st: st})
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
		if op != "endr" {
			st.errf("undefined macro or opcode: %s", strings.ToUpper(l.op))
			return
		}
		// A data segment opened by a bare RECORD closes with either ENDR or
		// ENDP; only a template's ENDR is handled in doRecordLine.
		if st.cur == nil {
			st.errf("ENDR without RECORD")
			return
		}
		st.cur.endPC = st.pc
		st.cur = nil
		return
	}

	if _, isInst := opTable[op]; isInst {
		if l.label != "" {
			st.defineCodeLabel(l.label)
		}
		st.doInst(op, st.operandField(l.rest))
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

// beginSegment opens a segment with no options beyond its OMF kind.
func (st *asmState) beginSegment(label string, kind uint16) {
	name := st.sym(label)
	if name == "" {
		st.errf("segment requires a label")
		return
	}
	st.openSegment(&segState{name: name, loadName: st.loadName,
		imports: map[string]bool{}, kind: kind})
}

func (st *asmState) openSegment(seg *segState) {
	// A PROC closes whatever was still open: ExpressLoad's get_seg_base has
	// no ENDP at all, and leaving its length at zero produced a segment whose
	// records were right but whose header said it was empty.
	if st.cur != nil {
		st.cur.endPC = st.pc
	}
	st.withs = nil // WITH scoping does not cross a segment boundary
	// A segment whose own label is EXPORTed is not private: UniDisk3.5 says
	// "EXPORT driver_data" before "driver_data PROC" and its segment is
	// KIND $0000 (oracle-verified), the same as writing "PROC EXPORT".
	if !seg.kindSet && st.entries[seg.name] && st.entryPriv[seg.name] == 0 {
		seg.kind, seg.kindSet = 0x0000, true
	}
	st.segs = append(st.segs, seg)
	st.cur = seg
	st.pc = 0
	st.segHigh = 0
	for _, rec := range st.pendingRecs {
		seg.actions = append(seg.actions, action{kind: aRec, bytes: rec})
	}
	st.pendingRecs = nil
	// The segment's own label names it, so the label stays visible to the
	// whole file even though the labels inside it do not.
	if seg.name != "" {
		st.fileWide[seg.name] = true
		st.segNames[seg.name] = true
		st.define(seg.name, segVal(st.curSegIndex(), 0))
	}
}

// storageLine opens the one-line data segment a file-scope storage
// declaration gets. Every "label ds n" (or dc/dcb) between PROCs is its OWN
// KIND $4001 segment named by its label -- "" when unlabeled -- and the next
// storage line opens another; nothing is appended to the previous segment
// (oracle-probed; DOS3.3.FST includes DOS.FST.storage between two PROCs and
// its references resolve segment by segment). Returns true when it opened
// one, in which case the label is already defined as the segment name.
func (st *asmState) storageLine(label string) bool {
	if st.ended || (st.cur != nil && !st.cur.storage) {
		return false
	}
	st.openSegment(&segState{name: st.sym(label), loadName: st.loadName,
		imports: map[string]bool{}, kind: 0x4001, kindSet: true, storage: true})
	return true
}

func (st *asmState) defineCodeLabel(name string) {
	// Storage declared between PROCs (an included .storage file, say) belongs
	// to no segment's scope, so it stays visible file-wide even though the
	// bytes land in whichever segment is resumed.
	outside := st.cur == nil
	if !st.resumeSegment() {
		st.errf("label %q outside PROC", name)
		return
	}
	if outside {
		st.fileWide[st.sym(name)] = true
	}
	st.define(name, segVal(st.curSegIndex(), st.pc))
	u := st.sym(name)
	// Fields of a RECORD data segment are also reachable through the
	// qualified "record.field" form, as a template's fields are; the
	// qualified name stays file-wide even though the plain name is scoped
	// to the data segment.
	if st.cur.kind&0x1F == 0x01 && u != st.cur.name {
		q := st.cur.name + "." + u
		st.fileWide[q] = true
		st.define(q, segVal(st.curSegIndex(), st.pc))
	}
	// A published name yields exactly ONE GLOBAL record, at its last
	// definition -- ProDOS.FST defines clear_index twice and the original
	// publishes only the second. A name that also names a segment yields
	// none: the export shows up as the segment's KIND instead (get_time is
	// both a PROC and, much later, a plain label).
	if st.entries[u] && !st.entryEqu[u] && !st.segNames[u] {
		st.globalNth[u]++
		pinned, ok := st.entrySeg[u]
		_, chosen := st.pubGseq[u]
		// The pinned segment's definition wins; failing that, the first.
		if (ok && pinned == st.curSegIndex()) || (!chosen && (!ok || pinned < 0)) {
			st.pubGseq[u] = st.globalNth[u]
			st.lastPubSeq[u] = st.defSeq
		}
		st.addAction(action{kind: aRec, bytes: globalRec(u, st.entryPriv[u]),
			global: u, gseq: st.globalNth[u]})
	}
}

// publishedAt reports whether a term names the definition that a published
// symbol's GLOBAL record actually declares. Publication attaches to one
// definition, not to the name: ProDOS.FST's file-scope "ENTRY clear_index"
// covers only the second of the two definitions, so the earlier local one
// still folds into a branch displacement like any other label.
func (st *asmState) publishedAt(t term) bool {
	if t.name == "" || !st.entries[t.name] || st.segNames[t.name] {
		return false
	}
	seq, ok := st.lastPubSeq[t.name]
	return !ok || t.defSeq == seq
}

// globalRec builds a GLOBAL record for a published label (oracle-verified:
// name, length=0, type 'M', then the private byte).
func globalRec(name string, private byte) []byte {
	rec := append([]byte{0xE6, byte(len(name))}, name...)
	return append(rec, 0x00, 0x00, 'M', private)
}

// gequRec builds a GEQU record: the same header as GLOBAL followed by the
// symbol's value as an expression (constant, end).
func gequRec(name string, private byte, v int64) []byte {
	rec := append([]byte{0xE7, byte(len(name))}, name...)
	rec = append(rec, 0x00, 0x00, 'M', private, 0x81)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return append(append(rec, b[:]...), 0x00)
}

// recField places one field of `size` bytes in the open RECORD template and
// binds its label to the field's own offset.
//
// In a "RECORD start,decrement" template the fields build downward, so a
// field's offset is the template pointer *after* the subtraction, not before
// -- the field occupies the bytes below the pointer, not above it. The
// console driver's direct page is built this way, and getting it backwards
// slid every field one slot (drvr_parm_ptr came out $E6 instead of $E2).
func (st *asmState) recField(label string, size int64, def func(string, Val)) {
	if st.recDown {
		st.recPC -= size
	}
	if label != "" {
		def(label, num(st.recPC))
	}
	if !st.recDown {
		st.recPC += size
	}
}

// doRecordLine handles lines inside RECORD ... ENDR: a template that only
// defines constants (field offsets); nothing is emitted.
func (st *asmState) doRecordLine(op string, l line) {
	// A template's fields are reachable as RECORD.FIELD from anywhere, and
	// unqualified only inside the template itself -- DP.a pads with
	// "if (dp_end MOD 2) <> 0" right where dp_end is declared, but a bare
	// field name outside is "Undefined ID" (oracle-probed). Leaving them
	// defined globally let a template field shadow a PROC of the same name:
	// the loader's call table folded "DC.L LoadName-1" to a constant.
	defField := func(name string, v Val) {
		// In a RECORD IMPORT the storage is external: a ds-declared field is
		// the imported base symbol plus its offset, not a bare constant (an
		// EQU inside stays a constant, same as recEqus for instances).
		if st.recImport && v.isNum() && op != "equ" && op != "set" {
			iv := fwdVal(st.recName)
			iv.C = v.C
			v = iv
		}
		if key := st.sym(name); key != "" {
			prev, had := st.syms[key]
			st.recBare = append(st.recBare,
				bareField{key: key, val: prev, had: had, seqLen: len(st.symSeq[key])})
		}
		st.define(name, v)
		if st.recName != "" && name != "" {
			st.define(st.recName+"."+st.sym(name), v)
			if v.isNum() {
				if st.recFields[st.recName] == nil {
					st.recFields[st.recName] = map[string]int64{}
				}
				st.recFields[st.recName][st.sym(name)] = v.C
			}
		}
	}
	switch op {
	case "endr", "endp", "endf", "end":
		// MPW closes a RECORD template with ENDR or ENDP (both appear in the
		// GS/OS sources); END closes everything.
		if st.recName != "" {
			st.recSize[st.recName] = st.recPC
		}
		// Restore in reverse: a field may shadow a global equate of the same
		// name (SCSIHD.Equates has "removable" both ways), and deleting it
		// outright took the equate with it.
		for i := len(st.recBare) - 1; i >= 0; i-- {
			b := st.recBare[i]
			if b.had {
				st.syms[b.key] = b.val
			} else {
				delete(st.syms, b.key)
			}
			if len(st.symSeq[b.key]) > b.seqLen {
				st.symSeq[b.key] = st.symSeq[b.key][:b.seqLen]
			}
		}
		st.recBare = nil
		st.inRecord = false
		st.recImport = false
		st.recName = ""
		if op == "end" {
			st.ended = true
		}
		return
	case "org":
		// A bare ORG restores the location counter to its high-water mark,
		// which is how overlapping ORG regions in a template are unioned.
		if st.operandField(l.rest) == "" {
			if st.recPC > st.recHigh {
				st.recHigh = st.recPC
			}
			st.recPC = st.recHigh
			return
		}
		v, err := evalNum(st.operandField(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("RECORD ORG: %v", err)
			return
		}
		if st.recPC > st.recHigh {
			st.recHigh = st.recPC
		}
		st.recPC = v
		return
	case "ds", "ds.b", "ds.w", "ds.l":
		// A bare DS counts WORDS, not bytes: the device dispatcher reserves
		// its 32-character replacement name with "ds 32" and gets 64 bytes.
		size := int64(2)
		switch op {
		case "ds.b":
			size = 1
		case "ds.l":
			size = 4
		}
		// "MSDos_stuff ds msdos_vcr" nests one template inside another:
		// it reserves the inner template's size and aliases its fields as
		// label.field at the current offset.
		if rec := st.sym(st.operandField(l.rest)); st.recSize[rec] != 0 {
			base := st.recPC
			if l.label != "" {
				for f, off := range st.recFields[rec] {
					if st.recEqus[rec][f] {
						defField(st.sym(l.label)+"."+f, num(off))
						continue
					}
					defField(st.sym(l.label)+"."+f, num(base+off))
				}
			}
			st.recField(l.label, st.recSize[rec], defField)
			return
		}
		n, err := evalNum(st.operandField(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("RECORD DS: %v", err)
			return
		}
		st.recField(l.label, n*size, defField)
		return
	case "equ", "set":
		v, err := evalExpr(st.operandField(l.rest), &exprCtx{st: st})
		if err != nil {
			st.errf("%s: %v", strings.ToUpper(op), err)
			return
		}
		// An equate inside a template is reachable as RECORD.NAME too --
		// DP.a ends with "dir_page_size equ *" and Data.a reserves
		// "DirectPage.dir_page_size+2" bytes from it.
		defField(l.label, v)
		if st.recName != "" && l.label != "" {
			if st.recEqus[st.recName] == nil {
				st.recEqus[st.recName] = map[string]bool{}
			}
			st.recEqus[st.recName][st.sym(l.label)] = true
		}
		return
	case "", "anop":
		if l.label != "" {
			defField(l.label, num(st.recPC))
		}
		return
	case "dc", "dc.b", "dc.w", "dc.l", "dc.a", "dcb", "dcb.b":
		// Inside a RECORD template, DC directives only size the field: the
		// label takes the field's template offset and no bytes are emitted.
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
		st.recField(l.label, n*unit, defField)
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
	if !st.storageLine(l.label) && l.label != "" {
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
	// The operand field ends at the first blank outside a quoted string, so a
	// bare trailing comment is not part of it -- these sources contain typos
	// like "DC.L ctree_idx_rec  'ptr to ..." where the comment opens with a
	// quote instead of a semicolon. An adjoining operator continues the
	// expression past the blank (see dcOperand).
	for _, item := range splitArgs(st.dcOperand(l.rest)) {
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
			b := macRomanBytes(s)
			if st.msb {
				for i := range b {
					b[i] |= 0x80
				}
			}
			if st.strMode == "PASCAL" {
				b = append([]byte{byte(len(b))}, b...)
			} else if st.strMode == "C" {
				// STRING C: NUL-terminated (DOS3.3.FST's volume name table)
				b = append(b, 0)
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
			st.addAction(action{kind: aExpr, target: v, size: size, rec: byte(recLexpr), shift: shift + v.Shift})
			st.pc += int64(size)
		}
	}
}

// exprRecFor picks the expression record for an instruction operand. BEXPR
// asks the linker to check that the address lands in the current bank, so it
// applies to any two-byte operand -- absolute, indirect, even immediate --
// while long transfers and DC data are always LEXPR.
//
// CODECHK governs a direct-absolute jmp/jsr and defaults on; DATACHK governs
// everything else and defaults off. An indirect jmp goes with DATACHK: its
// operand is a pointer's address, not the destination (all oracle-probed).
func (st *asmState) exprRecFor(mn string, chosen Mode, n int) byte {
	if n != 2 {
		return recLexpr
	}
	if (mn == "jmp" || mn == "jsr") && chosen == Abs {
		if st.codeChk {
			return recBexpr
		}
		return recLexpr
	}
	if st.dataChk {
		return recBexpr
	}
	return recLexpr
}

func (st *asmState) doDCB(op string, l line) {
	if !st.storageLine(l.label) && l.label != "" {
		st.defineCodeLabel(l.label)
	}
	args := splitArgs(l.rest)
	if len(args) != 2 {
		st.errf("DCB.B needs count,value")
		return
	}
	n, err1 := evalNum(strings.TrimSpace(args[0]), &exprCtx{st: st})
	if err1 != nil {
		st.errf("DCB.B: bad operands")
		return
	}
	// The fill value is a data item like any other, so under STRING PASCAL a
	// quoted one carries its length byte and each repeat is two bytes wide:
	// the SCSI manager's "dcb.b 20,' '" name padding is 40 bytes, not 20.
	if fill := strings.TrimSpace(args[1]); st.strMode == "PASCAL" && len(fill) > 1 && fill[0] == '\'' {
		s, err := unquote(fill)
		if err != nil {
			st.errf("DCB: %v", err)
			return
		}
		b := macRomanBytes(s)
		if st.msb {
			for i := range b {
				b[i] |= 0x80
			}
		}
		b = append([]byte{byte(len(b))}, b...)
		var out []byte
		for i := int64(0); i < n; i++ {
			out = append(out, b...)
		}
		st.emitBytes(out...)
		return
	}
	v, err2 := evalNum(strings.TrimSpace(args[1]), &exprCtx{st: st})
	if err2 != nil {
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
		// opcode, dstbank, srcbank (oracle-verified). A relocatable operand
		// (AppleDisk5.25's "mvn xtra_dstat1,dstat1") emits a 1-byte LEXPR of
		// label >> 16 -- the linker extracts the bank.
		parts := splitArgs(exprStr)
		if len(parts) != 2 {
			st.errf("%s: need two operands", mn)
			return
		}
		st.emitBytes(info.code)
		for _, p := range [2]string{parts[1], parts[0]} { // dst first
			v, err := evalExpr(p, &exprCtx{st: st})
			if err != nil {
				st.errf("%s: bad operands", mn)
				return
			}
			if v.isNum() {
				st.emitBytes(byte(v.C >> 16))
				continue
			}
			st.addAction(action{kind: aExpr, target: v, size: 1,
				rec: recLexpr, shift: -16 + v.Shift})
			st.pc++
		}
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
		rec := st.exprRecFor(mn, chosen, n)
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
		rec := st.exprRecFor(mn, chosen, n)
		st.emitBytes(info.code)
		st.addAction(action{kind: aExpr, target: val, size: n, rec: rec, shift: shift + val.Shift})
		st.pc += int64(n)
	default:
		// The opcode and its operand are separate emission units, which is
		// what lets a CONST run end between them: the loader's Process_Reloc
		// has an "lsr $60" whose opcode fills one LCONST to 255 and whose
		// operand opens the next.
		st.emitBytes(info.code)
		c := applyShift(val.C, shift)
		var b []byte
		for i := 0; i < n; i++ {
			b = append(b, byte(c>>(8*i)))
		}
		if len(b) > 0 {
			st.emitBytes(b...)
		}
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
