package asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// The preprocessor layer: INCLUDE, IF/ELSEIF/ELSE/ENDIF conditionals, and
// the MPW asm macro language (MACRO/MEND, &param substitution, LCLA/LCLC/
// GBLA set-variables, SETA/SETC, and the & builtin functions used by the
// GS/OS-era sources).

type macroDef struct {
	labelVar string   // "&lab" prototype label variable (upper, no &)
	namePre  string   // literal name, lowercased; for "equds.&siz" this is "equds."
	nameVar  string   // param bound to the name suffix ("" if exact-match name)
	params   []string // positional parameter names (upper, no &)
	defaults []string // per-param default value ("&creator=$FFFFFFFF"), "" if none
	body     []string
}

type condFrame struct {
	parentActive bool
	active       bool
	taken        bool
}

type ppFrame struct { // one macro expansion
	vars map[string]string
}

type ppState struct {
	st      *asmState
	macros  map[string]*macroDef // key: namePre (lowercase)
	globals map[string]string
	frames  []*ppFrame
	conds   []condFrame

	capturing *macroDef
	protoNext bool // next line is the macro prototype

	incDirs []string
	// DUMP/LOAD precompiled symbol tables (the AppleShare FST's
	// equates.dump). Our .dump file is a stub naming the source that built
	// it; LOAD replays that source into the current state, stopping at its
	// DUMP directive (loadDepth > 0 while replaying, stopLoad unwinds it).
	curDir    string              // MPW current directory, for DUMP's path
	defines   []string            // this invocation's -d list, recorded in the stub
	getenv    func(string) string // MPW shell variables (&GETENV)
	loadDepth int
	stopLoad  bool
	// mexit is set by MEXIT to stop expanding the current macro body
	mexit bool
	// gotoTarget is the sequence symbol a GOTO is skipping forward to
	gotoTarget string
	// whileCond/whileBody capture a WHILE ... ENDWHILE macro loop
	whileCond  string
	whileBody  []string
	whileDepth int
	inWhile    bool
}

func newPP(st *asmState) *ppState {
	return &ppState{st: st, macros: map[string]*macroDef{}, globals: map[string]string{}}
}

func (pp *ppState) active() bool {
	for _, c := range pp.conds {
		if !c.active {
			return false
		}
	}
	return true
}

// ---------- file/line driving ----------

func (pp *ppState) processFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var text string
	if utf8.Valid(data) {
		text = string(data)
	} else if d, derr := charmap.Macintosh.NewDecoder().Bytes(data); derr == nil {
		text = string(d) // classic-Mac MacRoman interface files
	} else {
		text = string(data)
	}
	src := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	pp.processSource(src, path)
	return nil
}

// stripAsmComment removes a ';' comment (outside quotes); a '*' or ';' in
// column one makes the whole line a comment.
func stripAsmComment(s string) string {
	if s != "" && (s[0] == '*' || s[0] == ';') {
		return ""
	}
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inStr = !inStr
		case ';':
			if !inStr {
				return s[:i]
			}
		}
	}
	return s
}

// findInclude resolves an INCLUDE spec: the including file's directory
// first, then the search path, matching names case-insensitively (MPW file
// names are case-insensitive and the sources are inconsistent).
func (pp *ppState) findInclude(spec string) string {
	direct := mpwPath(filepath.Dir(pp.st.curFile), spec)
	if _, err := os.Stat(direct); err == nil {
		return direct
	}
	base := spec
	if i := strings.LastIndex(base, ":"); i >= 0 {
		base = base[i+1:]
	}
	dirs := append([]string{filepath.Dir(pp.st.curFile)}, pp.incDirs...)
	for _, d := range dirs {
		cand := filepath.Join(d, base)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			// '/' is an ordinary character in a Mac filename (":" separates
			// there), so a name like "SCSI Get Vol/Disk" reaches this tree
			// with '_' in its place.
			if strings.EqualFold(ent.Name(), base) ||
				strings.EqualFold(ent.Name(), strings.ReplaceAll(base, "/", "_")) {
				return filepath.Join(d, ent.Name())
			}
		}
	}
	return direct
}

// ---------- DUMP/LOAD precompiled symbol tables ----------
//
// The original AsmIIGS writes a binary snapshot of its symbol table, macros
// and records; other files LOAD it in place of re-including everything (the
// AppleShare FST is the only GS/OS user). The dump file is a build
// intermediate nothing shipped ever contains, so instead of matching its
// format we write a stub naming the source (and -d defines) that produced
// it; LOAD replays that source into the current state up to its DUMP
// directive, which reproduces the snapshot semantics.

const dumpStubMagic = ";asmiigs-dump v1"

func (pp *ppState) writeDump(spec string) {
	st := pp.st
	dir := pp.curDir
	if dir == "" {
		dir = filepath.Dir(st.curFile)
	}
	path := mpwPath(dir, spec)
	src := st.curFile
	if abs, err := filepath.Abs(src); err == nil {
		src = abs
	}
	var b strings.Builder
	b.WriteString(dumpStubMagic + "\n")
	b.WriteString(";source=" + src + "\n")
	for _, d := range pp.defines {
		b.WriteString(";define=" + d + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		st.errf("DUMP %s: %v", spec, err)
		return
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		st.errf("DUMP %s: %v", spec, err)
	}
}

func (pp *ppState) doLoad(spec string) {
	st := pp.st
	path := pp.findInclude(spec)
	data, err := os.ReadFile(path)
	if err != nil {
		st.errf("LOAD %s: %v", spec, err)
		return
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != dumpStubMagic {
		st.errf("LOAD %s: not an asmiigs dump stub", spec)
		return
	}
	src := ""
	for _, ln := range lines[1:] {
		if v, ok := strings.CutPrefix(ln, ";source="); ok {
			src = v
		} else if v, ok := strings.CutPrefix(ln, ";define="); ok {
			st.applyDefine(v)
		}
	}
	if src == "" {
		st.errf("LOAD %s: stub names no source", spec)
		return
	}
	pp.loadDepth++
	err = pp.processFile(src)
	pp.loadDepth--
	pp.stopLoad = false
	if err != nil {
		st.errf("LOAD %s: %v", spec, err)
	}
}

func (pp *ppState) processSource(src, path string) {
	st := pp.st
	prevFile, prevLine := st.curFile, st.curLine
	st.curFile = path
	lines := strings.Split(src, "\n")
	for n := 0; n < len(lines); n++ {
		if st.ended || pp.stopLoad {
			break
		}
		raw := lines[n]
		st.curLine = n + 1
		// A trailing '\' continues the statement on the next line (the
		// driver sources wrap long expressions this way). The marker sits
		// before any comment, so comments are removed first.
		if body, cont := splitContinuation(stripAsmComment(raw)); cont {
			joined := body
			for n+1 < len(lines) {
				next := stripAsmComment(lines[n+1])
				n++
				if body, cont := splitContinuation(next); cont {
					joined = joinContinuation(joined, body)
					continue
				}
				joined = joinContinuation(joined, next)
				break
			}
			raw = joined
		}
		pp.processLine(raw)
	}
	st.curFile, st.curLine = prevFile, prevLine
}

// splitContinuation reports whether a line is continued, returning the text
// before the '\'. Apple's own note in DOS3.3.FST says it: "The presence of
// comments after the line continuation character (\) is NOT officially
// supported by the MAX assembler but works fine for version 1.1d9" -- so
// anything after the marker is commentary, not part of the statement.
func splitContinuation(s string) (string, bool) {
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inStr = !inStr
		case '\\':
			if !inStr {
				return strings.TrimRight(s[:i], " \t"), true
			}
		}
	}
	return s, false
}

// joinContinuation appends a '\'-continued line to what came before it.
//
// The break may fall in the middle of an expression ("#bit_6++\" + "bit_7")
// or between whole tokens ("IF block_dvc = true\" + "AND ..."). The original
// assembler keeps both working, so keep the pieces adjacent when either side
// carries an operator and separate them otherwise; inserting a blank into an
// expression would end the operand field under BLANKS OFF.
func joinContinuation(acc, next string) string {
	next = strings.TrimLeft(next, " \t")
	isOp := func(c byte) bool { return strings.IndexByte("+-*/<>=&|^,()[]#", c) >= 0 }
	if acc == "" || next == "" {
		return acc + next
	}
	if isOp(acc[len(acc)-1]) || isOp(next[0]) {
		return acc + next
	}
	return acc + " " + next
}

// splitIfGoto separates "cond GOTO .sym" into its parts.
func splitIfGoto(rest string) (cond, target string, ok bool) {
	up := strings.ToUpper(rest)
	i := strings.Index(up, "GOTO")
	if i < 0 {
		return "", "", false
	}
	if i > 0 && !isSpaceByte(rest[i-1]) {
		return "", "", false
	}
	target = strings.TrimSpace(operandOnly(strings.TrimSpace(rest[i+4:])))
	if !strings.HasPrefix(target, ".") {
		return "", "", false
	}
	return strings.TrimSpace(rest[:i]), target, true
}

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' }

// runWhile executes a captured WHILE body until its condition goes false.
func (pp *ppState) runWhile() {
	cond, body := pp.whileCond, pp.whileBody
	pp.inWhile, pp.whileCond, pp.whileBody = false, "", nil
	for n := 0; pp.condEval(pp.subst(cond)); n++ {
		if n > 100000 {
			pp.st.errf("WHILE %s: loop does not terminate", cond)
			return
		}
		for _, bl := range body {
			if pp.st.ended {
				return
			}
			pp.processLine(bl)
		}
	}
}

func (pp *ppState) processLine(raw string) {
	st := pp.st
	if st.ended {
		return
	}
	// A whole-line comment is not scanned for & references. Ours were being
	// substituted, so a comment that merely mentioned "&s2i(&n)" raised an
	// error about an undefined macro parameter.
	if raw != "" && (raw[0] == ';' || raw[0] == '*') {
		return
	}

	// macro capture mode
	if pp.capturing != nil {
		if pp.protoNext {
			pp.protoNext = false
			pp.parseProto(raw)
			return
		}
		l := splitLine(raw)
		op := strings.ToLower(l.op)
		if op == "mend" || op == "endm" {
			def := pp.capturing
			pp.capturing = nil
			pp.macros[def.namePre] = def
			return
		}
		pp.capturing.body = append(pp.capturing.body, raw)
		return
	}

	l := splitLine(raw)
	op := strings.ToLower(l.op)

	// WHILE cond DO ... ENDWHILE: capture the body, then run it while the
	// condition holds. The gsos HEX macro walks a string this way.
	if pp.inWhile {
		switch op {
		case "while":
			pp.whileDepth++
		case "endwhile":
			if pp.whileDepth > 0 {
				pp.whileDepth--
			} else {
				pp.runWhile()
				return
			}
		}
		pp.whileBody = append(pp.whileBody, raw)
		return
	}
	if op == "while" && pp.active() {
		cond := strings.TrimSpace(l.rest)
		if up := strings.ToUpper(cond); strings.HasSuffix(up, "DO") {
			cond = strings.TrimSpace(cond[:len(cond)-2])
		}
		pp.whileCond, pp.whileBody, pp.inWhile = cond, nil, true
		return
	}
	if op == "endwhile" {
		// A WHILE inside an inactive conditional was skipped, so its ENDWHILE
		// is skipped too rather than reported.
		if pp.active() {
			st.errf("ENDWHILE without WHILE")
		}
		return
	}

	// A GOTO skips forward to the line whose label field holds the matching
	// sequence symbol (".tl1"); everything in between is not assembled. The
	// target line itself still is -- ".a phb" both marks the target and
	// assembles an instruction.
	if pp.gotoTarget != "" {
		if !strings.EqualFold(l.label, pp.gotoTarget) {
			return
		}
		pp.gotoTarget = ""
	}
	// A sequence symbol is a branch target for GOTO, not a program label.
	if strings.HasPrefix(l.label, ".") {
		raw = strings.Repeat(" ", len(l.label)) + raw[len(l.label):]
		l = splitLine(raw)
		op = strings.ToLower(l.op)
	}
	if op == "goto" || op == "ago" {
		pp.gotoTarget = strings.TrimSpace(operandOnly(pp.subst(l.rest)))
		return
	}

	// MEXIT leaves the macro body early (MEND still closes the definition).
	if op == "mexit" && pp.active() {
		pp.mexit = true
		return
	}

	// conditional structure is tracked even in inactive regions
	switch op {
	case "if":
		if !pp.active() {
			// "IF cond GOTO .sym" opens no block even when skipped: mlisrc's
			// "if 0 then" region contains one, and pushing a frame for it
			// made the region's ENDIF pop the wrong conditional and swallow
			// the rest of the file.
			if _, _, ok := splitIfGoto(l.rest); ok {
				return
			}
			pp.conds = append(pp.conds, condFrame{parentActive: false})
			return
		}
		// "IF cond GOTO .sym" branches instead of opening a block.
		if cond, target, ok := splitIfGoto(pp.subst(l.rest)); ok {
			if pp.condEval(cond) {
				pp.gotoTarget = target
			}
			return
		}
		v := pp.condEval(pp.subst(l.rest))
		pp.conds = append(pp.conds, condFrame{parentActive: true, active: v, taken: v})
		return
	case "elseif":
		if len(pp.conds) == 0 {
			st.errf("ELSEIF without IF")
			return
		}
		c := &pp.conds[len(pp.conds)-1]
		if !c.parentActive {
			return
		}
		if c.taken {
			c.active = false
		} else {
			v := pp.condEval(pp.subst(l.rest))
			c.active, c.taken = v, v
		}
		return
	case "else":
		if len(pp.conds) == 0 {
			st.errf("ELSE without IF")
			return
		}
		c := &pp.conds[len(pp.conds)-1]
		if c.parentActive {
			c.active = !c.taken
			c.taken = true
		}
		return
	case "endif":
		if len(pp.conds) == 0 {
			st.errf("ENDIF without IF")
			return
		}
		pp.conds = pp.conds[:len(pp.conds)-1]
		return
	}
	if !pp.active() {
		return
	}

	switch op {
	case "macro":
		pp.capturing = &macroDef{}
		pp.protoNext = true
		return
	case "lcla", "lclc", "gbla", "gblc":
		pp.declareVars(op, l.rest)
		return
	case "seta", "setc":
		pp.setVar(op, l)
		return
	case "include":
		spec := strings.TrimSpace(l.rest)
		if s, err := unquote(operandOnly(spec)); err == nil {
			spec = s
		}
		path := pp.findInclude(spec)
		if err := pp.processFile(path); err != nil {
			st.errf("INCLUDE %s: %v", spec, err)
		}
		return
	case "dump":
		// DUMP 'file' snapshots the symbol/macro state. While replaying a
		// source under LOAD it instead marks where the snapshot was taken:
		// everything past it was not in the dump.
		if pp.loadDepth > 0 {
			pp.stopLoad = true
			return
		}
		spec := strings.TrimSpace(l.rest)
		if s, err := unquote(operandOnly(spec)); err == nil {
			spec = s
		}
		pp.writeDump(spec)
		return
	case "load":
		spec := strings.TrimSpace(l.rest)
		if s, err := unquote(operandOnly(spec)); err == nil {
			spec = s
		}
		pp.doLoad(spec)
		return
	case "write", "writeln", "writehex":
		// listing-directed output; substitution still happens for its side
		// effects but nothing is printed or emitted
		pp.subst(l.rest)
		return
	}

	// substitute & references (macro parameters, set-variables and the
	// builtin functions); these are legal outside macros too
	if strings.ContainsRune(raw, '&') {
		l = splitLine(pp.subst(raw))
		op = strings.ToLower(l.op)
	}

	// macro invocation?
	if def, suffix := pp.findMacro(op); def != nil {
		pp.expand(def, suffix, l)
		return
	}

	st.doLine(l)
}

// ---------- macro definition & expansion ----------

func (pp *ppState) parseProto(raw string) {
	l := splitLine(raw)
	def := pp.capturing
	if strings.HasPrefix(l.label, "&") {
		def.labelVar = strings.ToUpper(l.label[1:])
	}
	name := strings.ToLower(l.op)
	if i := strings.IndexByte(name, '&'); i >= 0 {
		def.namePre = name[:i]
		def.nameVar = strings.ToUpper(strings.TrimPrefix(name[i:], "&"))
	} else {
		def.namePre = name
	}
	for _, p := range splitArgs(l.rest) {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "&") {
			// "&param=value" gives the parameter a default, taken when the
			// invocation omits the argument (AppleShare's ftype macro:
			// "&creator=$FFFFFFFF").
			name, dflt, _ := strings.Cut(p[1:], "=")
			def.params = append(def.params, strings.ToUpper(strings.TrimSpace(name)))
			def.defaults = append(def.defaults, strings.TrimSpace(dflt))
		}
	}
}

// findMacro matches an op against defined macros, handling interpolated
// names like "equds.&siz" (returns the bound suffix).
func (pp *ppState) findMacro(op string) (*macroDef, string) {
	if def, ok := pp.macros[op]; ok && def.nameVar == "" {
		return def, ""
	}
	for pre, def := range pp.macros {
		if def.nameVar == "" {
			continue
		}
		if strings.HasPrefix(op, pre) {
			return def, op[len(pre):]
		}
		// "equds.&siz" also matches bare "equds" (empty suffix)
		if strings.HasSuffix(pre, ".") && op == pre[:len(pre)-1] {
			return def, ""
		}
	}
	return nil, ""
}

func (pp *ppState) expand(def *macroDef, nameSuffix string, inv line) {
	frame := &ppFrame{vars: map[string]string{}}
	redirect := labelRedirect{}
	if def.labelVar != "" {
		frame.vars[def.labelVar] = inv.label
		// The invocation's label belongs to the CALLER: a plain label
		// delimits the caller's @local scope exactly as writing it outside
		// would (pascal.fst's "sys_entry PROCNAME" segments reuse @no_way;
		// without this a stale @no_way from an earlier segment leaks in).
		// An @-label instead defines INTO the caller's scope when the body's
		// "&lab" line runs ("@hitReturn _RestoreTextState" in ETalk must
		// satisfy the outer "beq @hitReturn").
		if inv.label != "" && !strings.HasPrefix(inv.label, "@") {
			pp.st.localScopeMax++
			pp.st.scopeChain[len(pp.st.scopeChain)-1] = pp.st.localScopeMax
		} else if strings.HasPrefix(inv.label, "@") {
			redirect = labelRedirect{name: pp.st.sym(inv.label),
				chainIdx: len(pp.st.scopeChain) - 1}
		}
	} else if inv.label != "" {
		// a label on an invocation of a label-less macro defines a code label
		pp.st.defineCodeLabel(inv.label)
	}
	if def.nameVar != "" {
		frame.vars[def.nameVar] = nameSuffix
	}
	// A macro argument may contain blanks -- the gsos macros are invoked as
	// "freespace SCM segment 0,seg_0_start,..." -- so the whole operand field
	// is the argument list, not just up to the first blank.
	args := splitArgs(strings.TrimRight(inv.rest, " \t"))
	for i, p := range def.params {
		v := ""
		if i < len(args) {
			v = strings.TrimSpace(args[i])
		}
		if v == "" && i < len(def.defaults) {
			v = def.defaults[i]
		}
		frame.vars[p] = v
	}
	pp.frames = append(pp.frames, frame)
	// A macro expansion pushes its own @local scope: each expansion's
	// @labels stay apart from the next one's, and the caller's scope (with
	// its @labels) resumes after the call (see scopeChain in asm.go).
	chainDepth := len(pp.st.scopeChain)
	pp.st.localScopeMax++
	pp.st.scopeChain = append(pp.st.scopeChain, pp.st.localScopeMax)
	pp.st.labelRedirect = append(pp.st.labelRedirect, redirect)
	condDepth := len(pp.conds)
	for _, bl := range def.body {
		if pp.st.ended || pp.mexit {
			break
		}
		pp.processLine(bl)
	}
	pp.st.labelRedirect = pp.st.labelRedirect[:len(pp.st.labelRedirect)-1]
	pp.st.scopeChain = pp.st.scopeChain[:chainDepth]
	pp.mexit = false
	// close any conditional left open by the body (defensive)
	if len(pp.conds) > condDepth {
		pp.conds = pp.conds[:condDepth]
	}
	pp.frames = pp.frames[:len(pp.frames)-1]
}

// ---------- set-variables ----------

func (pp *ppState) declareVars(op, rest string) {
	init := ""
	if op == "lcla" || op == "gbla" {
		init = "0"
	}
	for _, v := range splitArgs(rest) {
		v = strings.TrimSpace(v)
		if !strings.HasPrefix(v, "&") {
			continue
		}
		name := strings.ToUpper(v[1:])
		if op == "gbla" || op == "gblc" {
			if _, ok := pp.globals[name]; !ok {
				pp.globals[name] = init
			}
		} else if len(pp.frames) > 0 {
			pp.frames[len(pp.frames)-1].vars[name] = init
		}
	}
}

func (pp *ppState) setVar(op string, l line) {
	name := strings.ToUpper(strings.TrimPrefix(l.label, "&"))
	rest := pp.subst(operandOnly(l.rest))
	var val string
	if op == "seta" {
		n, err := evalNumLenient(strings.TrimSpace(rest), &exprCtx{st: pp.st})
		if err != nil {
			pp.st.errf("SETA &%s: %v", name, err)
			return
		}
		val = strconv.FormatInt(n, 10)
	} else {
		rest = strings.TrimSpace(rest)
		if s, err := unquote(rest); err == nil && strings.HasPrefix(rest, "'") {
			val = s
		} else {
			val = rest
		}
	}
	pp.assign(name, val)
}

func (pp *ppState) assign(name, val string) {
	for i := len(pp.frames) - 1; i >= 0; i-- {
		if _, ok := pp.frames[i].vars[name]; ok {
			pp.frames[i].vars[name] = val
			return
		}
	}
	pp.globals[name] = val
}

func (pp *ppState) lookupVar(name string) (string, bool) {
	name = strings.ToUpper(name)
	for i := len(pp.frames) - 1; i >= 0; i-- {
		if v, ok := pp.frames[i].vars[name]; ok {
			return v, true
		}
	}
	if v, ok := pp.globals[name]; ok {
		return v, true
	}
	// Built-in variables naming the current position. The loader asserts
	// with them: "if &SysSeg <> 'Loader    ' then AError ...", so SysSeg is
	// blank-padded to the 10-character OMF load-segment name.
	switch name {
	case "SYSDATE", "SYSTIME":
		// The build timestamp, which RAM5 and P8 stamp into their binaries.
		// Only expanded inside a macro body: at file scope the original
		// leaves the reference as literal text (oracle-verified). Set
		// SOURCE_DATE_EPOCH to pin it and make those builds reproducible.
		if len(pp.frames) == 0 {
			return "", false
		}
		t := buildTime()
		if name == "SYSDATE" {
			return t.Format("02-Jan-06"), true
		}
		return t.Format("15:04:05"), true
	case "SYSSEG":
		return fmt.Sprintf("%-10s", strings.Trim(pp.st.loadName, "'")), true
	case "SYSMOD":
		if pp.st.cur != nil {
			return pp.st.cur.name, true
		}
		return "", true
	}
	return "", false
}

// ---------- & substitution ----------

var ppFuncs = map[string]bool{
	"EVAL": true, "TRIM": true, "LEN": true, "UC": true, "LC": true,
	"CONCAT": true, "I2S": true, "SETTING": true, "FINDSYM": true,
	"ORD": true, "SUBSTR": true, "TYPE": true, "S2I": true, "GETENV": true,
}

// subst evaluates & references (variables, substrings, builtin functions) in
// a line of macro body text.
func (pp *ppState) subst(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c != '&' {
			out.WriteByte(c)
			i++
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' ||
			s[j] >= '0' && s[j] <= '9' || s[j] == '_') {
			j++
		}
		ident := s[i+1 : j]
		upper := strings.ToUpper(ident)
		if j < len(s) && s[j] == '(' && ppFuncs[upper] {
			args, end, ok := parseCallArgs(s, j)
			if !ok {
				out.WriteByte(c)
				i++
				continue
			}
			out.WriteString(pp.callFunc(upper, args))
			i = end
			continue
		}
		if v, ok := pp.lookupVar(upper); ok {
			// optional substring suffix [start:len]
			if j < len(s) && s[j] == '[' {
				if k := strings.IndexByte(s[j:], ']'); k >= 0 {
					inner := pp.subst(s[j+1 : j+k])
					if a, b, ok := parseSubstring(inner, pp); ok {
						v = substr(v, a, b)
						j = j + k + 1
					}
				}
			}
			out.WriteString(v)
			i = j
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

func parseSubstring(inner string, pp *ppState) (int64, int64, bool) {
	parts := strings.SplitN(inner, ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err1 := evalNum(strings.TrimSpace(parts[0]), &exprCtx{st: pp.st})
	b, err2 := evalNum(strings.TrimSpace(parts[1]), &exprCtx{st: pp.st})
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return a, b, true
}

func substr(s string, start, length int64) string {
	if start < 1 {
		start = 1
	}
	if start > int64(len(s)) {
		return ""
	}
	end := start - 1 + length
	if end > int64(len(s)) {
		end = int64(len(s))
	}
	return s[start-1 : end]
}

// parseCallArgs parses "(a,b,...)" starting at the '(' in s[open]; returns
// raw args and the index just past ')'.
func parseCallArgs(s string, open int) ([]string, int, bool) {
	depth := 0
	inStr := false
	start := open + 1
	var args []string
	for i := open; i < len(s); i++ {
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
				if depth == 0 {
					args = append(args, s[start:i])
					return args, i + 1, true
				}
			}
		case ',':
			if !inStr && depth == 1 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	return nil, 0, false
}

// argText resolves one function argument to its string value: quoted
// literals are unquoted, & references substituted.
func (pp *ppState) argText(a string) string {
	a = strings.TrimSpace(pp.subst(a))
	if strings.HasPrefix(a, "'") {
		if s, err := unquote(a); err == nil {
			return s
		}
	}
	return a
}

func (pp *ppState) argNum(a string) int64 {
	n, err := evalNumLenient(strings.TrimSpace(pp.subst(a)), &exprCtx{st: pp.st})
	if err != nil {
		pp.st.errf("bad numeric argument %q: %v", a, err)
		return 0
	}
	return n
}

func (pp *ppState) callFunc(name string, args []string) string {
	switch name {
	case "S2I":
		// String to integer: the loader's Stack_Cleanup sizes its pops with
		// "&s2i(&param_bytes)". Without it the condition read as non-numeric
		// and always took the tsc/tcs branch.
		if len(args) == 0 {
			return "0"
		}
		return strconv.FormatInt(pp.argNum(args[0]), 10)
	case "EVAL", "ORD":
		// &ORD yields the numeric value of its argument; the gsos macros use
		// "&segment_pc seta &segment_pc+&ord(*)" to total a segment's size.
		if len(args) != 1 {
			return "0"
		}
		return strconv.FormatInt(pp.argNum(args[0]), 10)
	case "TYPE":
		// &TYPE names a symbol's kind, or 'UNDEFINED' when it has none.
		// AD3.5 guards its defaults with
		// "if &TYPE('VERSION6X') = 'UNDEFINED' then".
		if len(args) != 1 {
			return "UNDEFINED"
		}
		nm := strings.ToUpper(strings.Trim(strings.TrimSpace(pp.rawArg(args)), "'"))
		if _, ok := pp.lookupVar(nm); ok {
			return "SETC"
		}
		if pp.st != nil {
			for _, key := range [2]string{pp.st.scopePrefix() + nm, nm} {
				if v, ok := pp.st.syms[key]; ok {
					if v.isNum() {
						return "EQU"
					}
					return "LABEL"
				}
			}
		}
		return "UNDEFINED"
	case "SUBSTR":
		// &SUBSTR(str, start, length) -- the function form of the &var[a:b]
		// substring syntax.
		if len(args) != 3 {
			return ""
		}
		return substr(pp.rawArg(args[:1]), pp.argNum(args[1]), pp.argNum(args[2]))
	case "TRIM":
		return strings.TrimSpace(pp.rawArg(args))
	case "GETENV":
		// MPW shell variable lookup; the AppleShare equates default their
		// DebugCode from &getenv('MSDDebugFlag'). Under mpwmk this reads
		// the makefile's variable table, standalone the process env.
		if pp.getenv == nil || len(args) == 0 {
			return ""
		}
		return pp.getenv(strings.Trim(strings.TrimSpace(pp.rawArg(args)), "'"))
	case "LEN":
		return strconv.Itoa(len(pp.rawArg(args)))
	case "UC":
		return strings.ToUpper(pp.rawArg(args))
	case "LC":
		return strings.ToLower(pp.rawArg(args))
	case "CONCAT":
		var b strings.Builder
		for _, a := range args {
			b.WriteString(pp.argText(a))
		}
		return b.String()
	case "I2S":
		if len(args) == 0 {
			return ""
		}
		n := pp.argNum(args[0])
		width, flag := int64(0), int64(0)
		if len(args) > 1 {
			width = pp.argNum(args[1])
		}
		if len(args) > 2 {
			flag = pp.argNum(args[2])
		}
		var s string
		if flag&1 != 0 {
			s = strings.ToUpper(strconv.FormatInt(n, 16))
		} else {
			s = strconv.FormatInt(n, 10)
		}
		// A negative width zero-fills, a positive one blank-fills, and a
		// value too wide for the field is not truncated (oracle-probed).
		// gquit builds "v4.02" with &i2s(&minor,-2).
		pad := " "
		if width < 0 {
			width, pad = -width, "0"
		}
		for int64(len(s)) < width {
			s = pad + s
		}
		return s
	case "SETTING":
		onOff := func(b bool) string {
			if b {
				return "ON"
			}
			return "OFF"
		}
		switch strings.ToUpper(pp.argText(args[0])) {
		case "MSB":
			return onOff(pp.st.msb)
		case "LONGA":
			return onOff(pp.st.longA)
		case "LONGI":
			return onOff(pp.st.longI)
		case "STRING":
			return pp.st.strMode
		}
		return ""
	case "FINDSYM":
		if len(args) < 2 {
			return "0"
		}
		name := strings.ToUpper(pp.argText(args[len(args)-1]))
		if _, ok := pp.globals[name]; ok {
			return "1"
		}
		return "0"
	}
	return ""
}

// rawArg: single-argument text form.
//
// A quoted literal written directly in the source is a string constant, so
// its delimiters are not part of the value -- &LEN('CONSOLE') is 7. Text that
// arrives by substitution is taken verbatim, delimiters and all, so a macro
// parameter whose value is 'END' has &LEN 5. Both oracle-probed; the console
// driver's DIB name padding ("dcb.b 31-&len('CONSOLE'),' '") depends on the
// first and came out two bytes short while we counted the quotes.
func (pp *ppState) rawArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	a := strings.TrimSpace(args[0])
	if isQuoted(a) {
		if u, err := unquote(a); err == nil {
			return pp.subst(u)
		}
	}
	return strings.TrimSpace(pp.subst(a))
}

// ---------- conditionals ----------

// condEval evaluates an IF/ELSEIF condition (trailing THEN stripped).
//
// The assembler distinguishes boolean-typed from integer-typed results, and
// tests them differently (verified against the original assembler): a
// comparison or a NOT/AND/OR expression is boolean and true when bit 0 is set,
// while a bare arithmetic expression is true when it is non-zero. So
// "IF 2" is true but "IF not 1" is false (not 1 = $FFFE, bit 0 clear).
func (pp *ppState) condEval(s string) bool {
	v, isBool := pp.condValue(s)
	if isBool {
		return v&1 != 0
	}
	return v != 0
}

// condValue evaluates a condition to its value plus whether that value is
// boolean-typed. NOT binds tighter than AND, which binds tighter than OR; all
// three combine bitwise.
func (pp *ppState) condValue(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if up := strings.ToUpper(s); strings.HasSuffix(up, "THEN") {
		s = strings.TrimSpace(s[:len(s)-4])
	}
	if parts := splitLogical(s, "OR"); len(parts) > 1 {
		var acc int64
		for _, p := range parts {
			v, _ := pp.condValue(p)
			acc |= v
		}
		return acc, true
	}
	if parts := splitLogical(s, "AND"); len(parts) > 1 {
		acc := int64(-1)
		for _, p := range parts {
			v, _ := pp.condValue(p)
			acc &= v
		}
		return acc, true
	}
	if f := strings.Fields(s); len(f) > 1 && strings.EqualFold(f[0], "not") {
		v, _ := pp.condValue(strings.TrimSpace(s[len(f[0]):]))
		return ^v, true
	}
	return pp.condCompare(s)
}

// splitLogical splits s on a top-level whole-word AND/OR (case-insensitive),
// ignoring occurrences inside quotes or parentheses.
func splitLogical(s, word string) []string {
	var parts []string
	depth, inStr, start := 0, false, 0
	isWordByte := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '&' || c == '.'
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'':
			inStr = !inStr
		case inStr:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && (c == word[0] || c == word[0]+32):
			if i+len(word) > len(s) || !strings.EqualFold(s[i:i+len(word)], word) {
				continue
			}
			if i > 0 && isWordByte(s[i-1]) {
				continue
			}
			if j := i + len(word); j < len(s) && isWordByte(s[j]) {
				continue
			}
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + len(word)
			i = start - 1
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return append(parts, strings.TrimSpace(s[start:]))
}

// condCompare evaluates a single comparison or bare expression.
func (pp *ppState) condCompare(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	// A bare "IF expr THEN" tests the value; anything after the expression is
	// commentary. Word operators keep their operand.
	if !strings.ContainsAny(s, "=<>≠≤≥") {
		f := strings.Fields(s)
		if len(f) > 1 && strings.EqualFold(f[0], "not") {
			s = f[0] + " " + f[1]
		} else {
			s = operandOnly(s)
		}
	}
	lhs, op, rhs := splitCompare(s)
	if op == "" && strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		if inner := s[1 : len(s)-1]; balancedParens(inner) {
			return pp.condValue(inner)
		}
	}
	if op == "" {
		n, err := evalNum(s, &exprCtx{st: pp.st})
		if err != nil {
			pp.st.errf("IF: %v", err)
			return 0, false
		}
		return n, false
	}
	ln, lerr := evalNum(lhs, &exprCtx{st: pp.st})
	rn, rerr := evalNum(rhs, &exprCtx{st: pp.st})
	if lerr == nil && rerr == nil {
		return boolVal(compareOrdered(ln, rn, op)), true
	}
	// One side did not evaluate as a number, so compare as strings. A macro
	// argument substituted into the condition often is not numeric at all.
	ls, rs := stripQuote(lhs), stripQuote(rhs)
	// Trailing blanks are significant between two quoted strings, but an
	// unquoted operand is a substituted value whose own trailing blanks are
	// indistinguishable from the whitespace separating it from the operator.
	// &SysSeg yields a blank-padded 10-character name and the loader compares
	// it against 'Loader    ', so ignore trailing blanks in that case.
	if !isQuoted(lhs) || !isQuoted(rhs) {
		ls, rs = strings.TrimRight(ls, " \t"), strings.TrimRight(rs, " \t")
	}
	if op == "=" || op == "<>" {
		eq := strings.EqualFold(ls, rs)
		return boolVal(eq == (op == "=")), true
	}
	return boolVal(compareOrderedStr(strings.ToUpper(ls), strings.ToUpper(rs), op)), true
}

func boolVal(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func compareOrdered(l, r int64, op string) bool {
	switch op {
	case "=":
		return l == r
	case "<>":
		return l != r
	case "<":
		return l < r
	case ">":
		return l > r
	case "<=":
		return l <= r
	case ">=":
		return l >= r
	}
	return false
}

func compareOrderedStr(l, r, op string) bool {
	switch op {
	case "<":
		return l < r
	case ">":
		return l > r
	case "<=":
		return l <= r
	case ">=":
		return l >= r
	}
	return false
}

// balancedParens reports whether every '(' in s is closed within s.
func balancedParens(s string) bool {
	depth := 0
	for _, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func isQuoted(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\''
}

func stripQuote(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "'") {
		if u, err := unquote(s); err == nil {
			return u
		}
	}
	return s
}

// splitCompare finds the top-level comparison operator.
//
// Brackets group ([foo],y indirect operands) only when they balance: a
// substring reference such as &addr[1:1] can expand to a bare "[", and
// treating that as an open group would hide the comparison behind it.
func splitCompare(s string) (string, string, string) {
	depth := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '[' {
			depth++
		} else if s[i] == ']' {
			depth--
		}
	}
	return splitCompareIn(s, depth == 0)
}

func splitCompareIn(s string, brackets bool) (string, string, string) {
	// MacRoman comparison operators
	for _, op := range []struct{ tok, norm string }{{"≠", "<>"}, {"≤", "<="}, {"≥", ">="}} {
		if i := strings.Index(s, op.tok); i >= 0 {
			return strings.TrimSpace(s[:i]), op.norm, strings.TrimSpace(s[i+len(op.tok):])
		}
	}
	depth := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inStr = !inStr
		case '(':
			if !inStr {
				depth++
			}
		case ')':
			if !inStr {
				depth--
			}
		case '[':
			if !inStr && brackets {
				depth++
			}
		case ']':
			if !inStr && brackets {
				depth--
			}
		case '<':
			if inStr || depth != 0 {
				continue
			}
			if i+1 < len(s) && s[i+1] == '<' { // shift, not comparison
				i++
				continue
			}
			// A bare "<" needs a left-hand side to be a comparison. With none
			// it is the direct-page prefix of a substituted operand, as in
			// "IF &addr1='' THEN" with &addr1 = "<s_temp1" -- reading that as
			// a comparison took the wrong branch of gsos.macros' pulllong and
			// dropped the stores entirely. This holds even when '=' follows:
			// M16.Util's pushlong tests "&addr[1:1]='#'", and with &addr =
			// "<last_dib" the condition is the string "<" against "#", not
			// "<=" with an empty left side.
			if strings.TrimSpace(s[:i]) == "" {
				continue
			}
			if i+1 < len(s) {
				if s[i+1] == '>' {
					return strings.TrimSpace(s[:i]), "<>", strings.TrimSpace(s[i+2:])
				}
				if s[i+1] == '=' {
					return strings.TrimSpace(s[:i]), "<=", strings.TrimSpace(s[i+2:])
				}
			}
			return strings.TrimSpace(s[:i]), "<", strings.TrimSpace(s[i+1:])
		case '>':
			if inStr || depth != 0 {
				continue
			}
			if i+1 < len(s) && s[i+1] == '>' { // shift
				i++
				continue
			}
			if strings.TrimSpace(s[:i]) == "" {
				continue // long-addressing prefix, not a comparison
			}
			if i+1 < len(s) && s[i+1] == '=' {
				return strings.TrimSpace(s[:i]), ">=", strings.TrimSpace(s[i+2:])
			}
			return strings.TrimSpace(s[:i]), ">", strings.TrimSpace(s[i+1:])
		case '=':
			if !inStr && depth == 0 {
				return strings.TrimSpace(s[:i]), "=", strings.TrimSpace(s[i+1:])
			}
		}
	}
	return s, "", ""
}

// ---------- MPW path resolution ----------

// mpwPath converts an MPW-style path (':' separated, leading ':' = current
// dir, '::' = parent) into a host path relative to dir.
func mpwPath(dir, spec string) string {
	if !strings.Contains(spec, ":") {
		return filepath.Join(dir, spec)
	}
	for strings.HasPrefix(spec, "::") {
		dir = filepath.Dir(dir)
		spec = spec[1:]
	}
	spec = strings.TrimPrefix(spec, ":")
	return filepath.Join(dir, strings.ReplaceAll(spec, ":", "/"))
}

// buildTime is the timestamp &SYSDATE/&SYSTIME report. SOURCE_DATE_EPOCH
// pins it so a build that stamps its own date stays reproducible.
func buildTime() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Now()
}
