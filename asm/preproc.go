package asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	src := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	pp.processSource(src, path)
	return nil
}

func (pp *ppState) processSource(src, path string) {
	st := pp.st
	prevFile, prevLine := st.curFile, st.curLine
	st.curFile = path
	for n, raw := range strings.Split(src, "\n") {
		if st.ended {
			break
		}
		st.curLine = n + 1
		pp.processLine(raw)
	}
	st.curFile, st.curLine = prevFile, prevLine
}

func (pp *ppState) processLine(raw string) {
	st := pp.st
	if st.ended {
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

	// conditional structure is tracked even in inactive regions
	switch op {
	case "if":
		if !pp.active() {
			pp.conds = append(pp.conds, condFrame{parentActive: false})
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
		path := mpwPath(filepath.Dir(st.curFile), spec)
		if _, serr := os.Stat(path); serr != nil {
			for _, d := range pp.incDirs {
				cand := filepath.Join(d, strings.ReplaceAll(strings.TrimPrefix(spec, ":"), ":", "/"))
				if _, serr2 := os.Stat(cand); serr2 == nil {
					path = cand
					break
				}
			}
		}
		if err := pp.processFile(path); err != nil {
			st.errf("INCLUDE %s: %v", spec, err)
		}
		return
	case "writeln":
		fmt.Fprintln(os.Stderr, pp.subst(l.rest))
		return
	}

	// inside a macro expansion, substitute & references before assembling
	if len(pp.frames) > 0 {
		raw2 := pp.subst(raw)
		l = splitLine(raw2)
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
			def.params = append(def.params, strings.ToUpper(p[1:]))
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
	if def.labelVar != "" {
		frame.vars[def.labelVar] = inv.label
	} else if inv.label != "" {
		// a label on an invocation of a label-less macro defines a code label
		pp.st.defineCodeLabel(inv.label)
	}
	if def.nameVar != "" {
		frame.vars[def.nameVar] = nameSuffix
	}
	args := splitArgs(operandOnly(inv.rest))
	for i, p := range def.params {
		v := ""
		if i < len(args) {
			v = strings.TrimSpace(args[i])
		}
		frame.vars[p] = v
	}
	pp.frames = append(pp.frames, frame)
	condDepth := len(pp.conds)
	for _, bl := range def.body {
		if pp.st.ended {
			break
		}
		pp.processLine(bl)
	}
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
	v, ok := pp.globals[name]
	return v, ok
}

// ---------- & substitution ----------

var ppFuncs = map[string]bool{
	"EVAL": true, "TRIM": true, "LEN": true, "UC": true, "LC": true,
	"CONCAT": true, "I2S": true, "SETTING": true, "FINDSYM": true,
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
	case "EVAL":
		if len(args) != 1 {
			return "0"
		}
		return strconv.FormatInt(pp.argNum(args[0]), 10)
	case "TRIM":
		return strings.TrimSpace(pp.rawArg(args))
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
		for int64(len(s)) < width {
			s = " " + s
		}
		return s
	case "SETTING":
		switch strings.ToUpper(pp.argText(args[0])) {
		case "MSB":
			if pp.st.msb {
				return "ON"
			}
			return "OFF"
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

// rawArg: single-argument text form, quoted literals unquoted but WITHOUT
// trimming (LEN counts delimiters of raw quoted params: &LEN of a param
// whose value is 'END' is 5).
func (pp *ppState) rawArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.TrimSpace(pp.subst(args[0]))
}

// ---------- conditionals ----------

// condEval evaluates an IF/ELSEIF condition (trailing THEN stripped):
// numeric comparison when both sides evaluate; string comparison otherwise.
func (pp *ppState) condEval(s string) bool {
	s = strings.TrimSpace(s)
	if up := strings.ToUpper(s); strings.HasSuffix(up, "THEN") {
		s = strings.TrimSpace(s[:len(s)-4])
	}
	lhs, op, rhs := splitCompare(s)
	if op == "" {
		n, err := evalNum(s, &exprCtx{st: pp.st})
		if err != nil {
			pp.st.errf("IF: %v", err)
			return false
		}
		return n != 0
	}
	ln, lerr := evalNum(lhs, &exprCtx{st: pp.st})
	rn, rerr := evalNum(rhs, &exprCtx{st: pp.st})
	if lerr == nil && rerr == nil {
		switch op {
		case "=":
			return ln == rn
		case "<>":
			return ln != rn
		case "<":
			return ln < rn
		case ">":
			return ln > rn
		case "<=":
			return ln <= rn
		case ">=":
			return rn <= ln
		}
	}
	// string comparison
	ls, rs := stripQuote(lhs), stripQuote(rhs)
	switch op {
	case "=":
		return strings.EqualFold(ls, rs)
	case "<>":
		return !strings.EqualFold(ls, rs)
	}
	pp.st.errf("cannot compare %q %s %q", lhs, op, rhs)
	return false
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
func splitCompare(s string) (string, string, string) {
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
		case '<':
			if inStr || depth != 0 {
				continue
			}
			if i+1 < len(s) {
				if s[i+1] == '>' {
					return strings.TrimSpace(s[:i]), "<>", strings.TrimSpace(s[i+2:])
				}
				if s[i+1] == '=' {
					return strings.TrimSpace(s[:i]), "<=", strings.TrimSpace(s[i+2:])
				}
				if s[i+1] == '<' { // shift, not comparison
					i++
					continue
				}
			}
			return strings.TrimSpace(s[:i]), "<", strings.TrimSpace(s[i+1:])
		case '>':
			if inStr || depth != 0 {
				continue
			}
			if i+1 < len(s) {
				if s[i+1] == '=' {
					return strings.TrimSpace(s[:i]), ">=", strings.TrimSpace(s[i+2:])
				}
				if s[i+1] == '>' { // shift
					i++
					continue
				}
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
