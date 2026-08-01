// Package asm is a from-scratch reimplementation of the Apple MPW IIGS
// assembler (AsmIIGS): MPW-syntax 65816/65C02 macro assembler emitting OMF v2
// object files.
//
// First-light scope: PROC/ENDP/END, EQU, ANOP, DC.B/W/L, MACHINE,
// LONGA/LONGI, full 65816 instruction encoding with constant operands.
// Label-reference operands (which the real assembler emits as OMF expression
// records) and macros come next; behavior is developed by byte-diffing
// against the original assembler under emulation.
package asm

import (
	"fmt"
	"strings"
)

type Segment struct {
	Name string
	Code []byte
}

type Object struct {
	Segments []Segment
}

type asmState struct {
	cpu    int
	longA  bool
	longI  bool
	syms   map[string]int64
	obj    *Object
	cur    *Segment
	errs   []string
	lineNo int
}

func (st *asmState) errf(format string, args ...any) {
	st.errs = append(st.errs, fmt.Sprintf("line %d: %s", st.lineNo, fmt.Sprintf(format, args...)))
}

type line struct {
	label string
	op    string
	rest  string
}

// splitLine parses "[label] op operands ; comment". A label starts in column
// one; an optional trailing ':' is stripped.
func splitLine(s string) line {
	// strip comment (';' not inside a quoted string)
	inStr := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			inStr = !inStr
		} else if s[i] == ';' && !inStr {
			s = s[:i]
			break
		}
	}
	if s == "" {
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
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	l.rest = strings.TrimRight(s[j:], " \t")
	return l
}

// Assemble assembles MPW IIgs assembler source (already LF-terminated,
// MacRoman semantics are the caller's concern for now).
func Assemble(src string) (*Object, error) {
	st := &asmState{
		cpu:   cpu65816,
		longA: true,
		longI: true,
		syms:  map[string]int64{},
		obj:   &Object{},
	}
	for n, raw := range strings.Split(src, "\n") {
		st.lineNo = n + 1
		l := splitLine(raw)
		if l.op == "" && l.label == "" {
			continue
		}
		st.doLine(l)
	}
	if len(st.errs) > 0 {
		return st.obj, fmt.Errorf("%s", strings.Join(st.errs, "\n"))
	}
	return st.obj, nil
}

func (st *asmState) doLine(l line) {
	op := strings.ToLower(l.op)
	switch op {
	case "proc":
		if l.label == "" {
			st.errf("PROC requires a label")
			return
		}
		st.obj.Segments = append(st.obj.Segments, Segment{Name: strings.ToUpper(l.label)})
		st.cur = &st.obj.Segments[len(st.obj.Segments)-1]
		return
	case "endp":
		st.cur = nil
		return
	case "end":
		st.cur = nil
		return
	case "anop":
		if l.label != "" {
			st.errf("a label is not allowed on ANOP") // matches AsmIIGS error 24
		}
		return
	case "":
		// label-only line defines a code label at the current offset
		if l.label != "" && st.cur != nil {
			st.syms[strings.ToUpper(l.label)] = int64(len(st.cur.Code))
		}
		return
	case "equ":
		v, err := evalExpr(l.rest, &exprCtx{syms: st.syms})
		if err != nil {
			st.errf("EQU: %v", err)
			return
		}
		st.syms[strings.ToUpper(l.label)] = v
		return
	case "machine":
		switch strings.ToLower(l.rest) {
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
		st.longA = strings.EqualFold(l.rest, "on")
		return
	case "longi":
		st.longI = strings.EqualFold(l.rest, "on")
		return
	case "dc", "dc.b", "dc.w", "dc.l":
		st.doDC(op, l)
		return
	}
	if _, isInst := opTable[op]; isInst {
		if l.label != "" && st.cur != nil {
			st.syms[strings.ToUpper(l.label)] = int64(len(st.cur.Code))
		}
		st.doInst(op, l.rest)
		return
	}
	st.errf("unknown opcode/directive %q", l.op)
}

func (st *asmState) emit(b ...byte) {
	if st.cur == nil {
		st.errf("code outside PROC")
		return
	}
	st.cur.Code = append(st.cur.Code, b...)
}

func (st *asmState) doDC(op string, l line) {
	if l.label != "" && st.cur != nil {
		st.syms[strings.ToUpper(l.label)] = int64(len(st.cur.Code))
	}
	size := 1
	switch op {
	case "dc.w":
		size = 2
	case "dc.l":
		size = 4
	}
	for _, item := range splitArgs(l.rest) {
		item = strings.TrimSpace(item)
		if len(item) >= 2 && item[0] == '\'' && item[len(item)-1] == '\'' {
			for _, c := range []byte(item[1 : len(item)-1]) {
				st.emit(c)
			}
			continue
		}
		v, err := evalExpr(item, &exprCtx{syms: st.syms})
		if err != nil {
			st.errf("DC: %v", err)
			return
		}
		for i := 0; i < size; i++ {
			st.emit(byte(v >> (8 * i)))
		}
	}
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
	out = append(out, s[start:])
	return out
}

func (st *asmState) doInst(mn, operand string) {
	mode, exprStr, err := parseOperand(mn, operand)
	if err != nil {
		st.errf("%s: %v", mn, err)
		return
	}
	// Evaluate the operand first: mode selection is value-driven (the
	// original assembler picks DP/Abs/AbsL by operand magnitude).
	var val int64
	if exprStr != "" && mode != Move {
		v, err := evalExpr(exprStr, &exprCtx{syms: st.syms, pc: int64(len(st.curCode()))})
		if err != nil {
			st.errf("%s: %v", mn, err)
			return
		}
		val = v
	}
	sizeNeeded := 0
	if exprStr != "" {
		sizeNeeded = 1
	}
	if val >= 0x10000 || val < -0x8000 {
		sizeNeeded = 3
	} else if val >= 0x100 || val < -0x80 {
		sizeNeeded = 2
	}
	chain := modeChain(mode)
	var info opInfo
	var found bool
	var chosen Mode
	for _, m := range chain {
		if oi, ok := ops[opKey{mn, m}]; ok && oi.cpu <= st.cpu {
			switch m {
			case Rel8, Rel16, ImmM, ImmX, Imm8, Move:
				// size handled at emit time
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
		st.errf("%s does not support this addressing mode", mn)
		return
	}
	if chosen == Move {
		// MVN/MVP src,dst: operands are addresses; the bank bytes are
		// emitted as opcode, dstbank, srcbank (oracle-verified).
		parts := splitArgs(exprStr)
		if len(parts) != 2 {
			st.errf("%s: need two operands", mn)
			return
		}
		src, err1 := evalExpr(parts[0], &exprCtx{syms: st.syms})
		dst, err2 := evalExpr(parts[1], &exprCtx{syms: st.syms})
		if err1 != nil || err2 != nil {
			st.errf("%s: bad operands", mn)
			return
		}
		st.emit(info.code, byte(dst>>16), byte(src>>16))
		return
	}
	st.emit(info.code)
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
	case Rel8, Rel16:
		// constant branch targets are relative to PC after the instruction
		val = val - int64(len(st.curCode())+n)
	}
	for i := 0; i < n; i++ {
		st.emit(byte(val >> (8 * i)))
	}
}

func (st *asmState) curCode() []byte {
	if st.cur == nil {
		return nil
	}
	return st.cur.Code
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
// expression text (forced-size prefixes < | > handled by the caller later).
func parseOperand(mn, s string) (Mode, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Implied, "", nil
	}
	if strings.EqualFold(s, "a") {
		return Accum, "", nil
	}
	if s[0] == '#' {
		return ImmM, s[1:], nil // sized later; ImmX/Imm8 chosen via table chain
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
	return DP, s, nil // plain: chain resolves DP/Abs/AbsL/branch
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
