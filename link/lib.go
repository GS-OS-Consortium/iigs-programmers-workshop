package link

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

// libHash is LinkIIGS's symbol-table hash: h = (h*2 + c) mod 512 over the
// canonical (upper-case) name. Recovered empirically: pulling A0..Z0 from a
// library lands in this order whatever the reference or dictionary order,
// and the MSDos.FST map follows it bucket by bucket.
func libHash(name string) int {
	h := 0
	for i := 0; i < len(name); i++ {
		h = (h*2 + int(name[i])) % 512
	}
	return h
}

// SelectLib picks the library segments the objects need, in the order the
// original LinkIIGS places them: symbols live in 512 hash buckets; the
// linker sweeps buckets in ascending order, pulling the defining segment
// for any still-unresolved symbol; a pulled segment's own references enter
// the table immediately, so buckets ahead of the sweep are caught this pass
// and buckets behind wait for the next sweep.
//
// PRIVATE symbols -- a segment name with KIND bit $4000, or a GLOBAL/GEQU
// whose private byte is set -- are scoped to their FILE: a root object, or
// one library MEMBER (the dictionary records each segment's member and
// mirrors the private flags). A reference binds to its own file's private
// definition before any public one, so a dozen members can each carry a
// private "~arrays"/"~string0" and each pull only its own (GSCalc:
// SANELIB.P.OBJ's NUM2STR references "~arrays" and pulls SANELIB's 2-byte
// ~arrays even though the root object and CSANELIB both define the same
// name).
func SelectLib(objs []*omf.File, lib *omf.File) *omf.File {
	return SelectLibs(objs, []*omf.File{lib})
}

// SelectLibs pulls from SEVERAL libraries with ONE symbol-table sweep: the
// original linker resolves each unresolved symbol against every -lib in
// command order, so pulls from different libraries INTERLEAVE in bucket
// order (Apple.Bowl: ProgAid's DRAW lands between IntBasicLib's ~ASSIGNSTRING
// and ~INTSGN).
func SelectLibs(objs []*omf.File, libs []*omf.File) *omf.File {
	return selectLibs(objs, libs, nil)
}

// IsLibrary reports whether the parsed file carries a MakeLib dictionary.
func IsLibrary(f *omf.File) bool {
	for i := range f.Segments {
		if f.Segments[i].Kind&0x1F == 0x08 {
			return true
		}
	}
	return false
}

// SelectLibAllowed is SelectLib restricted to library segments allow()
// admits. "PLib(@main,@PLib,@~globals)" pulls need-based like -lib, but
// only from those load segments: an excluded segment neither satisfies nor
// publishes anything, so a reference into ~arrays resolves to zero exactly
// as the original warns.
func SelectLibAllowed(objs []*omf.File, lib *omf.File, allow func(*omf.Segment) bool) *omf.File {
	return selectLibs(objs, []*omf.File{lib}, allow)
}

func selectLibs(objs []*omf.File, libs []*omf.File, allow func(*omf.Segment) bool) *omf.File {
	le := binary.LittleEndian

	// Member identity and private names, from each library dictionary.
	// Member ids carry the library index in the high bits so two -libs'
	// members stay distinct.
	memberOfSeg := map[*omf.Segment]int{}
	privProvides := map[int]map[string]*omf.Segment{} // member -> private name -> defining segment
	provides := map[string]*omf.Segment{}
	for li, lib := range libs {
		segByOff := map[uint32]int{}
		off := uint32(0)
		for i := range lib.Segments {
			segByOff[off] = i
			off += lib.Segments[i].ByteCnt
		}
		for i := range lib.Segments {
			s := &lib.Segments[i]
			if s.Kind&0x1F != 0x08 {
				continue
			}
			var lconsts [][]byte
			for _, r := range s.Records {
				if r.Op == omf.RecLconst {
					lconsts = append(lconsts, r.Raw[5:])
				}
			}
			if len(lconsts) < 3 {
				continue
			}
			names := lconsts[2]
			d := lconsts[1]
			for j := 0; j+12 <= len(d); j += 12 {
				nd := le.Uint32(d[j:])
				fn := li<<16 | int(le.Uint16(d[j+4:]))
				fl := le.Uint16(d[j+6:])
				so := le.Uint32(d[j+8:])
				si, ok := segByOff[so]
				if !ok {
					continue
				}
				memberOfSeg[&lib.Segments[si]] = fn
				if allow != nil && !allow(&lib.Segments[si]) {
					continue
				}
				if fl != 0 && int(nd) < len(names) {
					n := int(names[nd])
					name := string(names[nd+1 : nd+1+uint32(n)])
					if privProvides[fn] == nil {
						privProvides[fn] = map[string]*omf.Segment{}
					}
					if privProvides[fn][name] == nil {
						privProvides[fn][name] = &lib.Segments[si]
					}
				}
			}
		}

		// Public definitions only: a private name never satisfies (or
		// shadows) a reference from another file. First -lib wins a name.
		for i := range lib.Segments {
			s := &lib.Segments[i]
			if s.Kind&0x1F == 0x08 { // the dictionary
				continue
			}
			if allow != nil && !allow(s) {
				continue
			}
			if s.Kind&0x4000 == 0 && provides[s.SegName] == nil {
				provides[s.SegName] = s
			}
			for _, r := range s.Records {
				if r.Op == omf.RecGlobal || r.Op == omf.RecGequ {
					if globalPrivate(r.Raw) != 0 {
						continue
					}
					n := int(r.Raw[1])
					name := string(r.Raw[2 : 2+n])
					if provides[name] == nil {
						provides[name] = s
					}
				}
			}
		}
	}

	// A root object's private names, so its own references to them stay out
	// of the pull table entirely.
	rootPriv := map[*omf.File]map[string]bool{}
	for _, f := range objs {
		p := map[string]bool{}
		for i := range f.Segments {
			s := &f.Segments[i]
			if s.Kind&0x4000 != 0 {
				p[s.SegName] = true
			}
			for _, r := range s.Records {
				if (r.Op == omf.RecGlobal || r.Op == omf.RecGequ) && globalPrivate(r.Raw) != 0 {
					n := int(r.Raw[1])
					p[string(r.Raw[2:2+n])] = true
				}
			}
		}
		rootPriv[f] = p
	}

	// Chain entries are public names, or "\x00member\x00name" for a
	// reference to a member's private name; both hash by the bare name.
	scopedKey := func(m int, n string) string { return "\x00" + strconv.Itoa(m) + "\x00" + n }
	scopedSeg := map[string]*omf.Segment{}

	var buckets [512][]string
	seen := map[string]bool{}
	defined := map[string]bool{}
	// A reference lookup moves its symbol to the head of its chain, EVERY
	// time, but only when the re-reference comes from a DIFFERENT file than
	// the earlier ones: lookups dedup per FILE -- a root object counts as one
	// file, a library member counts as one file. (GSCalc pinned the
	// granularity: GETROUND re-references getenvironment right after its
	// member-mate SETROUND first referenced it, and the oracle does NOT
	// hoist.)
	//
	// This used to hoist each symbol at most once, which fitted every target
	// then in the corpus -- a symbol that is already at the head cannot be
	// seen to rise, so "rises at its second reference but not its third" also
	// reads as "was already at the head". Teach separates the two: its
	// _wsign_extend is referenced from three files with GETPORT's reference
	// in between, so the third lookup has somewhere to rise FROM, and the
	// oracle raises it.
	dbgBuckets := map[int]bool{}
	if v := os.Getenv("LINKIIGS_LIBDEBUG"); v != "" {
		for _, s := range strings.Split(v, ",") {
			n, _ := strconv.Atoi(s)
			dbgBuckets[n] = true
		}
	}
	insert := func(key, name string) {
		b := libHash(name)
		if dbgBuckets[b] {
			fmt.Fprintf(os.Stderr, "insert %q b=%d seen=%v chain=%v\n", key, b, seen[key], buckets[b])
		}
		if !seen[key] {
			seen[key] = true
			buckets[b] = append([]string{key}, buckets[b]...)
			return
		}
		ch := buckets[b]
		for i, x := range ch {
			if x == key {
				ch = append(ch[:i:i], ch[i+1:]...)
				break
			}
		}
		buckets[b] = append([]string{key}, ch...)
	}
	// segBatch feeds one segment's records to the symbol table, in record
	// order: the segment's own name first, then each GLOBAL/GEQU definition
	// and each expression reference at its position. Each distinct symbol is
	// looked up ONCE per file, at its first occurrence. priv is the file's
	// private-name set; member is the library member (-1 for a root file).
	segBatch := func(s *omf.Segment, inFile map[string]bool, priv map[string]bool, member int) {
		if s.Kind&0x4000 == 0 {
			if !seen[s.SegName] {
				insert(s.SegName, s.SegName)
			}
			defined[s.SegName] = true
		}
		ref := func(n string) {
			if inFile[n] {
				return
			}
			inFile[n] = true
			if priv[n] {
				if member < 0 {
					return // resolves within the root file; nothing to pull
				}
				if t := privProvides[member][n]; t != nil {
					k := scopedKey(member, n)
					scopedSeg[k] = t
					insert(k, n)
				}
				return
			}
			// Only now is the name resolved ACROSS files, which is the one
			// place "-a old=new" applies: the pull follows the alias, so the
			// member defining new comes in and the one defining old does not
			// (link.go's evalOMFExprReloc aliases at the matching point).
			n = alias(n)
			insert(n, n)
		}
		def := func(r omf.Record) {
			n := int(r.Raw[1])
			name := string(r.Raw[2 : 2+n])
			if globalPrivate(r.Raw) != 0 {
				return
			}
			if !seen[name] {
				insert(name, name)
			}
			defined[name] = true
		}
		exprRefs := func(b []byte) {
			for i := 0; i < len(b) && b[i] != 0x00; {
				switch b[i] {
				case 0x81, 0x80, 0x87:
					i += 5
				case 0x82, 0x83:
					n := int(b[i+1])
					ref(string(b[i+2 : i+2+n]))
					i += 2 + n
				default:
					i++
				}
			}
		}
		for _, r := range s.Records {
			switch r.Op {
			case omf.RecGlobal:
				def(r)
			case omf.RecGequ:
				def(r)
				n := int(r.Raw[1])
				exprRefs(r.Raw[2+n+4:])
			case omf.RecLexpr, omf.RecBexpr, omf.RecExpr:
				exprRefs(r.Raw[2:])
			case omf.RecRelexpr:
				exprRefs(r.Raw[6:])
			}
		}
	}

	// Private names of each library member, for pulled segments' references.
	memberPriv := map[int]map[string]bool{}
	for m, p := range privProvides {
		mp := map[string]bool{}
		for n := range p {
			mp[n] = true
		}
		memberPriv[m] = mp
	}

	for _, f := range objs {
		inFile := map[string]bool{}
		for i := range f.Segments {
			segBatch(&f.Segments[i], inFile, rootPriv[f], -1)
		}
	}

	pulled := map[*omf.Segment]bool{}
	memberGate := map[int]map[string]bool{}
	out := &omf.File{}
	pullSeg := func(s *omf.Segment) {
		pulled[s] = true
		m := memberOfSeg[s]
		cp := *s
		cp.LibMember = m
		out.Segments = append(out.Segments, cp)
		if os.Getenv("LINKIIGS_LIBPULLS") != "" {
			fmt.Fprintf(os.Stderr, "pull %q len=$%X member=%d\n", s.SegName, s.Length, m)
		}
		g := memberGate[m]
		if g == nil {
			g = map[string]bool{}
			memberGate[m] = g
		}
		segBatch(s, g, memberPriv[m], m)
	}
	for progress := true; progress; {
		progress = false
		for b := 0; b < 512; b++ {
			chain := append([]string(nil), buckets[b]...)
			for _, n := range chain {
				var s *omf.Segment
				if t, ok := scopedSeg[n]; ok {
					s = t
				} else {
					if defined[n] {
						continue
					}
					s = provides[n]
				}
				if s == nil || pulled[s] {
					continue
				}
				pullSeg(s)
				progress = true
			}
		}
	}
	if len(out.Segments) == 0 {
		return nil
	}
	return out
}
