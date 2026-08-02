package link

import (
	"github.com/dagenbrock/iigs-tools/omf"
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
// original LinkIIGS places them: symbols live in 512 hash buckets (newest
// first within a bucket); the linker sweeps buckets in ascending order,
// pulling the defining segment for any still-unresolved symbol; a pulled
// segment's own references enter the table immediately, so buckets ahead of
// the sweep are caught this pass and buckets behind wait for the next
// sweep. Validated against the original linker's -l map on MSDos.FST
// (156/160 segments in identical order; the rest are one bucket's
// tie-break).
func SelectLib(objs []*omf.File, lib *omf.File) *omf.File {
	refs := func(s *omf.Segment) []string {
		var out []string
		for _, r := range s.Records {
			switch r.Op {
			case omf.RecLexpr, omf.RecBexpr, omf.RecExpr, omf.RecRelexpr:
				b := r.Raw[2:]
				if r.Op == omf.RecRelexpr {
					b = r.Raw[6:]
				}
				for i := 0; i < len(b) && b[i] != 0x00; {
					switch b[i] {
					case 0x81, 0x80, 0x87:
						i += 5
					case 0x82, 0x83:
						n := int(b[i+1])
						out = append(out, string(b[i+2:i+2+n]))
						i += 2 + n
					default:
						i++
					}
				}
			}
		}
		return out
	}
	defs := func(s *omf.Segment) []string {
		out := []string{s.SegName}
		for _, r := range s.Records {
			if r.Op == omf.RecGlobal || r.Op == omf.RecGequ {
				n := int(r.Raw[1])
				out = append(out, string(r.Raw[2:2+n]))
			}
		}
		return out
	}
	provides := map[string]*omf.Segment{}
	for i := range lib.Segments {
		s := &lib.Segments[i]
		if s.Kind&0x1F == 0x08 { // the dictionary
			continue
		}
		for _, d := range defs(s) {
			if provides[d] == nil {
				provides[d] = s
			}
		}
	}

	var buckets [512][]string
	seen := map[string]bool{}
	defined := map[string]bool{}
	// A reference lookup can move a symbol to its chain's head, but each
	// symbol moves AT MOST ONCE: the first reference prepends it, the first
	// RE-reference (from a later segment) hoists it back to the head, and
	// every reference after that leaves it in place -- as if a 1-bit
	// "multiply referenced" flag gates the relink. Oracle-probed (p5: a
	// re-reference hoists an old entry over a newer one) and pinned by
	// MSDos.FST's buckets 505/3/139/162, which need exactly one hoist:
	// mount_volume rises over search_name at its second reference but does
	// NOT rise over find_volume at its third.
	hoisted := map[string]bool{}
	insert := func(n string) {
		b := libHash(n)
		if !seen[n] {
			seen[n] = true
			buckets[b] = append([]string{n}, buckets[b]...)
			return
		}
		if hoisted[n] {
			return
		}
		hoisted[n] = true
		ch := buckets[b]
		for i, x := range ch {
			if x == n {
				ch = append(ch[:i:i], ch[i+1:]...)
				break
			}
		}
		buckets[b] = append([]string{n}, ch...)
	}
	segBatch := func(s *omf.Segment) {
		for _, d := range defs(s) {
			if !seen[d] {
				insert(d)
			}
			defined[d] = true
		}
		// Each distinct symbol is looked up ONCE per segment, at its first
		// occurrence -- repeats within the segment do not re-hoist it
		// (oracle-probed: READ references curr_mark, then save_curr_mark,
		// then curr_mark again, and save_curr_mark is pulled first).
		inSeg := map[string]bool{}
		for _, r := range refs(s) {
			if inSeg[r] {
				continue
			}
			inSeg[r] = true
			insert(r)
		}
	}

	for _, f := range objs {
		for i := range f.Segments {
			segBatch(&f.Segments[i])
		}
	}

	pulled := map[*omf.Segment]bool{}
	out := &omf.File{}
	for progress := true; progress; {
		progress = false
		for b := 0; b < 512; b++ {
			chain := append([]string(nil), buckets[b]...)
			for _, n := range chain {
				if defined[n] {
					continue
				}
				s := provides[n]
				if s == nil || pulled[s] {
					continue
				}
				pulled[s] = true
				out.Segments = append(out.Segments, *s)
				segBatch(s)
				progress = true
			}
		}
	}
	if len(out.Segments) == 0 {
		return nil
	}
	return out
}
