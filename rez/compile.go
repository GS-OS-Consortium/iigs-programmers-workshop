package rez

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Resource is one compiled resource.
type Resource struct {
	Type  int64
	ID    int64
	Attrs uint16
	Name  string
	Data  []byte
}

// Compiler holds the declared types and constants while compiling.
type Compiler struct {
	IncDirs []string
	types   map[string]*typeDecl // lowercased name -> template
	defs    map[string][]token   // #defines, for constant lookup
	res     []Resource
}

// Compile reads a Rez source file and returns its resources in source order.
func Compile(path string, incDirs []string) ([]Resource, error) {
	c := &Compiler{
		IncDirs: incDirs,
		types:   map[string]*typeDecl{},
	}
	pp := newPreproc(incDirs)
	if err := pp.file(path); err != nil {
		return nil, err
	}
	c.defs = pp.defs
	p := &parser{toks: pp.out, c: c}
	if err := c.run(p, filepath.Dir(path)); err != nil {
		return nil, err
	}
	return append(c.res, resNames(c.res)...), nil
}

// resNames builds the rResName resources RezIIGS generates for itself: every
// resource declared with a name contributes to one $8014 resource per type,
// numbered $00010000|type and appended after everything from the source.
// Its layout is TypesIIGS.r's rResName -- a format word, a longint count,
// then a longint id and a pstring name per entry, in source order.
func resNames(res []Resource) []Resource {
	const rResNameType = 0x8014
	var types []int64
	byType := map[int64][]Resource{}
	for _, r := range res {
		if r.Name == "" {
			continue
		}
		if _, ok := byType[r.Type]; !ok {
			types = append(types, r.Type)
		}
		byType[r.Type] = append(byType[r.Type], r)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

	var out []Resource
	for _, t := range types {
		named := byType[t]
		d := []byte{1, 0} // name holder format
		d = binary.LittleEndian.AppendUint32(d, uint32(len(named)))
		for _, r := range named {
			d = binary.LittleEndian.AppendUint32(d, uint32(r.ID))
			nb := macRomanString(r.Name)
			if len(nb) > 255 {
				nb = nb[:255]
			}
			d = append(d, byte(len(nb)))
			d = append(d, nb...)
		}
		out = append(out, Resource{
			Type: rResNameType,
			ID:   0x00010000 | t,
			Data: d,
		})
	}
	return out
}

// run walks the top-level statements: type declarations, resource bodies and
// read statements.
func (c *Compiler) run(p *parser, baseDir string) error {
	for {
		t := p.peek()
		if t.kind == tEOF {
			return nil
		}
		if p.accept(";") {
			continue
		}
		switch {
		case t.is("type"):
			p.next()
			td, err := p.parseTypeDecl()
			if err != nil {
				return err
			}
			c.types[strings.ToLower(td.name)] = td
		case t.is("resource"):
			p.next()
			if err := c.parseResource(p); err != nil {
				return err
			}
		case t.is("read"):
			p.next()
			if err := c.parseRead(p, baseDir); err != nil {
				return err
			}
		case t.is("data"):
			p.next()
			if err := c.parseData(p); err != nil {
				return err
			}
		case t.is("delete") || t.is("change") || t.is("include"):
			return p.errf(t, "%q statements are not implemented", t.text)
		default:
			return p.errf(t, "unexpected %s at top level", t)
		}
	}
}

// resHeader parses "TypeName (id [,\"name\"] [,attrs...])" shared by
// resource/read/data.
func (c *Compiler) resHeader(p *parser) (*typeDecl, Resource, error) {
	var r Resource
	nameTok := p.next()
	if nameTok.kind != tIdent && nameTok.kind != tNumber {
		return nil, r, p.errf(nameTok, "resource type expected, found %s", nameTok)
	}
	var td *typeDecl
	if nameTok.kind == tNumber {
		r.Type = nameTok.num
		td = c.types[strings.ToLower(fmt.Sprintf("$%04X", nameTok.num))]
	} else {
		td = c.types[strings.ToLower(nameTok.text)]
		if td == nil {
			return nil, r, p.errf(nameTok, "undeclared resource type %q", nameTok.text)
		}
		r.Type = td.id
	}
	if td != nil && td.hasID {
		r.Type = td.id
	}
	if _, err := p.expect("("); err != nil {
		return nil, r, err
	}
	idExpr, err := p.exprTokens()
	if err != nil {
		return nil, r, err
	}
	id, err := c.evalConst(idExpr)
	if err != nil {
		return nil, r, err
	}
	r.ID = id
	for p.accept(",") {
		t := p.peek()
		if t.kind == tString {
			r.Name = p.next().text
			continue
		}
		at := p.next()
		if at.kind == tNumber { // a raw attribute word, e.g. "($8000)"
			r.Attrs |= uint16(at.num)
			continue
		}
		bits, ok := resAttr(at.text)
		if !ok {
			return nil, r, p.errf(at, "unknown resource attribute %q", at.text)
		}
		r.Attrs |= bits
	}
	if _, err := p.expect(")"); err != nil {
		return nil, r, err
	}
	return td, r, nil
}

func (c *Compiler) parseResource(p *parser) error {
	td, r, err := c.resHeader(p)
	if err != nil {
		return err
	}
	if td == nil {
		return fmt.Errorf("resource $%04X has no template", r.Type)
	}
	if _, err := p.expect("{"); err != nil {
		return err
	}
	// Scouting passes locate labels and array counts, rewinding to the same
	// data tokens each time. One pass is not always enough: rIcon computes
	// its image size from "(Mask-Image)/8 - 6" and then sizes the image
	// itself by reading that word back, so an unknown Mask feeds a wrong
	// size which feeds a wrong Mask. Iterating settles it (five rounds for
	// the icons); the real emission runs once the offsets stop moving.
	body := p.pos
	var labels map[string]int
	var counts map[string]int64
	for round := 0; ; round++ {
		p.pos = body
		sc := &emitter{c: c, p: p, pass1: true,
			labels: copyLabels(labels), counts: copyCounts(counts)}
		if err := sc.fields(td.fields); err != nil {
			return err
		}
		settled := sameLabels(labels, sc.labels) && sameCounts(counts, sc.counts)
		labels, counts = sc.labels, sc.counts
		if settled {
			break
		}
		if round == 20 {
			return fmt.Errorf("resource $%04X id $%08X: offsets never settle",
				r.Type, uint32(r.ID))
		}
	}
	p.pos = body
	e := &emitter{c: c, p: p, labels: labels, counts: counts}
	if err := e.fields(td.fields); err != nil {
		return err
	}
	p.accept(";") // a body may end with a semicolon before its brace
	if _, err := p.expect("}"); err != nil {
		return err
	}
	p.accept(";")
	r.Data = e.flush()
	c.res = append(c.res, r)
	return nil
}

func copyLabels(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyCounts(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sameLabels(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func sameCounts(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

// parseData handles "data 'type'(id) { $"..." }" -- a raw resource body.
func (c *Compiler) parseData(p *parser) error {
	_, r, err := c.resHeader(p)
	if err != nil {
		return err
	}
	if _, err := p.expect("{"); err != nil {
		return err
	}
	var raw []byte
	for {
		t := p.peek()
		if t.is("}") {
			break
		}
		if p.accept(",") {
			continue
		}
		t = p.next()
		if t.kind != tHexString && t.kind != tString {
			return p.errf(t, "data body expects hex or character strings")
		}
		raw = append(raw, macRomanBytes(t)...)
	}
	if _, err := p.expect("}"); err != nil {
		return err
	}
	p.accept(";")
	r.Data = raw
	c.res = append(c.res, r)
	return nil
}

// parseRead handles "read TypeName(id,attrs) \"file\"". The Convert
// attribute means the file is an OMF load file that must be flattened into a
// plain image first; every use in this tree is a code resource built by
// LinkIIGS -x.
func (c *Compiler) parseRead(p *parser, baseDir string) error {
	_, r, err := c.resHeader(p)
	if err != nil {
		return err
	}
	ft := p.next()
	if ft.kind != tString {
		return p.errf(ft, "read expects a file name, found %s", ft)
	}
	p.accept(";")

	path := ft.text
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	if _, err := os.Stat(path); err != nil {
		if alt, ok := findCaseInsensitive(path); ok {
			path = alt
		}
	}
	// "read" takes the file verbatim -- including under Convert, which does
	// NOT transform the bytes: the original's converted rCtlDefProc/
	// rCodeResource resources are byte-identical to the LinkIIGS -x load
	// files they name (oracle-verified). Convert only sets a bit in the
	// index, telling the Resource Manager the resource came from a load file
	// ("Convert,locked" emits $8800, not $8000).
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %q: %w", ft.text, err)
	}
	r.Data = data
	c.res = append(c.res, r)
	return nil
}

func findCaseInsensitive(path string) (string, bool) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range ents {
		if strings.EqualFold(e.Name(), base) {
			return filepath.Join(dir, e.Name()), true
		}
	}
	return "", false
}

// evalConst evaluates a constant expression made of numbers, #defined names
// and the usual operators.
func (c *Compiler) evalConst(ts []token) (int64, error) {
	e := &constEval{c: c, toks: ts}
	v, err := e.expr(0)
	if err != nil {
		return 0, err
	}
	if e.pos < len(e.toks) {
		return 0, fmt.Errorf("trailing %s in expression", e.toks[e.pos])
	}
	return v, nil
}
