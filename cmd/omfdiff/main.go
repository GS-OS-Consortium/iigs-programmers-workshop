// omfdiff structurally compares two OMF files: per-segment header fields,
// then record-by-record with a hex window around the first divergence.
// Exit 0 = identical, 1 = differ, 2 = usage/parse error.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

var diffs int

func report(format string, args ...any) {
	diffs++
	fmt.Printf(format+"\n", args...)
}

func main() {
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: omfdiff a b")
		os.Exit(2)
	}
	a := load(flag.Arg(0))
	b := load(flag.Arg(1))

	if len(a.Segments) != len(b.Segments) {
		report("segment count: %d vs %d", len(a.Segments), len(b.Segments))
	}
	n := min(len(a.Segments), len(b.Segments))
	for i := 0; i < n; i++ {
		diffSegment(i, &a.Segments[i], &b.Segments[i])
	}
	if diffs == 0 {
		fmt.Println("identical (structurally)")
		os.Exit(0)
	}
	os.Exit(1)
}

func load(path string) *omf.File {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	f, err := omf.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		os.Exit(2)
	}
	return f
}

func diffSegment(i int, a, b *omf.Segment) {
	pre := fmt.Sprintf("seg %d (%q)", i+1, a.SegName)
	cmp := func(field string, x, y any) {
		if fmt.Sprint(x) != fmt.Sprint(y) {
			report("%s %s: %v vs %v", pre, field, x, y)
		}
	}
	cmp("SEGNAME", a.SegName, b.SegName)
	cmp("LOADNAME", fmt.Sprintf("%q", a.LoadName), fmt.Sprintf("%q", b.LoadName))
	cmp("VERSION", a.Version, b.Version)
	cmp("KIND", fmt.Sprintf("$%04X", a.Kind), fmt.Sprintf("$%04X", b.Kind))
	cmp("BYTECNT", fmt.Sprintf("$%X", a.ByteCnt), fmt.Sprintf("$%X", b.ByteCnt))
	cmp("RESSPC", a.ResSpc, b.ResSpc)
	cmp("LENGTH", fmt.Sprintf("$%X", a.Length), fmt.Sprintf("$%X", b.Length))
	cmp("LABLEN", a.LabLen, b.LabLen)
	cmp("BANKSIZE", fmt.Sprintf("$%X", a.BankSize), fmt.Sprintf("$%X", b.BankSize))
	cmp("ORG", fmt.Sprintf("$%X", a.Org), fmt.Sprintf("$%X", b.Org))
	cmp("ALIGN", a.Align, b.Align)
	cmp("SEGNUM", a.SegNum, b.SegNum)
	cmp("ENTRY", a.EntryPt, b.EntryPt)
	cmp("DISPNAME", fmt.Sprintf("$%X", a.DispName), fmt.Sprintf("$%X", b.DispName))
	cmp("DISPDATA", fmt.Sprintf("$%X", a.DispData), fmt.Sprintf("$%X", b.DispData))
	cmp("TEMPORG", a.TempOrg, b.TempOrg)

	if len(a.Records) != len(b.Records) {
		report("%s record count: %d vs %d", pre, len(a.Records), len(b.Records))
	}
	rn := min(len(a.Records), len(b.Records))
	shown := 0
	for r := 0; r < rn && shown < 5; r++ {
		ra, rb := a.Records[r], b.Records[r]
		if ra.Op != rb.Op {
			report("%s record %d: %s vs %s", pre, r, omf.RecName(ra.Op), omf.RecName(rb.Op))
			shown++
			continue
		}
		if !bytes.Equal(ra.Raw, rb.Raw) {
			off := 0
			for off < len(ra.Raw) && off < len(rb.Raw) && ra.Raw[off] == rb.Raw[off] {
				off++
			}
			report("%s record %d (%s, %d vs %d bytes) first diff at +$%X:\n    a: % x\n    b: % x",
				pre, r, omf.RecName(ra.Op), len(ra.Raw), len(rb.Raw), off,
				window(ra.Raw, off), window(rb.Raw, off))
			shown++
		}
	}
}

func window(b []byte, off int) []byte {
	lo := max(0, off-8)
	hi := min(len(b), off+16)
	return b[lo:hi]
}
