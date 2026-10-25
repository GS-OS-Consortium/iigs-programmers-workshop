package mpwmk

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/dagenbrock/iigs-programmers-workshop/asm"
	"github.com/dagenbrock/iigs-programmers-workshop/link"
	"github.com/dagenbrock/iigs-programmers-workshop/omf"
)

func TestSegmentImageStopsAtReloc(t *testing.T) {
	seg := []byte{0xF2, 4, 0, 0, 0, 'A', 'B', 'C', 'D', 0xF5, 2, 0, 0, 0, 0, 0}
	img := segmentImage(seg, 0)
	if string(img) != "ABCD" {
		t.Fatalf("image %q", img)
	}
}

func TestFinderPadEntry(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "pad.aii")
	body := "main proc\n" +
		" dc.b $3A,$43,$46,$46,$41,$35\n" +
		" ds.b 16\n" +
		" nop\n" +
		" end\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	obj, err := asm.AssembleFile(src)
	if err != nil {
		t.Fatal(err)
	}
	f, err := omf.Parse(obj.WriteOMF())
	if err != nil {
		t.Fatal(err)
	}
	linked, err := link.LinkGroups([]link.Group{{
		Name:    "FINDER",
		Kind:    0x1100,
		KindSet: true,
		Sels:    []link.Sel{{File: f}},
	}}, true)
	if err != nil {
		t.Fatal(err)
	}
	rawOff, _, ok := finderEntry(linked)
	if !ok {
		t.Fatal("pad not recognized in the link")
	}
	// The link itself leaves the entry at 0, matching public LinkIIGS.
	if got := binary.LittleEndian.Uint32(linked[rawOff+0x24:]); got != 0 {
		t.Fatalf("link wrote entry $%X; public LinkIIGS leaves 0", got)
	}
	patched := patchFinderStartup(linked)
	off, entry, ok := finderEntry(patched)
	if !ok {
		t.Fatal("pad not recognized")
	}
	if entry != 22 {
		t.Fatalf("entry $%X, want $16 (6 signature bytes + 16 of DS)", entry)
	}
	if got := binary.LittleEndian.Uint32(patched[off+0x24:]); got != 22 {
		t.Fatalf("segment header entry $%X", got)
	}
	// The ~ExpressLoad directory copy of the header carries the same entry.
	window := append([]byte(nil), patched[off+0x0C:off+0x2C]...)
	window[0x2A-0x0C] = 0
	window[0x2A-0x0C+1] = 0
	if findWindow(patched, window) < 0 {
		t.Fatal("expressload directory copy was not updated")
	}
	plain, err := link.LinkGroups([]link.Group{{
		Name: "main",
		Sels: []link.Sel{{File: f}},
	}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(patchFinderStartup(plain)) != string(plain) {
		t.Fatal("a segment not named FINDER was patched")
	}
}
