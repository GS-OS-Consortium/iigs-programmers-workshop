package link

import (
	"bytes"
	"testing"
)

// recordKinds walks a relocation dictionary and returns, in order, the SUPER
// type of each SUPER record and the opcode of every other record.
func recordKinds(t *testing.T, b []byte) []int {
	t.Helper()
	var kinds []int
	for i := 0; i < len(b); {
		switch b[i] {
		case 0xF7: // SUPER: 4-byte length, then type + page list
			n := int(b[i+1]) | int(b[i+2])<<8 | int(b[i+3])<<16 | int(b[i+4])<<24
			kinds = append(kinds, 0x100+int(b[i+5]))
			i += 5 + n
		case 0xF5: // cRELOC
			kinds = append(kinds, 0xF5)
			i += 7
		case 0xE2: // RELOC
			kinds = append(kinds, 0xE2)
			i += 11
		default:
			t.Fatalf("unexpected record $%02X at %d", b[i], i)
		}
	}
	return kinds
}

func withEncoding(t *testing.T, e RelocEncoding) {
	t.Helper()
	prev := relocEncoding
	relocEncoding = e
	t.Cleanup(func() { relocEncoding = prev })
}

func TestRelocRecords1993PacksDcLAndHighWord(t *testing.T) {
	withEncoding(t, Relocs1993)
	patches := []relocPatch{
		{size: 2, offset: 0x10, value: 0x0123},             // lda #Label
		{size: 4, offset: 0x20, value: 0x0456},             // dc.l Label
		{size: 2, shift: -16, offset: 0x30, value: 0x0789}, // lda #^Label
		{size: 3, offset: 0x40, value: 0x0abc},             // jsl Label
	}
	got := recordKinds(t, relocRecords(patches, 2))
	want := []int{0x100, 0x101, 0x100 + 27}
	if !equalInts(got, want) {
		t.Fatalf("records = %x, want %x", got, want)
	}
	// a plain single-segment load file is segment 1: the high word is type 26
	got = recordKinds(t, relocRecords(patches[2:3], 1))
	if !equalInts(got, []int{0x100 + 26}) {
		t.Fatalf("segment 1 high word = %x, want SUPER 26", got)
	}
}

func TestRelocRecords1993KeepsUnpackableStandalone(t *testing.T) {
	withEncoding(t, Relocs1993)
	patches := []relocPatch{
		{size: 2, offset: 0x10, value: 0x80000123},             // #Label+$80000000
		{size: 2, shift: -16, offset: 0x13, value: 0x80000123}, // its high half
		{size: 2, shift: -8, offset: 0x20, value: 0x0042},      // #>Label
		{size: 4, offset: 0x30, value: 0x01000000},             // past 24 bits
		{size: 2, shift: -16, offset: 0x40, value: 0x12345},    // offset past a word
		{size: 2, offset: 0x50, value: 0x0010},
	}
	got := recordKinds(t, relocRecords(patches, 2))
	want := []int{0xE2, 0xE2, 0xF5, 0xE2, 0xE2, 0x100}
	if !equalInts(got, want) {
		t.Fatalf("records = %x, want %x", got, want)
	}
	// segments past 12 have no INTERSEG25+n type
	got = recordKinds(t, relocRecords([]relocPatch{{size: 2, shift: -16, offset: 4, value: 8}}, 13))
	if !equalInts(got, []int{0xF5}) {
		t.Fatalf("segment 13 high word = %x, want cRELOC", got)
	}
}

func TestRelocRecords12LeavesDcLAndHighWordAsCReloc(t *testing.T) {
	withEncoding(t, Relocs12)
	patches := []relocPatch{
		{size: 2, offset: 0x10, value: 0x0123},
		{size: 4, offset: 0x20, value: 0x0456},
		{size: 2, shift: -16, offset: 0x30, value: 0x0789},
	}
	got := recordKinds(t, relocRecords(patches, 2))
	want := []int{0xF5, 0xF5, 0x100}
	if !equalInts(got, want) {
		t.Fatalf("records = %x, want %x", got, want)
	}
}

func TestRelocRecordsSuperTypesAscendAcrossInterseg(t *testing.T) {
	withEncoding(t, Relocs1993)
	patches := []relocPatch{
		{size: 2, shift: -16, offset: 0x10, value: 0x0100},                     // own segment 3: type 28
		{size: 2, offset: 0x20, interseg: true, seg: 1, segoff: 0x40},          // type 14
		{size: 2, shift: -16, offset: 0x30, interseg: true, seg: 4, segoff: 8}, // type 29
	}
	got := recordKinds(t, relocRecords(patches, 3))
	want := []int{0x100 + 14, 0x100 + 28, 0x100 + 29}
	if !equalInts(got, want) {
		t.Fatalf("records = %x, want %x", got, want)
	}
}

func TestRelocRecordsPageList(t *testing.T) {
	withEncoding(t, Relocs1993)
	got := relocRecords([]relocPatch{
		{size: 4, offset: 0x0005, value: 1},
		{size: 4, offset: 0x0009, value: 1},
		{size: 4, offset: 0x0310, value: 1},
	}, 2)
	// type 1; page 0: 2 patches; skip 2 pages; page 3: 1 patch
	want := []byte{0xF7, 7, 0, 0, 0, 1, 1, 0x05, 0x09, 0x82, 0, 0x10}
	if !bytes.Equal(got, want) {
		t.Fatalf("SUPER = % x, want % x", got, want)
	}
}

func TestParseRelocEncoding(t *testing.T) {
	for s, want := range map[string]RelocEncoding{"1.2": Relocs12, "1.3": Relocs1993, "1993": Relocs1993} {
		if got, err := ParseRelocEncoding(s); err != nil || got != want {
			t.Errorf("ParseRelocEncoding(%q) = %v, %v", s, got, err)
		}
	}
	if _, err := ParseRelocEncoding("1.1"); err == nil {
		t.Error("ParseRelocEncoding(1.1) accepted")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
