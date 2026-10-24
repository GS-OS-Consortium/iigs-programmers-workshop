package rez

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFileTypeField(t *testing.T) {
	if got := FileTypeField(0xF9, 0); got != [4]byte{'F', '9', ' ', ' '} {
		t.Errorf("F9/0 = %q", got)
	}
	if got := FileTypeField(0xB3, 0x03DB); got != [4]byte{'p', 0xB3, 0xDB, 0x03} {
		t.Errorf("B3/03DB = % x", got)
	}
}

func TestStampMemoOddLongName(t *testing.T) {
	fork := Build([]Resource{{Type: 0x8001, ID: 1, Data: []byte{1, 2, 3}}})
	m := Memo{Name: "Long.Odd.Name", FileType: FileTypeField(0xF9, 0),
		Creator: [4]byte{'p', 'd', 'o', 's'}, Created: 0x01020304, Const: 2,
		Tail: [8]byte{9, 9, 9, 9, 9, 9, 9, 9}, Marker: [2]byte{0x30, 0x44}}
	if err := StampMemo(fork, m); err != nil {
		t.Fatal(err)
	}
	memo := fork[memoStart : memoStart+memoSize]
	want := append([]byte{13}, "Long.Odd.Name"...)
	want = append(want, 2, 0, 0, 0)
	want = append(want, "F9  pdos"...)
	if !bytes.Equal(memo[memoNameOff:memoNameOff+len(want)], want) {
		t.Fatalf("name/type field = % x", memo[memoNameOff:memoNameOff+len(want)])
	}
	// copy 1's type/creator ends at 62: its tail just fits before 70, but the
	// marker (at 72) would cross it and is dropped
	if !bytes.Equal(memo[62:70], m.Tail[:]) {
		t.Errorf("copy-1 tail = % x", memo[62:70])
	}
	if !bytes.Equal(memo[70:78], []byte("F9  pdos")) {
		t.Errorf("marker overwrote copy 2: % x", memo[70:78])
	}
	if !bytes.Equal(memo[memoCopy2Off:memoCopy2Off+16], append([]byte("F9  pdos"), 9, 9, 9, 9, 9, 9, 9, 9)) {
		t.Errorf("copy 2 = % x", memo[memoCopy2Off:memoCopy2Off+16])
	}
	if got := binary.BigEndian.Uint32(memo[memoCreatedOff:]); got != 0x01020304 {
		t.Errorf("created = %#x", got)
	}
	if got := binary.BigEndian.Uint32(memo[memoForkLenOff:]); got != uint32(len(fork)) {
		t.Errorf("fork length = %d, want %d", got, len(fork))
	}
	if !bytes.Equal(memo[:memoNameOff], make([]byte, memoNameOff)) || !bytes.Equal(memo[114:], make([]byte, 14)) {
		t.Error("constant-zero areas written")
	}
}

func TestStampMemoEvenShortName(t *testing.T) {
	fork := Build(nil)
	m := Memo{Name: "Time", FileType: FileTypeField(0xC7, 0), Creator: [4]byte{'p', 'd', 'o', 's'},
		Const: 2, NamePad: 0xB4, Tail: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Marker: [2]byte{0x30, 0xAA}}
	if err := StampMemo(fork, m); err != nil {
		t.Fatal(err)
	}
	memo := fork[memoStart : memoStart+memoSize]
	// name field 1+4 is odd: a pad byte rounds it to 6, then the 2, copy 1 at 46
	if memo[41] != 0xB4 || binary.LittleEndian.Uint32(memo[42:]) != 2 {
		t.Fatalf("pad/const = % x", memo[36:46])
	}
	if !bytes.Equal(memo[46:62], append([]byte("C7  pdos"), 1, 2, 3, 4, 5, 6, 7, 8)) {
		t.Errorf("copy 1 = % x", memo[46:62])
	}
	if !bytes.Equal(memo[64:66], []byte{0x30, 0xAA}) {
		t.Errorf("marker = % x", memo[64:66])
	}
}

func TestStampMemoRejectsOverlong(t *testing.T) {
	fork := Build(nil)
	if err := StampMemo(fork, Memo{Name: "A.Name.Far.Too.Long.For.The.Memo"}); err == nil {
		t.Error("accepted a name that pushes type/creator past offset 70")
	}
	if err := StampMemo(make([]byte, 20), Memo{}); err == nil {
		t.Error("accepted a fork shorter than the memo")
	}
}
