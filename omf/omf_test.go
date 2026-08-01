package omf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Apple-derived reference files live outside this public repo; point
// IIGS_FIXTURES at the gsos-601 checkout to enable these tests.
func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	root := os.Getenv("IIGS_FIXTURES")
	if root == "" {
		t.Skip("IIGS_FIXTURES not set")
	}
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The in-tree Applesoft chain plus assorted prebuilt OMF artifacts — object
// files, load files (incl. ExpressLoad Finder), and a MakeLibIIGS library.
var fixtureFiles = []string{
	"upstream/IIGS.601.SRC/GSFirmware/Applesoft/Applesoft.obj",
	"upstream/IIGS.601.SRC/GSFirmware/Applesoft/Applesoft.rel",
	"upstream/IIGS.601.SRC/A.U.G/Finder/Finder",
	"upstream/IIGS.601.SRC/A.U.G/Installer/Installer",
	"upstream/IIGS.601.SRC/A.U.G/Installer/Objects/GSOString.lib",
	"upstream/IIGS.601.SRC/A.U.G/Installer/Objects/Installer.Load",
	"upstream/IIGS.601.SRC/GSToolbox/Patch/Patch2/TS2",
	"upstream/IIGS.601.SRC/GSToolbox/Patch/Patch3/TS3",
	"upstream/IIGS.601.SRC/ToolBoxMisc/Teach/Teach",
	"upstream/IIGS.601.SRC/Debugger/debug.init",
	"upstream/IIGS.601.SRC/A.U.G/CtlPanel/NetworkCDEV/network.Load",
	"upstream/IIGS.601.SRC/A.U.G/CtlPanel/SoundCDEV/ReqProc.Load",
	"upstream/IIGS.601.SRC/A.U.G/Finder/EasyMount/EasyMount",
}

func TestParseFixtures(t *testing.T) {
	for _, rel := range fixtureFiles {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			data := fixture(t, rel)
			f, err := Parse(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(f.Segments) == 0 {
				t.Fatal("no segments")
			}
			for i := range f.Segments {
				if f.Segments[i].Version != 1 && f.Segments[i].Version != 2 {
					t.Errorf("segment %d: bad version %d", i, f.Segments[i].Version)
				}
			}
		})
	}
}

func TestRoundTripFixtures(t *testing.T) {
	for _, rel := range fixtureFiles {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			data := fixture(t, rel)
			f, err := Parse(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			out := f.Write()
			// Write() reproduces segments; input may have zero padding after
			// the last segment which Parse tolerates and Write drops.
			if !bytes.Equal(out, data[:len(out)]) {
				t.Fatalf("round-trip mismatch: %d in, %d out", len(data), len(out))
			}
			for _, b := range data[len(out):] {
				if b != 0 {
					t.Fatalf("non-zero trailing byte dropped")
				}
			}
		})
	}
}
