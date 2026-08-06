package mpwmk

// The oracle bridge runs an ORIGINAL MPW IIGS tool under emulation for the
// languages we have no reimplementation of (PascalIIGS, CIIGS, ...). This is
// the project's compiler ladder: the original compiler is the production
// compiler, driven from the same makefile as everything else.
//
// MPWMK_ORACLE names the runner script (gsos-601's oracle/run). Each
// invocation stages the current directory into a scratch tree the emulated
// tool can read -- CR/MacRoman text with a TEXT/MPS Finder type, binaries
// verbatim with their recorded type -- runs the tool there, and copies every
// new or changed file back, byte-exact, with its Finder type preserved in a
// sidecar xattr so a later invocation can restage it faithfully.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// oracleTools maps makefile command names to the original tool binaries.
var oracleTools = map[string]string{
	"pascaliigs": "PascalIIGS",
	"ciigs":      "CIIGS",
	"pasasmiigs": "PasAsmIIGS",
	"tmlpascal":  "TMLPascal",
	"tmlpas":     "tmlpas",
	"tmlclean":   "TMLClean",
}

const textFinderInfo = "TEXTMPS \x00\x00\x00\x00\x00\x00\x00\x00" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

var macRoman = charmap.Macintosh.NewEncoder()

func getFinderInfo(path string) []byte {
	out, err := exec.Command("xattr", "-px", "com.apple.FinderInfo", path).Output()
	if err != nil {
		return nil
	}
	hex := strings.Fields(strings.ReplaceAll(string(out), "\n", " "))
	var b []byte
	for _, h := range hex {
		for i := 0; i+2 <= len(h); i += 2 {
			var v byte
			fmt.Sscanf(h[i:i+2], "%02X", &v)
			b = append(b, v)
		}
	}
	return b
}

func setFinderInfo(path string, info []byte) {
	if len(info) == 0 {
		return
	}
	var sb strings.Builder
	for _, b := range info {
		fmt.Fprintf(&sb, "%02X", b)
	}
	exec.Command("xattr", "-wx", "com.apple.FinderInfo", sb.String(), path).Run()
}

// isTextFile: valid UTF-8 with no NUL bytes. (An OMF object can decode as
// UTF-8 -- NUL is valid -- so the NUL check is what actually decides.)
func isTextFile(data []byte) bool {
	return !strings.Contains(string(data), "\x00") && utf8.Valid(data)
}

// runOracleTool stages e.Dir, runs the named original tool there, and pulls
// the outputs back.
func (e *Env) runOracleTool(name string, args []string) error {
	runner := os.Getenv("MPWMK_ORACLE")
	if runner == "" {
		return fmt.Errorf("%s: original-tool bridge disabled (set MPWMK_ORACLE to the oracle runner)", name)
	}
	tool := oracleTools[name]

	work, err := os.MkdirTemp("", "mpwmk-oracle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	// Stage the invocation directory (flat -- MPW builds compile in their
	// source directory; subdirectory inputs are rare enough to stage on
	// demand when a target needs them).
	snapshot := map[string]string{} // staged name -> content hash of input
	ents, err := os.ReadDir(e.Dir)
	if err != nil {
		return err
	}
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		src := filepath.Join(e.Dir, ent.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		dst := filepath.Join(work, ent.Name())
		info := getFinderInfo(src)
		if isTextFile(data) {
			if mac, err := macRoman.Bytes(data); err == nil {
				data = mac
			}
			data = []byte(strings.ReplaceAll(string(data), "\n", "\r"))
			if len(info) == 0 {
				info = []byte(textFinderInfo)
			}
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return err
		}
		setFinderInfo(dst, info)
		snapshot[ent.Name()] = fmt.Sprintf("%d:%x", len(data), data[:min(len(data), 64)])
	}

	// Arguments: path-like operands become their base names (everything the
	// tool needs sits flat in the work dir); flags pass through.
	var targs []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || !strings.ContainsAny(a, ":/") {
			targs = append(targs, a)
			continue
		}
		targs = append(targs, filepath.Base(strings.ReplaceAll(strings.TrimSuffix(e.HostPath(a), "/"), ":", "/")))
	}

	cmd := exec.Command(runner, append([]string{tool}, targs...)...)
	cmd.Dir = work
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(macToUTF8(outBytes))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s (oracle): %s", name, msg)
	}
	e.logOracle(name, args)

	// Copy back everything the tool created or rewrote, byte-exact, with its
	// Finder type mirrored so a later staging round-trips it.
	after, err := os.ReadDir(work)
	if err != nil {
		return err
	}
	for _, ent := range after {
		if ent.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(work, ent.Name()))
		if err != nil {
			continue
		}
		sig := fmt.Sprintf("%d:%x", len(data), data[:min(len(data), 64)])
		if prev, ok := snapshot[ent.Name()]; ok && prev == sig {
			continue
		}
		dst := filepath.Join(e.Dir, ent.Name())
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return err
		}
		setFinderInfo(dst, getFinderInfo(filepath.Join(work, ent.Name())))
	}
	return nil
}

func macToUTF8(b []byte) string {
	dec := charmap.Macintosh.NewDecoder()
	if u, err := dec.Bytes(b); err == nil {
		return strings.ReplaceAll(string(u), "\r", "\n")
	}
	return string(b)
}

// logOracle records an original-tool invocation in the tool log so the
// sweeps can list it (there is nothing to replay -- the original tool IS the
// oracle).
func (e *Env) logOracle(name string, args []string) {
	path := os.Getenv("MPWMK_TOOLLOG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	rec := append([]string{"oracle", name}, args...)
	fmt.Fprintln(f, strings.Join(rec, "\t"))
}
