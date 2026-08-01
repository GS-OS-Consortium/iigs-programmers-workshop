// omfdump prints the structure of an Apple IIgs OMF file: per-segment header
// fields and a record-type summary (or full record listing with -v).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dagenbrock/iigs-tools/omf"
)

func main() {
	verbose := flag.Bool("v", false, "list every record")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: omfdump [-v] file...")
		os.Exit(2)
	}
	exit := 0
	for _, path := range flag.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			exit = 1
			continue
		}
		f, err := omf.Parse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			exit = 1
		}
		fmt.Printf("%s: %d segment(s)\n", path, len(f.Segments))
		for i := range f.Segments {
			s := &f.Segments[i]
			fmt.Printf("  seg %d %-20q load=%-10q v%d kind=$%04X org=$%06X len=$%06X bytecnt=$%X\n",
				s.SegNum, s.SegName, s.LoadName, s.Version, s.Kind, s.Org, s.Length, s.ByteCnt)
			if *verbose {
				for _, r := range s.Records {
					fmt.Printf("    %-9s %5d bytes\n", omf.RecName(r.Op), len(r.Raw))
				}
			} else {
				counts := map[string]int{}
				for _, r := range s.Records {
					counts[omf.RecName(r.Op)]++
				}
				fmt.Printf("    records:")
				for _, n := range []string{"CONST", "LCONST", "DS", "RELOC", "cRELOC",
					"INTERSEG", "cINTERSEG", "SUPER", "EXPR", "LEXPR", "ZEXPR", "BEXPR",
					"RELEXPR", "GLOBAL", "LOCAL", "GEQU", "EQU", "USING", "STRONG",
					"ENTRY", "ALIGN", "ORG", "MEM", "END"} {
					if counts[n] > 0 {
						fmt.Printf(" %s=%d", n, counts[n])
					}
				}
				fmt.Println()
			}
		}
	}
	os.Exit(exit)
}
