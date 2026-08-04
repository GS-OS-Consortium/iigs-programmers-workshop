# IIgs Programmers Workshop

A from-scratch, modern reimplementation (in Go) of the Apple **MPW IIGS**
cross-development toolchain — the Mac-hosted tools Apple used to build Apple
IIgs GS/OS System 6.0.1 — plus the MPW Make/Shell dialect the build system
depends on.

The fidelity bar is **byte-identical output**: every behavior is developed
against the original tools running under emulation (the "oracle"), and the
proof of correctness is that Apple's unmodified GS/OS 6.0.1 makefiles build
binaries that match the originals byte for byte — through assembly, linking,
library resolution, and load-file generation — and boot to the Finder.

## Tools

| Command | Reimplements | Notes |
|---|---|---|
| `asmiigs` | AsmIIGS 1.2 | 65816 assembler: full MPW macro language, RECORDs, conditionals, DUMP/LOAD symbol tables, OMF v2 output |
| `linkiigs` | LinkIIGS 1.2 | OMF linker: `-lseg` grouping, `-lib` hash-chain library pulls, ExpressLoad |
| `makebiniigs` | MakeBinIIGS 1.2 | Load file → binary image, applies relocation dictionaries |
| `reziigs` | RezIIGS | Resource compiler: type templates, the C-like preprocessor, `$$Word`/`$$Countof` builtins, `read` of converted code resources, IIgs resource file + map |
| `mpwmk` | MPW Make + Shell | Runs Apple's unmodified makefiles: `ƒ` rules, `∂` continuations, `{var}` expansion, MPW `:` paths, backquotes, built-ins, and in-process dispatch to all of the above (plus MakeLibIIGS, OverlayIIGS, RezIIGS) |
| `omfdump` | DumpObjIIGS (roughly) | Segment/record structure dumper for OMF files |
| `omfdiff` | — | Structural diff of two OMF files (exit 0 = identical) |

Library packages: `omf/` (OMF v1/v2/v2.1 reader/writer — round-trips real
object files, load files, and libraries byte-for-byte), `asm/`, `link/`,
`rez/`, `mpwmk/`.

## Build

Go 1.25+; no C dependencies.

```sh
go build ./...
go install ./cmd/...     # or: go build -o bin/ ./cmd/...
go test ./...
```

## Usage

Assemble, link, and flatten one file:

```sh
asmiigs prog.aii -o prog.obj -i include/dir -d DEBUG=0
linkiigs prog.obj -o prog
makebiniigs -org $2000 prog -o prog.bin
```

Run an unmodified MPW IIGS makefile:

```sh
mpwmk -f make.myproject -vars shell-variables -set "Project=/path/to/tree/" -C /path/to/tree
```

`mpwmk` understands the GS/OS-era Make dialect (MacRoman metacharacters
arrive either raw or as UTF-8), executes the shell built-ins the makefiles
use (`Echo`, `Directory`, `Duplicate`, `Delete`, `Catenate`, `NewFolder`,
`Set`, backquote substitution, `If`/`Else`/`End`), and dispatches tool
invocations (`AsmIIGS`, `LinkIIGS`, `MakeBinIIGS`, `MakeLibIIGS`,
`OverlayIIGS`, `RezIIGS`) to the in-process Go implementations.
`MPWMK_TOOLLOG` records every tool invocation with resolved paths, which is
what drives replay testing against the original tools.

Inspect object files:

```sh
omfdump -v file.obj
omfdiff a.obj b.obj
```

When a byte-diff says "our segment is N bytes short", `ASMIIGS_SEGMAP` maps a
segment's image offsets back to the source lines that produced them:

```sh
ASMIIGS_SEGMAP=IMAGERPROC asmiigs imager.aii -o /dev/null    # writes to stderr
```

## How correctness is established

None of the MPW IIGS file formats or tool behaviors are fully documented, so
the semantics here were recovered empirically: assemble a probe with the
original tool under emulation, read what it emits, implement, and gate the
result. Highlights of what that process recovered:

- the one-pass assembler's forward-reference binding, symbol scoping
  (per-segment labels, @local scope *chains* across macro expansions,
  RECORD/WITH field visibility), expression-record emission order, and the
  exact CONST/LCONST chunking of the original;
- the linker's segment placement rules (ORG padding, SKIP, TEMPORG,
  absolute segments), relocation encodings (cRELOC/SUPER pages), and the
  `-lib` symbol-table discipline: 512 hash buckets, ascending sweeps, and a
  move-at-most-once chain order;
- the resource compiler's file geometry (header, map, free list, the ten
  spare index slots), its bit-measured labels, the attribute bits behind
  `locked`/`convert`/`preload`, and the `rResName` resources it synthesizes
  for named resources;
- reproducible builds: `SOURCE_DATE_EPOCH` pins `&SYSDATE`/`&SYSTIME` so
  date-stamping sources rebuild identically.

Public tests use self-authored fixtures. Tests against Apple-derived
reference binaries load via the `IIGS_FIXTURES` environment variable and
skip when unset.

**This repo contains no Apple-derived bytes.**
