# iigs-tools

A from-scratch, modern reimplementation (in Go) of the Apple **MPW IIGS**
cross-development toolchain — the Mac-hosted tools Apple used to build Apple
IIgs GS/OS System 6.0.1: `AsmIIGS`, `LinkIIGS`, `MakeBinIIGS`, `RezIIGS`,
`MakeLibIIGS`, `ExpressIIGS`, plus the MPW Make/Shell dialect the build
system depends on.

Status: early. Working today:

- `omf/` — OMF v1/v2/v2.1 (Apple IIgs Object Module Format) reader/writer.
  Parses the full record grammar including expression records, and
  round-trips real object files, load files (incl. ExpressLoad), and
  libraries byte-for-byte.
- `cmd/omfdump` — segment/record structure dumper.

Testing: public tests use self-authored fixtures. Tests against Apple-derived
reference binaries (the GS/OS 6.0.1 source tree's prebuilt artifacts) load
via the `IIGS_FIXTURES` environment variable and skip when unset.

This repo contains no Apple-derived bytes.
