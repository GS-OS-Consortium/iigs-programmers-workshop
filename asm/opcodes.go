package asm

// Addressing modes for the 65816 family.
type Mode int

const (
	Implied Mode = iota
	Accum
	ImmM // immediate sized by longa (m flag)
	ImmX // immediate sized by longi (x flag)
	Imm8 // always 8-bit immediate (sep/rep/cop/brk/wdm)
	DP
	DPX
	DPY
	Abs
	AbsX
	AbsY
	AbsL
	AbsLX
	DPInd   // (dp)
	DPIndX  // (dp,x)
	DPIndY  // (dp),y
	DPIndL  // [dp]
	DPIndLY // [dp],y
	SR      // sr,s
	SRIndY  // (sr,s),y
	AbsInd  // (abs)
	AbsIndX // (abs,x)
	AbsIndL // [abs]
	Rel8
	Rel16 // brl, per
	Move  // mvn/mvp
)

// operand byte length for a mode (ImmM/ImmX resolved by flag state).
func modeLen(m Mode) int {
	switch m {
	case Implied, Accum:
		return 0
	case Imm8, ImmM, ImmX, DP, DPX, DPY, DPInd, DPIndX, DPIndY, DPIndL, DPIndLY, SR, SRIndY, Rel8:
		return 1 // ImmM/ImmX widen to 2 via longa/longi at emit time
	case Abs, AbsX, AbsY, AbsInd, AbsIndX, AbsIndL, Rel16, Move:
		return 2
	case AbsL, AbsLX:
		return 3
	}
	panic("modeLen")
}

// cpu feature levels
const (
	cpu6502 = 1 << iota
	cpu65C02
	cpu65816
)

type opKey struct {
	mn string
	m  Mode
}

type opInfo struct {
	code byte
	cpu  int // minimum CPU level required
}

var ops = map[opKey]opInfo{}

type modeEnt struct {
	m    Mode
	code byte
	cpu  int
}

var opTable = map[string][]modeEnt{
	"adc": {{ImmM, 0x69, cpu6502}, {DP, 0x65, cpu6502}, {DPX, 0x75, cpu6502}, {Abs, 0x6D, cpu6502}, {AbsX, 0x7D, cpu6502}, {AbsY, 0x79, cpu6502}, {DPIndX, 0x61, cpu6502}, {DPIndY, 0x71, cpu6502}, {DPInd, 0x72, cpu65C02}, {AbsL, 0x6F, cpu65816}, {AbsLX, 0x7F, cpu65816}, {DPIndL, 0x67, cpu65816}, {DPIndLY, 0x77, cpu65816}, {SR, 0x63, cpu65816}, {SRIndY, 0x73, cpu65816}},
	"and": {{ImmM, 0x29, cpu6502}, {DP, 0x25, cpu6502}, {DPX, 0x35, cpu6502}, {Abs, 0x2D, cpu6502}, {AbsX, 0x3D, cpu6502}, {AbsY, 0x39, cpu6502}, {DPIndX, 0x21, cpu6502}, {DPIndY, 0x31, cpu6502}, {DPInd, 0x32, cpu65C02}, {AbsL, 0x2F, cpu65816}, {AbsLX, 0x3F, cpu65816}, {DPIndL, 0x27, cpu65816}, {DPIndLY, 0x37, cpu65816}, {SR, 0x23, cpu65816}, {SRIndY, 0x33, cpu65816}},
	"asl": {{Accum, 0x0A, cpu6502}, {Implied, 0x0A, cpu6502}, {DP, 0x06, cpu6502}, {DPX, 0x16, cpu6502}, {Abs, 0x0E, cpu6502}, {AbsX, 0x1E, cpu6502}},
	"bcc": {{Rel8, 0x90, cpu6502}},
	"blt": {{Rel8, 0x90, cpu6502}}, // alias of bcc
	"bcs": {{Rel8, 0xB0, cpu6502}},
	"bge": {{Rel8, 0xB0, cpu6502}}, // alias of bcs
	"beq": {{Rel8, 0xF0, cpu6502}},
	"bit": {{ImmM, 0x89, cpu65C02}, {DP, 0x24, cpu6502}, {DPX, 0x34, cpu65C02}, {Abs, 0x2C, cpu6502}, {AbsX, 0x3C, cpu65C02}},
	"bmi": {{Rel8, 0x30, cpu6502}},
	"bne": {{Rel8, 0xD0, cpu6502}},
	"bpl": {{Rel8, 0x10, cpu6502}},
	"bra": {{Rel8, 0x80, cpu65C02}},
	"brk": {{Imm8, 0x00, cpu6502}, {Implied, 0x00, cpu6502}},
	"brl": {{Rel16, 0x82, cpu65816}},
	"bvc": {{Rel8, 0x50, cpu6502}},
	"bvs": {{Rel8, 0x70, cpu6502}},
	"clc": {{Implied, 0x18, cpu6502}},
	"cld": {{Implied, 0xD8, cpu6502}},
	"cli": {{Implied, 0x58, cpu6502}},
	"clv": {{Implied, 0xB8, cpu6502}},
	"cmp": {{ImmM, 0xC9, cpu6502}, {DP, 0xC5, cpu6502}, {DPX, 0xD5, cpu6502}, {Abs, 0xCD, cpu6502}, {AbsX, 0xDD, cpu6502}, {AbsY, 0xD9, cpu6502}, {DPIndX, 0xC1, cpu6502}, {DPIndY, 0xD1, cpu6502}, {DPInd, 0xD2, cpu65C02}, {AbsL, 0xCF, cpu65816}, {AbsLX, 0xDF, cpu65816}, {DPIndL, 0xC7, cpu65816}, {DPIndLY, 0xD7, cpu65816}, {SR, 0xC3, cpu65816}, {SRIndY, 0xD3, cpu65816}},
	"cop": {{Imm8, 0x02, cpu65816}},
	"cpx": {{ImmX, 0xE0, cpu6502}, {DP, 0xE4, cpu6502}, {Abs, 0xEC, cpu6502}},
	"cpy": {{ImmX, 0xC0, cpu6502}, {DP, 0xC4, cpu6502}, {Abs, 0xCC, cpu6502}},
	"dec": {{Accum, 0x3A, cpu65C02}, {Implied, 0x3A, cpu65C02}, {DP, 0xC6, cpu6502}, {DPX, 0xD6, cpu6502}, {Abs, 0xCE, cpu6502}, {AbsX, 0xDE, cpu6502}},
	"dex": {{Implied, 0xCA, cpu6502}},
	"dey": {{Implied, 0x88, cpu6502}},
	"eor": {{ImmM, 0x49, cpu6502}, {DP, 0x45, cpu6502}, {DPX, 0x55, cpu6502}, {Abs, 0x4D, cpu6502}, {AbsX, 0x5D, cpu6502}, {AbsY, 0x59, cpu6502}, {DPIndX, 0x41, cpu6502}, {DPIndY, 0x51, cpu6502}, {DPInd, 0x52, cpu65C02}, {AbsL, 0x4F, cpu65816}, {AbsLX, 0x5F, cpu65816}, {DPIndL, 0x47, cpu65816}, {DPIndLY, 0x57, cpu65816}, {SR, 0x43, cpu65816}, {SRIndY, 0x53, cpu65816}},
	"inc": {{Accum, 0x1A, cpu65C02}, {Implied, 0x1A, cpu65C02}, {DP, 0xE6, cpu6502}, {DPX, 0xF6, cpu6502}, {Abs, 0xEE, cpu6502}, {AbsX, 0xFE, cpu6502}},
	"inx": {{Implied, 0xE8, cpu6502}},
	"iny": {{Implied, 0xC8, cpu6502}},
	"jml": {{AbsIndL, 0xDC, cpu65816}, {AbsL, 0x5C, cpu65816}},
	"jmp": {{Abs, 0x4C, cpu6502}, {AbsInd, 0x6C, cpu6502}, {AbsIndX, 0x7C, cpu65C02}, {AbsL, 0x5C, cpu65816}, {AbsIndL, 0xDC, cpu65816}},
	"jsl": {{AbsL, 0x22, cpu65816}},
	"jsr": {{Abs, 0x20, cpu6502}, {AbsIndX, 0xFC, cpu65816}, {AbsL, 0x22, cpu65816}},
	"lda": {{ImmM, 0xA9, cpu6502}, {DP, 0xA5, cpu6502}, {DPX, 0xB5, cpu6502}, {Abs, 0xAD, cpu6502}, {AbsX, 0xBD, cpu6502}, {AbsY, 0xB9, cpu6502}, {DPIndX, 0xA1, cpu6502}, {DPIndY, 0xB1, cpu6502}, {DPInd, 0xB2, cpu65C02}, {AbsL, 0xAF, cpu65816}, {AbsLX, 0xBF, cpu65816}, {DPIndL, 0xA7, cpu65816}, {DPIndLY, 0xB7, cpu65816}, {SR, 0xA3, cpu65816}, {SRIndY, 0xB3, cpu65816}},
	"ldx": {{ImmX, 0xA2, cpu6502}, {DP, 0xA6, cpu6502}, {DPY, 0xB6, cpu6502}, {Abs, 0xAE, cpu6502}, {AbsY, 0xBE, cpu6502}},
	"ldy": {{ImmX, 0xA0, cpu6502}, {DP, 0xA4, cpu6502}, {DPX, 0xB4, cpu6502}, {Abs, 0xAC, cpu6502}, {AbsX, 0xBC, cpu6502}},
	"lsr": {{Accum, 0x4A, cpu6502}, {Implied, 0x4A, cpu6502}, {DP, 0x46, cpu6502}, {DPX, 0x56, cpu6502}, {Abs, 0x4E, cpu6502}, {AbsX, 0x5E, cpu6502}},
	"mvn": {{Move, 0x54, cpu65816}},
	"mvp": {{Move, 0x44, cpu65816}},
	"nop": {{Implied, 0xEA, cpu6502}},
	"ora": {{ImmM, 0x09, cpu6502}, {DP, 0x05, cpu6502}, {DPX, 0x15, cpu6502}, {Abs, 0x0D, cpu6502}, {AbsX, 0x1D, cpu6502}, {AbsY, 0x19, cpu6502}, {DPIndX, 0x01, cpu6502}, {DPIndY, 0x11, cpu6502}, {DPInd, 0x12, cpu65C02}, {AbsL, 0x0F, cpu65816}, {AbsLX, 0x1F, cpu65816}, {DPIndL, 0x07, cpu65816}, {DPIndLY, 0x17, cpu65816}, {SR, 0x03, cpu65816}, {SRIndY, 0x13, cpu65816}},
	"pea": {{Abs, 0xF4, cpu65816}, {ImmM, 0xF4, cpu65816}},
	"pei": {{DPInd, 0xD4, cpu65816}, {DP, 0xD4, cpu65816}},
	"per": {{Rel16, 0x62, cpu65816}},
	"pha": {{Implied, 0x48, cpu6502}},
	"phb": {{Implied, 0x8B, cpu65816}},
	"phd": {{Implied, 0x0B, cpu65816}},
	"phk": {{Implied, 0x4B, cpu65816}},
	"php": {{Implied, 0x08, cpu6502}},
	"phx": {{Implied, 0xDA, cpu65C02}},
	"phy": {{Implied, 0x5A, cpu65C02}},
	"pla": {{Implied, 0x68, cpu6502}},
	"plb": {{Implied, 0xAB, cpu65816}},
	"pld": {{Implied, 0x2B, cpu65816}},
	"plp": {{Implied, 0x28, cpu6502}},
	"plx": {{Implied, 0xFA, cpu65C02}},
	"ply": {{Implied, 0x7A, cpu65C02}},
	"rep": {{Imm8, 0xC2, cpu65816}},
	"rol": {{Accum, 0x2A, cpu6502}, {Implied, 0x2A, cpu6502}, {DP, 0x26, cpu6502}, {DPX, 0x36, cpu6502}, {Abs, 0x2E, cpu6502}, {AbsX, 0x3E, cpu6502}},
	"ror": {{Accum, 0x6A, cpu6502}, {Implied, 0x6A, cpu6502}, {DP, 0x66, cpu6502}, {DPX, 0x76, cpu6502}, {Abs, 0x6E, cpu6502}, {AbsX, 0x7E, cpu6502}},
	"rti": {{Implied, 0x40, cpu6502}},
	"rtl": {{Implied, 0x6B, cpu65816}},
	"rts": {{Implied, 0x60, cpu6502}},
	"sbc": {{ImmM, 0xE9, cpu6502}, {DP, 0xE5, cpu6502}, {DPX, 0xF5, cpu6502}, {Abs, 0xED, cpu6502}, {AbsX, 0xFD, cpu6502}, {AbsY, 0xF9, cpu6502}, {DPIndX, 0xE1, cpu6502}, {DPIndY, 0xF1, cpu6502}, {DPInd, 0xF2, cpu65C02}, {AbsL, 0xEF, cpu65816}, {AbsLX, 0xFF, cpu65816}, {DPIndL, 0xE7, cpu65816}, {DPIndLY, 0xF7, cpu65816}, {SR, 0xE3, cpu65816}, {SRIndY, 0xF3, cpu65816}},
	"sec": {{Implied, 0x38, cpu6502}},
	"sed": {{Implied, 0xF8, cpu6502}},
	"sei": {{Implied, 0x78, cpu6502}},
	"sep": {{Imm8, 0xE2, cpu65816}},
	"sta": {{DP, 0x85, cpu6502}, {DPX, 0x95, cpu6502}, {Abs, 0x8D, cpu6502}, {AbsX, 0x9D, cpu6502}, {AbsY, 0x99, cpu6502}, {DPIndX, 0x81, cpu6502}, {DPIndY, 0x91, cpu6502}, {DPInd, 0x92, cpu65C02}, {AbsL, 0x8F, cpu65816}, {AbsLX, 0x9F, cpu65816}, {DPIndL, 0x87, cpu65816}, {DPIndLY, 0x97, cpu65816}, {SR, 0x83, cpu65816}, {SRIndY, 0x93, cpu65816}},
	"stp": {{Implied, 0xDB, cpu65816}},
	"stx": {{DP, 0x86, cpu6502}, {DPY, 0x96, cpu6502}, {Abs, 0x8E, cpu6502}},
	"sty": {{DP, 0x84, cpu6502}, {DPX, 0x94, cpu6502}, {Abs, 0x8C, cpu6502}},
	"stz": {{DP, 0x64, cpu65C02}, {DPX, 0x74, cpu65C02}, {Abs, 0x9C, cpu65C02}, {AbsX, 0x9E, cpu65C02}},
	"tax": {{Implied, 0xAA, cpu6502}},
	"tay": {{Implied, 0xA8, cpu6502}},
	"tcd": {{Implied, 0x5B, cpu65816}},
	"tcs": {{Implied, 0x1B, cpu65816}},
	"tdc": {{Implied, 0x7B, cpu65816}},
	"trb": {{DP, 0x14, cpu65C02}, {Abs, 0x1C, cpu65C02}},
	"tsb": {{DP, 0x04, cpu65C02}, {Abs, 0x0C, cpu65C02}},
	"tsc": {{Implied, 0x3B, cpu65816}},
	"tsx": {{Implied, 0xBA, cpu6502}},
	"txa": {{Implied, 0x8A, cpu6502}},
	"txs": {{Implied, 0x9A, cpu6502}},
	"txy": {{Implied, 0x9B, cpu65816}},
	"tya": {{Implied, 0x98, cpu6502}},
	"tyx": {{Implied, 0xBB, cpu65816}},
	"wai": {{Implied, 0xCB, cpu65816}},
	"wdm": {{Imm8, 0x42, cpu65816}, {Implied, 0x42, cpu65816}},
	"xba": {{Implied, 0xEB, cpu65816}},
	"xce": {{Implied, 0xFB, cpu65816}},
}

func init() {
	for mn, ents := range opTable {
		for _, e := range ents {
			ops[opKey{mn, e.m}] = opInfo{e.code, e.cpu}
		}
	}
}
