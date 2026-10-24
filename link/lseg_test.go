package link

import "testing"

func TestParseLsegOperand(t *testing.T) {
	tests := []struct {
		operand string
		name    string
		kind    uint16
		kindSet bool
		dynamic bool
		wantErr bool
	}{
		{operand: "SetStart", name: "SetStart"},
		{operand: "SetStart:$1000", name: "SetStart", kind: 0x1000, kindSet: true},
		{operand: "Main:$1000", name: "Main", kind: 0x1000, kindSet: true},
		{operand: "Mickey:$1000", name: "Mickey", kind: 0x1000, kindSet: true},
		{operand: "Darryl:$1000", name: "Darryl", kind: 0x1000, kindSet: true},
		{operand: "$1000:CDev", name: "CDev", kind: 0x1000, kindSet: true},
		{operand: "Pictures:$8000", name: "Pictures", kind: 0x8000, kindSet: true, dynamic: true},
		{operand: "$1000:nospecial", wantErr: true},
		{operand: "SetStart:RamDisk", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.operand, func(t *testing.T) {
			name, kind, kindSet, dynamic, err := ParseLsegOperand(tt.operand)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLsegOperand(%q) succeeded, want error", tt.operand)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLsegOperand(%q): %v", tt.operand, err)
			}
			if name != tt.name || kind != tt.kind || kindSet != tt.kindSet || dynamic != tt.dynamic {
				t.Fatalf("ParseLsegOperand(%q) = (%q, $%04X, kindSet=%v, dynamic=%v), want (%q, $%04X, kindSet=%v, dynamic=%v)",
					tt.operand, name, kind, kindSet, dynamic, tt.name, tt.kind, tt.kindSet, tt.dynamic)
			}
		})
	}
}
