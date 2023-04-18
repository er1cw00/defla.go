package defla

import (
	cs "github.com/er1cw00/btx.go/asm/cs"
	//logger "github.com/er1cw00/btx.go/base/logger"
)

func checkOpCond(cc uint32) uint32 {
	var _cc uint32 = R_COND_INV
	if cc == cs.ARM64_CC_AL || cc < 0 {
		_cc = R_COND_AL
	} else {
		switch cc {
		case cs.ARM64_CC_EQ:
			_cc = R_COND_EQ
		case cs.ARM64_CC_NE:
			_cc = R_COND_NE
		case cs.ARM64_CC_HS:
			_cc = R_COND_CS
		case cs.ARM64_CC_LO:
			_cc = R_COND_CC
		case cs.ARM64_CC_MI:
			_cc = R_COND_MI
		case cs.ARM64_CC_PL:
			_cc = R_COND_PL
		case cs.ARM64_CC_VS:
			_cc = R_COND_VS
		case cs.ARM64_CC_VC:
			_cc = R_COND_VC
		case cs.ARM64_CC_HI:
			_cc = R_COND_HI
		case cs.ARM64_CC_LS:
			_cc = R_COND_LS
		case cs.ARM64_CC_GE:
			_cc = R_COND_GE
		case cs.ARM64_CC_LT:
			_cc = R_COND_LT
		case cs.ARM64_CC_GT:
			_cc = R_COND_GT
		case cs.ARM64_CC_LE:
			_cc = R_COND_LE
		}
	}
	return _cc
}

func newOp(insn *cs.Instruction) *Op {

	// var result = false
	var opType uint32 = R_OP_TYPE_NULL
	var jump uint64 = 0
	var fail uint64 = 0
	var opCond uint32 = R_COND_INV

	id := insn.GetId()
	addr := insn.GetAddr()
	detail := insn.GetDetail().(*cs.Arm64Detail)
	opCond = checkOpCond(detail.CC)

	switch id {
	case cs.ARM64_INS_SVC:
		opType = R_OP_TYPE_SWI
	case cs.ARM64_INS_ADRP, cs.ARM64_INS_ADR:
		opType = R_OP_TYPE_LEA
	case cs.ARM64_INS_NOP:
		opType = R_OP_TYPE_NOP
	case cs.ARM64_INS_SUB, cs.ARM64_INS_MSUB:
		opType = R_OP_TYPE_SUB
	case cs.ARM64_INS_FDIV, cs.ARM64_INS_SDIV, cs.ARM64_INS_UDIV:
		opType = R_OP_TYPE_DIV
	case cs.ARM64_INS_MUL,
		cs.ARM64_INS_SMULL,
		cs.ARM64_INS_FMUL,
		cs.ARM64_INS_UMULL:
		opType = R_OP_TYPE_MUL
	case cs.ARM64_INS_ADDG,
		cs.ARM64_INS_ADD,
		cs.ARM64_INS_ADC,
		cs.ARM64_INS_UMADDL,
		cs.ARM64_INS_SMADDL,
		cs.ARM64_INS_FMADD,
		cs.ARM64_INS_MADD:
		opType = R_OP_TYPE_ADD
	case cs.ARM64_INS_MOV,
		cs.ARM64_INS_MOVI,
		cs.ARM64_INS_MOVK,
		cs.ARM64_INS_MOVN,
		cs.ARM64_INS_SMOV,
		cs.ARM64_INS_UMOV,
		cs.ARM64_INS_FMOV,
		cs.ARM64_INS_SBFX,
		cs.ARM64_INS_UBFX,
		cs.ARM64_INS_UBFM,
		cs.ARM64_INS_BFI,
		cs.ARM64_INS_SBFIZ,
		cs.ARM64_INS_UBFIZ,
		cs.ARM64_INS_BIC,
		cs.ARM64_INS_BFXIL,
		cs.ARM64_INS_MOVZ:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_UXTB,
		cs.ARM64_INS_SXTB,
		cs.ARM64_INS_UXTH,
		cs.ARM64_INS_SXTH,
		cs.ARM64_INS_UXTW,
		cs.ARM64_INS_SXTW:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_MRS, cs.ARM64_INS_MSR:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_DUP,
		cs.ARM64_INS_XTN,
		cs.ARM64_INS_XTN2,
		cs.ARM64_INS_REV64,
		cs.ARM64_INS_EXT,
		cs.ARM64_INS_INS:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_LSL, cs.ARM64_INS_SHL, cs.ARM64_INS_USHLL:
		opType = R_OP_TYPE_SHL
	case cs.ARM64_INS_LSR:
		opType = R_OP_TYPE_SHR
	case cs.ARM64_INS_ASR:
		opType = R_OP_TYPE_SAR
	case cs.ARM64_INS_NEG, cs.ARM64_INS_NEGS:
		opType = R_OP_TYPE_NOT
	case cs.ARM64_INS_ROR:
		opType = R_OP_TYPE_ROR
	case cs.ARM64_INS_AND:
		opType = R_OP_TYPE_AND
	case cs.ARM64_INS_ORR, cs.ARM64_INS_ORN:
		opType = R_OP_TYPE_OR
	case cs.ARM64_INS_EOR, cs.ARM64_INS_EON:
		opType = R_OP_TYPE_XOR
	case cs.ARM64_INS_BRK, cs.ARM64_INS_HLT:
		opType = R_OP_TYPE_TRAP
	case cs.ARM64_INS_CSEL, cs.ARM64_INS_FCSEL, cs.ARM64_INS_CSET, cs.ARM64_INS_CINC:
		opType = R_OP_TYPE_CMOV
	case cs.ARM64_INS_FCMP,
		cs.ARM64_INS_CCMP,
		cs.ARM64_INS_CCMN,
		cs.ARM64_INS_CMP,
		cs.ARM64_INS_CMN,
		cs.ARM64_INS_TST:
		opType = R_OP_TYPE_CMP
	case cs.ARM64_INS_RETAA, cs.ARM64_INS_RETAB, cs.ARM64_INS_ERETAA, cs.ARM64_INS_ERETAB:
		opType = R_OP_TYPE_RET
	case cs.ARM64_INS_ERET:
		opType = R_OP_TYPE_RET
	case cs.ARM64_INS_RET:
		opType = R_OP_TYPE_RET
	case cs.ARM64_INS_BL:
		opType = R_OP_TYPE_CALL
		jump = uint64(detail.Operands[0].Value.Imm)
		fail = addr + 4
	case cs.ARM64_INS_BLR:
		opType = R_OP_TYPE_RCALL
		fail = addr + 4
	case cs.ARM64_INS_CBZ, cs.ARM64_INS_CBNZ:
		opType = R_OP_TYPE_CJMP
		jump = uint64(detail.Operands[1].Value.Imm)
		fail = addr + 4
	case cs.ARM64_INS_TBZ, cs.ARM64_INS_TBNZ:
		opType = R_OP_TYPE_CJMP
		jump = uint64(detail.Operands[2].Value.Imm)
		fail = addr + 4
	case cs.ARM64_INS_BR:
		opType = R_OP_TYPE_RJMP
	case cs.ARM64_INS_B:
		if detail.Operands[0].Value.Reg == cs.ARM64_REG_LR {
			opType = R_OP_TYPE_RET
		} else if detail.CC != cs.ARM64_CC_INVALID {
			jump = uint64(detail.Operands[0].Value.Imm)
			fail = addr + 4
			opType = R_OP_TYPE_CJMP
		} else {
			jump = uint64(detail.Operands[0].Value.Imm)
			opType = R_OP_TYPE_JMP
		}
	case cs.ARM64_INS_STRB,
		cs.ARM64_INS_STURB,
		cs.ARM64_INS_STUR,
		cs.ARM64_INS_STR,
		cs.ARM64_INS_STP,
		cs.ARM64_INS_STNP,
		cs.ARM64_INS_STXR,
		cs.ARM64_INS_STXRH,
		cs.ARM64_INS_STLXR,
		cs.ARM64_INS_STLXRH,
		cs.ARM64_INS_STXRB:
		opType = R_OP_TYPE_STORE
	case cs.ARM64_INS_LDRAA, cs.ARM64_INS_LDRAB:
		opType = R_OP_TYPE_LOAD
	case cs.ARM64_INS_LDUR,
		cs.ARM64_INS_LDURB,
		cs.ARM64_INS_LDRSW,
		cs.ARM64_INS_LDRSB,
		cs.ARM64_INS_LDRSH,
		cs.ARM64_INS_LDR,
		cs.ARM64_INS_LDURSW,
		cs.ARM64_INS_LDP,
		cs.ARM64_INS_LDNP,
		cs.ARM64_INS_LDPSW,
		cs.ARM64_INS_LDRH,
		cs.ARM64_INS_LDRB:
		reg0 := detail.Operands[0].Value.Reg
		if reg0 == cs.ARM_REG_PC {
			opType = R_OP_TYPE_MJMP
			if detail.CC != cs.ARM64_CC_AL {
				opType = R_OP_TYPE_MCJMP
			}
		} else {
			opType = R_OP_TYPE_LOAD
		}
		switch id {
		case cs.ARM64_INS_LDPSW, cs.ARM64_INS_LDRSW, cs.ARM64_INS_LDRSH, cs.ARM64_INS_LDRSB:
			if detail.Operands[1].Value.Mem.Base != cs.ARM64_REG_X29 &&
				detail.Operands[1].Type == cs.ARM64_OP_IMM|cs.ARM64_OP_CIMM|cs.ARM64_OP_FP {
				opType = R_OP_TYPE_LEA
			}
		}
	case cs.ARM64_INS_IC, cs.ARM64_INS_DC:
		opType = R_OP_TYPE_SYNC
	case cs.ARM64_INS_IRG:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_BLRAA, cs.ARM64_INS_BLRAAZ, cs.ARM64_INS_BLRAB, cs.ARM64_INS_BLRABZ:
		opType = R_OP_TYPE_RCALL
	case cs.ARM64_INS_BRAA, cs.ARM64_INS_BRAAZ,
		cs.ARM64_INS_BRAB, cs.ARM64_INS_BRABZ:
		opType = R_OP_TYPE_RJMP
	}
	if opType != R_OP_TYPE_NULL {
		return &Op{
			Instruction: *insn,
			OpType:      opType,
			OpCond:      opCond,
			Jump:        jump,
			Fail:        fail,
		}
	}
	return nil
}
