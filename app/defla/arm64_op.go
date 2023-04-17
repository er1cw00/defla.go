package defla

import (
	cs "github.com/er1cw00/btx.go/asm/cs"
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
	case cs.ARM64_INS_ADRP:
	case cs.ARM64_INS_ADR:
		opType = R_OP_TYPE_LEA
	case cs.ARM64_INS_NOP:
		opType = R_OP_TYPE_NOP
	case cs.ARM64_INS_SUB:
	case cs.ARM64_INS_MSUB:
		opType = R_OP_TYPE_SUB
	case cs.ARM64_INS_FDIV:
	case cs.ARM64_INS_SDIV:
	case cs.ARM64_INS_UDIV:
		opType = R_OP_TYPE_DIV
	case cs.ARM64_INS_MUL:
	case cs.ARM64_INS_SMULL:
	case cs.ARM64_INS_FMUL:
	case cs.ARM64_INS_UMULL:
		opType = R_OP_TYPE_MUL
	case cs.ARM64_INS_ADDG:
	case cs.ARM64_INS_ADD:
	case cs.ARM64_INS_ADC:
	case cs.ARM64_INS_UMADDL:
	case cs.ARM64_INS_SMADDL:
	case cs.ARM64_INS_FMADD:
	case cs.ARM64_INS_MADD:
		opType = R_OP_TYPE_ADD
	case cs.ARM64_INS_MOV:
	case cs.ARM64_INS_MOVI:
	case cs.ARM64_INS_MOVK:
	case cs.ARM64_INS_MOVN:
	case cs.ARM64_INS_SMOV:
	case cs.ARM64_INS_UMOV:
	case cs.ARM64_INS_FMOV:
	case cs.ARM64_INS_SBFX:
	case cs.ARM64_INS_UBFX:
	case cs.ARM64_INS_UBFM:
	case cs.ARM64_INS_BFI:
	case cs.ARM64_INS_SBFIZ:
	case cs.ARM64_INS_UBFIZ:
	case cs.ARM64_INS_BIC:
	case cs.ARM64_INS_BFXIL:
	case cs.ARM64_INS_MOVZ:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_UXTB:
	case cs.ARM64_INS_SXTB:
	case cs.ARM64_INS_UXTH:
	case cs.ARM64_INS_SXTH:
	case cs.ARM64_INS_UXTW:
	case cs.ARM64_INS_SXTW:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_MRS:
	case cs.ARM64_INS_MSR:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_DUP:
	case cs.ARM64_INS_XTN:
	case cs.ARM64_INS_XTN2:
	case cs.ARM64_INS_REV64:
	case cs.ARM64_INS_EXT:
	case cs.ARM64_INS_INS:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_LSL:
	case cs.ARM64_INS_SHL:
	case cs.ARM64_INS_USHLL:
		opType = R_OP_TYPE_SHL
	case cs.ARM64_INS_LSR:
		opType = R_OP_TYPE_SHR
	case cs.ARM64_INS_ASR:
		opType = R_OP_TYPE_SAR
	case cs.ARM64_INS_NEG:
	case cs.ARM64_INS_NEGS:
		opType = R_OP_TYPE_NOT
	case cs.ARM64_INS_ROR:
		opType = R_OP_TYPE_ROR
	case cs.ARM64_INS_AND:
		opType = R_OP_TYPE_AND
	case cs.ARM64_INS_ORR:
	case cs.ARM64_INS_ORN:
		opType = R_OP_TYPE_OR
	case cs.ARM64_INS_EOR:
	case cs.ARM64_INS_EON:
		opType = R_OP_TYPE_XOR

	case cs.ARM64_INS_BRK:
	case cs.ARM64_INS_HLT:
		opType = R_OP_TYPE_TRAP
	case cs.ARM64_INS_CSEL:
	case cs.ARM64_INS_FCSEL:
	case cs.ARM64_INS_CSET:
	case cs.ARM64_INS_CINC:
		opType = R_OP_TYPE_CMOV
	case cs.ARM64_INS_FCMP:
	case cs.ARM64_INS_CCMP:
	case cs.ARM64_INS_CCMN:
	case cs.ARM64_INS_CMP:
	case cs.ARM64_INS_CMN:
	case cs.ARM64_INS_TST:
		opType = R_OP_TYPE_CMP
	case cs.ARM64_INS_RETAA:
	case cs.ARM64_INS_RETAB:
	case cs.ARM64_INS_ERETAA:
	case cs.ARM64_INS_ERETAB:
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
	case cs.ARM64_INS_CBZ:
	case cs.ARM64_INS_CBNZ:
		opType = R_OP_TYPE_CJMP
		jump = uint64(detail.Operands[1].Value.Imm)
		fail = addr + 4
	case cs.ARM64_INS_TBZ:
	case cs.ARM64_INS_TBNZ:
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
	case cs.ARM64_INS_STRB:
	case cs.ARM64_INS_STURB:
	case cs.ARM64_INS_STUR:
	case cs.ARM64_INS_STR:
	case cs.ARM64_INS_STP:
	case cs.ARM64_INS_STNP:
	case cs.ARM64_INS_STXR:
	case cs.ARM64_INS_STXRH:
	case cs.ARM64_INS_STLXR:
	case cs.ARM64_INS_STLXRH:
	case cs.ARM64_INS_STXRB:
		opType = R_OP_TYPE_STORE
	case cs.ARM64_INS_LDRAA:
	case cs.ARM64_INS_LDRAB:
		opType = R_OP_TYPE_LOAD
	case cs.ARM64_INS_LDUR:
	case cs.ARM64_INS_LDURB:
	case cs.ARM64_INS_LDRSW:
	case cs.ARM64_INS_LDRSB:
	case cs.ARM64_INS_LDRSH:
	case cs.ARM64_INS_LDR:
	case cs.ARM64_INS_LDURSW:
	case cs.ARM64_INS_LDP:
	case cs.ARM64_INS_LDNP:
	case cs.ARM64_INS_LDPSW:
	case cs.ARM64_INS_LDRH:
	case cs.ARM64_INS_LDRB:
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
		case cs.ARM64_INS_LDPSW:
		case cs.ARM64_INS_LDRSW:
		case cs.ARM64_INS_LDRSH:
		case cs.ARM64_INS_LDRSB:
			if detail.Operands[1].Value.Mem.Base != cs.ARM64_REG_X29 &&
				detail.Operands[1].Type == cs.ARM64_OP_IMM|cs.ARM64_OP_CIMM|cs.ARM64_OP_FP {
				opType = R_OP_TYPE_LEA
			}
		}
	case cs.ARM64_INS_IC:
	case cs.ARM64_INS_DC:
		opType = R_OP_TYPE_SYNC
	case cs.ARM64_INS_IRG:
		opType = R_OP_TYPE_MOV
	case cs.ARM64_INS_BLRAA:
	case cs.ARM64_INS_BLRAAZ:
	case cs.ARM64_INS_BLRAB:
	case cs.ARM64_INS_BLRABZ:
		opType = R_OP_TYPE_RCALL
	case cs.ARM64_INS_BRAA:
	case cs.ARM64_INS_BRAAZ:
	case cs.ARM64_INS_BRAB:
	case cs.ARM64_INS_BRABZ:
		opType = R_OP_TYPE_RJMP
	case cs.ARM64_INS_RETAA:
	case cs.ARM64_INS_RETAB:
	case cs.ARM64_INS_ERETAA:
	case cs.ARM64_INS_ERETAB:
	case cs.ARM64_INS_ERET:
	case cs.ARM64_INS_RET:

		opType = R_OP_TYPE_RET

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
