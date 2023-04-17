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
		}
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
