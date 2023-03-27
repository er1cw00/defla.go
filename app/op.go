package app

import (
	//"fmt"

	cs "github.com/er1cw00/btx.go/asm/cs"
)

/* * *
   0000 = EQ - Z set (equal，相等)
   0001 = NE - Z clear (not equal，不相等)
   0010 = CS - C set (unsigned higher or same，无符号大于或等于)
   0011 = CC - C clear (unsigned lower，无符号小于)
   0100 = MI - N set (negative，负数)
   0101 = PL - N clear (positive or zero，正数或零)
   0110 = VS - V set (overflow，溢出)
   0111 = VC - V clear (no overflow，未溢出)
   1000 = HI - C set and Z clear (unsigned higher，无符号大于)
   1001 = LS - C clear or Z set (unsigned lower or same，无符号小于或等于)
   1010 = GE - N set and V set or N clear and V clear (greater or equal，带符号大于或等于)
   1011 = LT - N set and V clear or N clear and V set (less than，带符号小于)
   1100 = GT - Z clear and either N set and V set or N clear and V clear (greater than，带符号大于)
   1101 = LE - Z set or N set and V clear or N clear and V set (less than or equal，带符号小于或等于)
   1110 = AL - always
   1111 = NV - never
*/
const (
	R_COND_INV uint32 = 0
	R_COND_EQ  uint32 = 1
	R_COND_NE  uint32 = 2
	R_COND_CS  uint32 = 3 //HS
	R_COND_CC  uint32 = 4 //LO
	R_COND_MI  uint32 = 5
	R_COND_PL  uint32 = 6
	R_COND_VS  uint32 = 7
	R_COND_VC  uint32 = 8
	R_COND_HI  uint32 = 9
	R_COND_LS  uint32 = 10
	R_COND_GE  uint32 = 11
	R_COND_LT  uint32 = 12
	R_COND_GT  uint32 = 13
	R_COND_LE  uint32 = 14
	R_COND_AL  uint32 = 15
	R_COND_NV  uint32 = 16
)

const (
	R_OP_TYPE_MASK   uint32 = 0x8000ffff
	R_OP_HINT_MASK   uint32 = 0xf0000000
	R_OP_TYPE_COND   uint32 = 0x80000000 // TODO must be moved to prefix?
	R_OP_TYPE_REP    uint32 = 0x40000000 /* repeats next instruction N times */
	R_OP_TYPE_MEM    uint32 = 0x20000000 // TODO must be moved to prefix?
	R_OP_TYPE_REG    uint32 = 0x10000000 // operand is a register
	R_OP_TYPE_IND    uint32 = 0x08000000 // operand is indirect
	R_OP_TYPE_NULL   uint32 = 0
	R_OP_TYPE_JMP    uint32 = 1 /* mandatory jump */
	R_OP_TYPE_UJMP   uint32 = 2 /* unknown jump (register or so) */
	R_OP_TYPE_RJMP   uint32 = R_OP_TYPE_UJMP | R_OP_TYPE_REG
	R_OP_TYPE_UCJMP  uint32 = R_OP_TYPE_UJMP | R_OP_TYPE_COND /* conditional unknown jump */
	R_OP_TYPE_IJMP   uint32 = R_OP_TYPE_UJMP | R_OP_TYPE_IND
	R_OP_TYPE_IRJMP  uint32 = R_OP_TYPE_UJMP | R_OP_TYPE_REG | R_OP_TYPE_IND
	R_OP_TYPE_CJMP   uint32 = R_OP_TYPE_JMP | R_OP_TYPE_COND /* conditional jump */
	R_OP_TYPE_MJMP   uint32 = R_OP_TYPE_JMP | R_OP_TYPE_MEM  /* memory jump */
	R_OP_TYPE_RCJMP  uint32 = R_OP_TYPE_CJMP | R_OP_TYPE_REG /* conditional jump register */
	R_OP_TYPE_MCJMP  uint32 = R_OP_TYPE_CJMP | R_OP_TYPE_MEM /* memory conditional jump */
	R_OP_TYPE_CALL   uint32 = 3                              /* call to subroutine (branch+link) */
	R_OP_TYPE_UCALL  uint32 = 4                              /* unknown call (register or so) */
	R_OP_TYPE_RCALL  uint32 = R_OP_TYPE_UCALL | R_OP_TYPE_REG
	R_OP_TYPE_ICALL  uint32 = R_OP_TYPE_UCALL | R_OP_TYPE_IND
	R_OP_TYPE_IRCALL uint32 = R_OP_TYPE_UCALL | R_OP_TYPE_REG | R_OP_TYPE_IND
	R_OP_TYPE_CCALL  uint32 = R_OP_TYPE_CALL | R_OP_TYPE_COND  /* conditional call to subroutine */
	R_OP_TYPE_UCCALL uint32 = R_OP_TYPE_UCALL | R_OP_TYPE_COND /* conditional unknown call */
	R_OP_TYPE_RET    uint32 = 5                                /* returns from subroutine */
	R_OP_TYPE_CRET   uint32 = R_OP_TYPE_COND | R_OP_TYPE_RET   /* conditional return from subroutine */
	R_OP_TYPE_ILL    uint32 = 6                                /* illegal instruction // trap */
	R_OP_TYPE_UNK    uint32 = 7                                /* unknown opcode type */
	R_OP_TYPE_NOP    uint32 = 8                                /* does nothing */
	R_OP_TYPE_MOV    uint32 = 9                                /* register move */
	R_OP_TYPE_CMOV   uint32 = 9 | R_OP_TYPE_COND               /* conditional move */
	R_OP_TYPE_TRAP   uint32 = 10                               /* it's a trap! */
	R_OP_TYPE_SWI    uint32 = 11                               /* syscall software interrupt */
	R_OP_TYPE_CSWI   uint32 = 11 | R_OP_TYPE_COND              /* syscall software interrupt */
	R_OP_TYPE_UPUSH  uint32 = 12                               /* unknown push of data into stack */
	R_OP_TYPE_RPUSH  uint32 = R_OP_TYPE_UPUSH | R_OP_TYPE_REG  /* push register */
	R_OP_TYPE_PUSH   uint32 = 13                               /* push value into stack */
	R_OP_TYPE_POP    uint32 = 14                               /* pop value from stack to register */
	R_OP_TYPE_CMP    uint32 = 15                               /* compare something */
	R_OP_TYPE_ACMP   uint32 = 16                               /* compare via and */
	R_OP_TYPE_ADD    uint32 = 17
	R_OP_TYPE_SUB    uint32 = 18
	R_OP_TYPE_IO     uint32 = 19
	R_OP_TYPE_MUL    uint32 = 20
	R_OP_TYPE_DIV    uint32 = 21
	R_OP_TYPE_SHR    uint32 = 22
	R_OP_TYPE_SHL    uint32 = 23
	R_OP_TYPE_SAL    uint32 = 24
	R_OP_TYPE_SAR    uint32 = 25
	R_OP_TYPE_OR     uint32 = 26
	R_OP_TYPE_AND    uint32 = 27
	R_OP_TYPE_XOR    uint32 = 28
	R_OP_TYPE_NOR    uint32 = 29
	R_OP_TYPE_NOT    uint32 = 30
	R_OP_TYPE_STORE  uint32 = 31 /* store from register to memory */
	R_OP_TYPE_LOAD   uint32 = 32 /* load from memory to register */
	R_OP_TYPE_LEA    uint32 = 33 /* TODO add ulea */
	R_OP_TYPE_LEAVE  uint32 = 34
	R_OP_TYPE_ROR    uint32 = 35
	R_OP_TYPE_ROL    uint32 = 36
	R_OP_TYPE_XCHG   uint32 = 37
	R_OP_TYPE_MOD    uint32 = 38
	R_OP_TYPE_SWITCH uint32 = 39
	R_OP_TYPE_CASE   uint32 = 40
	R_OP_TYPE_LENGTH uint32 = 41
	R_OP_TYPE_CAST   uint32 = 42
	R_OP_TYPE_NEW    uint32 = 43
	R_OP_TYPE_ABS    uint32 = 44
	R_OP_TYPE_CPL    uint32 = 45 /* complement */
	R_OP_TYPE_CRYPTO uint32 = 46
	R_OP_TYPE_SYNC   uint32 = 47
)

type OpDetail struct {
	OpType uint32
	Jump   uint64
	Next   uint64
}


type OpTypeLabel struct {
	opType uint32
	opName string
}
var opTypeLabels []OpTypeLabel = {
	{ R_OP_TYPE_IO, "io" },
	{ R_OP_TYPE_ACMP, "acmp" },
	{ R_OP_TYPE_ADD, "add" },
	{ R_OP_TYPE_SYNC, "sync" },
	{ R_OP_TYPE_AND, "and" },
	{ R_OP_TYPE_CALL, "call" },
	{ R_OP_TYPE_CCALL, "ccall" },
	{ R_OP_TYPE_CJMP, "cjmp" },
	{ R_OP_TYPE_MJMP, "mjmp" },
	{ R_OP_TYPE_CMP, "cmp" },
	{ R_OP_TYPE_ILL, "ill" },
	{ R_OP_TYPE_JMP, "jmp" },
	{ R_OP_TYPE_LEA, "lea" },
	{ R_OP_TYPE_LEAVE, "leave" },
	{ R_OP_TYPE_LOAD, "load" },
	{ R_OP_TYPE_NEW, "new" },
	{ R_OP_TYPE_MOD, "mod" },
	{ R_OP_TYPE_CMOV, "cmov" },
	{ R_OP_TYPE_MOV, "mov" },
	{ R_OP_TYPE_CAST, "cast" },
	{ R_OP_TYPE_MUL, "mul" },
	{ R_OP_TYPE_DIV, "div" },
	{ R_OP_TYPE_NOP, "nop" },
	{ R_OP_TYPE_NOT, "not" },
	{ R_OP_TYPE_NULL, "null" },
	{ R_OP_TYPE_OR, "or" },
	{ R_OP_TYPE_POP, "pop" },
	{ R_OP_TYPE_PUSH, "push" },
	{ R_OP_TYPE_RPUSH, "rpush" },
	{ R_OP_TYPE_REP, "rep" },
	{ R_OP_TYPE_RET, "ret" },
	{ R_OP_TYPE_CRET, "cret" },
	{ R_OP_TYPE_ROL, "rol" },
	{ R_OP_TYPE_ROR, "ror" },
	{ R_OP_TYPE_SAL, "sal" },
	{ R_OP_TYPE_SAR, "sar" },
	{ R_OP_TYPE_SHL, "shl" },
	{ R_OP_TYPE_SHR, "shr" },
	{ R_OP_TYPE_STORE, "store" },
	{ R_OP_TYPE_SUB, "sub" },
	{ R_OP_TYPE_SWI, "swi" },
	{ R_OP_TYPE_CSWI, "cswi" },
	{ R_OP_TYPE_SWITCH, "switch" },
	{ R_OP_TYPE_TRAP, "trap" },
	{ R_OP_TYPE_UCALL, "ucall" },
	{ R_OP_TYPE_RCALL, "rcall" },
	{ R_OP_TYPE_ICALL, "icall" },
	{ R_OP_TYPE_IRCALL, "ircall" },
	{ R_OP_TYPE_UCCALL, "uccall" },
	{ R_OP_TYPE_UCJMP, "ucjmp" },
	{ R_OP_TYPE_MCJMP, "mcjmp" },
	{ R_OP_TYPE_RCJMP, "rcjmp" },
	{ R_OP_TYPE_UJMP, "ujmp" },
	{ R_OP_TYPE_RJMP, "rjmp" },
	{ R_OP_TYPE_IJMP, "ijmp" },
	{ R_OP_TYPE_IRJMP, "irjmp" },
	{ R_OP_TYPE_UNK, "unk" },
	{ R_OP_TYPE_UPUSH, "upush" },
	{ R_OP_TYPE_RPUSH, "rpush" },
	{ R_OP_TYPE_XCHG, "xchg" },
	{ R_OP_TYPE_XOR, "xor" },
	{ R_OP_TYPE_CASE, "case" },
	{ R_OP_TYPE_CPL, "cpl" },
	{ R_OP_TYPE_CRYPTO, "crypto" },
	{ R_OP_TYPE_LENGTH, "lenght" },
	{ R_OP_TYPE_ABS, "abs" },
};

func opTypeToString(opType uint32)string {

}
func checkOpDetail(insn *cs.Instruction) *OpDetail {

	// var result = false
	var opType uint32 = R_OP_TYPE_NULL
	var jump uint64 = 0
	var next uint64 = 0

	id := insn.GetId()
	addr := insn.GetAddr()
	detail := insn.GetDetail().(*cs.Arm64Detail)
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
		next = addr + 4
	case cs.ARM64_INS_BLR:
		opType = R_OP_TYPE_RCALL
		next = addr + 4
	case cs.ARM64_INS_CBZ:
	case cs.ARM64_INS_CBNZ:
		opType = R_OP_TYPE_CJMP
		jump = uint64(detail.Operands[1].Value.Imm)
		next = addr + 4
	case cs.ARM64_INS_TBZ:
	case cs.ARM64_INS_TBNZ:
		opType = R_OP_TYPE_CJMP
		jump = uint64(detail.Operands[1].Value.Imm)
		next = addr + 4
	case cs.ARM64_INS_BR:
		opType = R_OP_TYPE_RJMP
	case cs.ARM64_INS_B:
		if detail.Operands[0].Value.Reg == cs.ARM64_REG_LR {
			opType = R_OP_TYPE_RET
		} else if detail.CC != cs.ARM64_CC_INVALID {
			jump = uint64(detail.Operands[0].Value.Imm)
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
		return &OpDetail{
			OpType: opType,
			Jump:   jump,
			Next:   next,
		}
	}
	return nil
}
