package defla

import (
//"fmt"
//	cs "github.com/er1cw00/btx.go/asm/cs"
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

var opCondLabels []string = []string{
	"inv", "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
}

func opCondToString(opCond uint32) string {
	if opCond >= 0 && opCond <= R_COND_NV {
		return opCondLabels[int(opCond)]
	}
	return "inv"
}

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

type OpTypeLabel struct {
	opType uint32
	opName string
}

var opTypeLabels []OpTypeLabel = []OpTypeLabel{
	OpTypeLabel{R_OP_TYPE_IO, "io"},
	OpTypeLabel{R_OP_TYPE_ACMP, "acmp"},
	OpTypeLabel{R_OP_TYPE_ADD, "add"},
	OpTypeLabel{R_OP_TYPE_SYNC, "sync"},
	OpTypeLabel{R_OP_TYPE_AND, "and"},
	OpTypeLabel{R_OP_TYPE_CALL, "call"},
	OpTypeLabel{R_OP_TYPE_CCALL, "ccall"},
	OpTypeLabel{R_OP_TYPE_CJMP, "cjmp"},
	OpTypeLabel{R_OP_TYPE_MJMP, "mjmp"},
	OpTypeLabel{R_OP_TYPE_CMP, "cmp"},
	OpTypeLabel{R_OP_TYPE_ILL, "ill"},
	OpTypeLabel{R_OP_TYPE_JMP, "jmp"},
	OpTypeLabel{R_OP_TYPE_LEA, "lea"},
	OpTypeLabel{R_OP_TYPE_LEAVE, "leave"},
	OpTypeLabel{R_OP_TYPE_LOAD, "load"},
	OpTypeLabel{R_OP_TYPE_NEW, "new"},
	OpTypeLabel{R_OP_TYPE_MOD, "mod"},
	OpTypeLabel{R_OP_TYPE_CMOV, "cmov"},
	OpTypeLabel{R_OP_TYPE_MOV, "mov"},
	OpTypeLabel{R_OP_TYPE_CAST, "cast"},
	OpTypeLabel{R_OP_TYPE_MUL, "mul"},
	OpTypeLabel{R_OP_TYPE_DIV, "div"},
	OpTypeLabel{R_OP_TYPE_NOP, "nop"},
	OpTypeLabel{R_OP_TYPE_NOT, "not"},
	OpTypeLabel{R_OP_TYPE_NULL, "null"},
	OpTypeLabel{R_OP_TYPE_OR, "or"},
	OpTypeLabel{R_OP_TYPE_POP, "pop"},
	OpTypeLabel{R_OP_TYPE_PUSH, "push"},
	OpTypeLabel{R_OP_TYPE_RPUSH, "rpush"},
	OpTypeLabel{R_OP_TYPE_REP, "rep"},
	OpTypeLabel{R_OP_TYPE_RET, "ret"},
	OpTypeLabel{R_OP_TYPE_CRET, "cret"},
	OpTypeLabel{R_OP_TYPE_ROL, "rol"},
	OpTypeLabel{R_OP_TYPE_ROR, "ror"},
	OpTypeLabel{R_OP_TYPE_SAL, "sal"},
	OpTypeLabel{R_OP_TYPE_SAR, "sar"},
	OpTypeLabel{R_OP_TYPE_SHL, "shl"},
	OpTypeLabel{R_OP_TYPE_SHR, "shr"},
	OpTypeLabel{R_OP_TYPE_STORE, "store"},
	OpTypeLabel{R_OP_TYPE_SUB, "sub"},
	OpTypeLabel{R_OP_TYPE_SWI, "swi"},
	OpTypeLabel{R_OP_TYPE_CSWI, "cswi"},
	OpTypeLabel{R_OP_TYPE_SWITCH, "switch"},
	OpTypeLabel{R_OP_TYPE_TRAP, "trap"},
	OpTypeLabel{R_OP_TYPE_UCALL, "ucall"},
	OpTypeLabel{R_OP_TYPE_RCALL, "rcall"},
	OpTypeLabel{R_OP_TYPE_ICALL, "icall"},
	OpTypeLabel{R_OP_TYPE_IRCALL, "ircall"},
	OpTypeLabel{R_OP_TYPE_UCCALL, "uccall"},
	OpTypeLabel{R_OP_TYPE_UCJMP, "ucjmp"},
	OpTypeLabel{R_OP_TYPE_MCJMP, "mcjmp"},
	OpTypeLabel{R_OP_TYPE_RCJMP, "rcjmp"},
	OpTypeLabel{R_OP_TYPE_UJMP, "ujmp"},
	OpTypeLabel{R_OP_TYPE_RJMP, "rjmp"},
	OpTypeLabel{R_OP_TYPE_IJMP, "ijmp"},
	OpTypeLabel{R_OP_TYPE_IRJMP, "irjmp"},
	OpTypeLabel{R_OP_TYPE_UNK, "unk"},
	OpTypeLabel{R_OP_TYPE_UPUSH, "upush"},
	OpTypeLabel{R_OP_TYPE_RPUSH, "rpush"},
	OpTypeLabel{R_OP_TYPE_XCHG, "xchg"},
	OpTypeLabel{R_OP_TYPE_XOR, "xor"},
	OpTypeLabel{R_OP_TYPE_CASE, "case"},
	OpTypeLabel{R_OP_TYPE_CPL, "cpl"},
	OpTypeLabel{R_OP_TYPE_CRYPTO, "crypto"},
	OpTypeLabel{R_OP_TYPE_LENGTH, "lenght"},
	OpTypeLabel{R_OP_TYPE_ABS, "abs"},
}

func opTypeToString(opType uint32) string {
	for _, label := range opTypeLabels {
		if label.opType == opType {
			return label.opName
		}
	}
	return "undefined"
}

type OpExtDetail struct {
	OpType uint32
	OpCond uint32
	Jump   uint64
	Fail   uint64
}
