package defla

import (
	"errors"
	cs "github.com/er1cw00/btx.go/asm/cs"
	logger "github.com/er1cw00/btx.go/base/logger"
	skiplist "github.com/huandu/skiplist"
)

var ErrorExistBB = errors.New("BB is exist")

type BB struct {
	Start uint64
	End   uint64
	Insn  []*cs.Instruction
	Cond  uint32
	Next  uint64
	Left  uint64
	Right uint64
}

const BB_INVALID uint64 = 0

type BBGraph struct {
	name   string
	base   uint64
	size   uint64
	insn   []*cs.Instruction
	rootBB uint64
	mapBB  map[uint64]*BB
	listBB []uint64
}

func NewBBG(name string, base, size uint64, insn []*cs.Instruction) *BBGraph {
	bbg := &BBGraph{
		name:   name,
		base:   base,
		size:   size,
		insn:   insn,
		rootBB: BB_INVALID,
		mapBB:  make(map[uint64]*BB),
		listBB: make([]uint64, 0),
	}
	return bbg
}

func NewBB(start, end uint64) *BB {
	bb := &BB{
		Start: start,
		End:   end,
		Insn:  nil,
		Cond:  R_COND_INV,
		Next:  BB_INVALID,
		Left:  BB_INVALID,
		Right: BB_INVALID,
	}

	return bb
}

func ParseFunction(capstone *cs.Capstone, name string, code, start, end uint64) error {

	insn, err := capstone.Disassemble(uintptr(code), int(end-start+4), start)
	if err != nil {
		panic(err)
	}
	//g := NewBBG(name, base, size, insn)

	bbList := skiplist.New(skiplist.Uint64Asc)
	jumpMap := make(map[uint64]bool, 0)
	var s uint64 = start
	for i := 0; i < len(insn); i += 1 {
		addr := insn[i].GetAddr()
		detail := insn[i].GetDetail().(*cs.Arm64Detail)
		logger.Debugf("    %d:  0x%x  %-4s %24s;      jump:%5v, call:%5v, ret:%5v, ir:%5v, cc:%03x",
			i,
			addr,
			insn[i].GetMnemonic(),
			insn[i].GetOptStr(),
			insn[i].CheckGroup(cs.CS_GRP_JUMP),
			insn[i].CheckGroup(cs.CS_GRP_CALL),
			insn[i].CheckGroup(cs.CS_GRP_RET),
			insn[i].CheckGroup(cs.CS_GRP_BRANCH_RELATIVE),
			detail.CC)

		if (insn[i].CheckGroup(cs.CS_GRP_JUMP) || insn[i].CheckGroup(cs.CS_GRP_RET)) &&
			!insn[i].CheckGroup(cs.CS_GRP_CALL) {
			if ext := checkOpExtDetail(insn[i]); ext != nil {
				if ext.OpType == R_OP_TYPE_RET ||
					ext.OpType == R_OP_TYPE_JMP ||
					ext.OpType == R_OP_TYPE_CJMP ||
					ext.OpType == R_OP_TYPE_RJMP ||
					ext.OpType == R_OP_TYPE_MCJMP {

					logger.Debugf("         Type:%s, block[0x%x - 0x%x], CC: %s, Jump:0x%x, Fail:0x%x",
						opTypeToString(ext.OpType),
						s, addr,
						opCondToString(ext.OpCond),
						ext.Jump, ext.Fail)

					next := addr + 4
					bb := NewBB(s, addr)
					bb.Cond = ext.OpCond
					if ext.OpCond == R_COND_INV {
						bb.Next = ext.Jump
					} else {
						bb.Left = ext.Jump
						bb.Right = ext.Fail
					}
					bbList.Set(s, bb)
					if ext.Jump != 0 {
						if _, ok := bbList.GetValue(ext.Jump); !ok {
							jumpMap[ext.Jump] = true
						}
					} else if ext.OpType != R_OP_TYPE_RET {
						panic(" jump == 0")
					}
					s = next
				}
			}
		}
	}
	for k, _ := range jumpMap {
		if bbList.Get(k) == nil {
			logger.Debugf("jump not found: 0x%x", k)
			e := bbList.Find(k)
			if e == nil {
				prev := bbList.Back()
				if prev == nil {
					logger.Fatalf("          not bb in list?")
				}
				prevBB := prev.Value.(*BB)
				prevBB.Next = k
				prevBB.Cond = R_COND_INV
				bb := NewBB(k, end)
				bbList.Set(k, bb)
				logger.Debugf("          elem is empty, new BB: [0x%0x - 0x%x]", bb.Start, bb.End)
				continue
			} else {
				prev := e.Prev()
				if prev == nil {
					logger.Fatalf("          not bb contain 0x%x", k)
					continue
				}
				prevBB := prev.Value.(*BB)
				bb := NewBB(k, prevBB.End)
				bb.Cond = prevBB.Cond
				bb.Next = prevBB.Next
				bb.Left = prevBB.Left
				bb.Right = prevBB.Right
				prevBB.Cond = R_COND_INV
				prevBB.Next = k
				prevBB.Left = BB_INVALID
				prevBB.Right = BB_INVALID
				prevBB.End = k - 4
				bbList.Set(k, bb)
				logger.Debugf("          match BB: [0x%0x - 0x%x], new BB: [0x%0x - 0x%x]", prevBB.Start, prevBB.End, bb.Start, bb.End)

			}
		}
	}

	for elem := bbList.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		logger.Debugf("BB =>  [0x%0x - 0x%x]  Cond:%s, Next:0x%x, Left:0x%x, Right:0x%x",
			elem.Key().(uint64),
			bb.End,
			opCondToString(bb.Cond),
			bb.Next,
			bb.Left,
			bb.Right)
	}
	return nil
}
