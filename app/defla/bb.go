package defla

import (
	"errors"
	"fmt"
	"strings"

	dot "github.com/emicklei/dot"
	cs "github.com/er1cw00/btx.go/asm/cs"
	logger "github.com/er1cw00/btx.go/base/logger"
	skiplist "github.com/huandu/skiplist"
)

var ErrorExistBB = errors.New("BB is exist")

const BB_INVALID uint64 = 0
const (
	BB_TYPE_UNK  = 0
	BB_TYPE_USED = 1
	BB_TYPE_OBF  = 2
)

type BB struct {
	Type  uint32
	Start uint64
	End   uint64
	Cond  uint32
	Next  uint64
	Left  uint64
	Right uint64
}

func newBB(start, end uint64) *BB {
	bb := &BB{
		Type:  BB_TYPE_UNK,
		Start: start,
		End:   end,
		Cond:  R_COND_INV,
		Next:  BB_INVALID,
		Left:  BB_INVALID,
		Right: BB_INVALID,
	}
	return bb
}
func bbTypeLabel(typ uint32) string {
	if typ == BB_TYPE_USED {
		return "used"
	} else if typ == BB_TYPE_OBF {
		return "obfuscated"
	}
	return "unknown"
}

type BBList struct {
	Name     string
	Base     uint64
	Size     int
	Capstone *cs.Capstone
	Insn     []*Op
	List     *skiplist.SkipList
}

func NewBBList(capstone *cs.Capstone, name string, code, start, end uint64) (*BBList, error) {
	size := int(end - start + 4)
	insn, err := capstone.Disassemble(uintptr(code), size, start)
	if err != nil {
		return nil, err
	}
	skipList, opList, err := parseFunction(insn, name, start, end)
	if err != nil {
		return nil, err
	}
	bblist := &BBList{
		Capstone: capstone,
		Name:     name,
		Base:     start,
		Size:     size,
		Insn:     opList,
		List:     skipList,
	}
	for elem := bblist.List.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		bb.Type = bblist.checkBBType(bb)
	}
	return bblist, nil
}

func (bblist *BBList) Draw() string {
	g := dot.NewGraph(dot.Directed)
	g.AttributesMap.Attr("bgcolor", "transparent")
	g.NodeInitializer(func(n dot.Node) {
		n.Attr("shape", "box")
		n.Attr("width", "4")
		n.Attr("fontname", "arial")
		n.Attr("style", "filled")
		n.Attr("nojustify", "true")
		n.Attr("outputorder", "edgesfirst")
	})
	g.EdgeInitializer(func(e dot.Edge) {

	})

	var prev *dot.Node = nil
	for elem := bblist.List.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		node := bblist.createDotNode(g, bb)
		if prev != nil {
			g.Edge(*prev, node)
		}
		prev = &node
		logger.Debugf("BB => [0x%0x - 0x%x] Cond:%s, Next:0x%x, Left:0x%x, Right:0x%x",
			elem.Key().(uint64),
			bb.End,
			opCondToString(bb.Cond),
			bb.Next,
			bb.Left,
			bb.Right)
	}
	return g.String()
}

func (bblist *BBList) GetInstructions(start, end uint64) []*Op {
	//	size := int(end - start + 4)
	insn := make([]*Op, 0)
	for off := start; off <= end; off += 4 {
		idx := int(off-bblist.Base) / 4
		insn = append(insn, bblist.Insn[idx])
	}
	return insn
}

func (bblist *BBList) checkBBType(bb *BB) uint32 {
	opList := bblist.GetInstructions(bb.Start, bb.End)
	count := len(opList)

	var typ uint32 = BB_TYPE_UNK
	for i := 0; i < count; i++ {
		op := opList[i]
		opType := op.OpType & R_OP_TYPE_MASK
		if opType == R_OP_TYPE_SWI ||
			opType == R_OP_TYPE_STORE ||
			opType == R_OP_TYPE_LOAD ||
			opType == R_OP_TYPE_CALL ||
			opType == R_OP_TYPE_UCALL ||
			opType == R_OP_TYPE_RET {
			//logger.Debugf("   >>> opType: %s ; \"0x%x %s %s\"", opTypeToString(opType), op.GetAddr(), op.GetMnemonic(), op.GetOptStr())
			typ = BB_TYPE_USED
			break
		}
	}
	logger.Debugf("BB: [0x%x - 0x%x]  Type: %s", bb.Start, bb.End, bbTypeLabel(typ))
	return typ
}
func (bblist *BBList) String() string {
	var sb strings.Builder
	sb.WriteString("[\n")
	for elem := bblist.List.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		insn := opToString(bblist.GetInstructions(bb.Start, bb.End))
		fmt.Fprintf(&sb, "{\"type\": \"%s\", \"offset\": \"0x%x\", \"insn\": %s}",
			bbTypeLabel(bb.Type),
			bb.Start,
			insn)

		if elem != bblist.List.Back() {
			sb.WriteString(",\n")
		}
	}
	sb.WriteString("]\n")
	return sb.String()
}

func (bblist *BBList) createDotNode(g *dot.Graph, bb *BB) dot.Node {
	label := fmt.Sprintf("0x%x", bb.Start)
	node := g.Node(label)
	insn := bblist.GetInstructions(bb.Start, bb.End)
	msg := label + "\n"
	for i := 0; i < len(insn); i++ {
		ins := insn[i]
		msg += fmt.Sprintf("0x%x %s %s\\l", ins.GetAddr(), ins.GetMnemonic(), ins.GetOptStr())
	}
	if bb.Type == BB_TYPE_OBF {
		node.Attr("fillcolor ", "#b1dc56")
	} else if bb.Type == BB_TYPE_USED {
		node.Attr("fillcolor ", "#41abe9")
	} else {
		node.Attr("fillcolor ", "#878787")
	}
	node.Attr("label", dot.Literal("\""+msg+"\""))
	return node
}

func opToString(insn []*Op) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, ins := range insn {
		//code := ins.GetBytes()
		fmt.Fprintf(&sb, "\"0x%x %s %s\"", ins.GetAddr(), ins.GetMnemonic(), ins.GetOptStr())
		if i < len(insn)-1 {
			sb.WriteString(",\n")
		}
	}
	sb.WriteString("]")
	return sb.String()
}

func parseFunction(insn []*cs.Instruction, name string, start, end uint64) (*skiplist.SkipList, []*Op, error) {

	bblist := skiplist.New(skiplist.Uint64Asc)
	opList := make([]*Op, 0)
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

		// if (insn[i].CheckGroup(cs.CS_GRP_JUMP) || insn[i].CheckGroup(cs.CS_GRP_RET)) &&
		// 	!insn[i].CheckGroup(cs.CS_GRP_CALL) {
		op := newOp(insn[i])
		if op == nil {
			panic(op)
		}

		opList = append(opList, op)

		// if insn[i].CheckGroup(cs.CS_GRP_JUMP) || insn[i].CheckGroup(cs.CS_GRP_RET) {
		// 	logger.Debugf("         %s Type:0x%x,%s, block[0x%x - 0x%x], CC: %s, Jump:0x%x, Fail:0x%x ",
		// 		op.String(),
		// 		op.OpType,
		// 		opTypeToString(op.OpType),
		// 		s, addr,
		// 		opCondToString(op.OpCond),
		// 		op.Jump, op.Fail)
		// }
		if op.OpType == R_OP_TYPE_RET ||
			op.OpType == R_OP_TYPE_JMP ||
			op.OpType == R_OP_TYPE_CJMP ||
			op.OpType == R_OP_TYPE_RJMP ||
			op.OpType == R_OP_TYPE_MCJMP {

			// logger.Debugf("        >>>> Type:0x%x,%s, block[0x%x - 0x%x], CC: %s, Jump:0x%x, Fail:0x%x",
			// 	op.OpType,
			// 	opTypeToString(op.OpType),
			// 	s, addr,
			// 	opCondToString(op.OpCond),
			// 	op.Jump, op.Fail)

			next := addr + 4
			bb := newBB(s, addr)
			bb.Cond = op.OpCond
			if op.OpCond == R_COND_INV {
				bb.Next = op.Jump
			} else {
				bb.Left = op.Jump
				bb.Right = op.Fail
			}
			bblist.Set(s, bb)
			if op.Jump != 0 {
				if _, ok := bblist.GetValue(op.Jump); !ok {
					jumpMap[op.Jump] = true
				}
			} else if op.OpType != R_OP_TYPE_RET {
				panic(" jump == 0")
			}
			s = next
		}

	}
	for k, _ := range jumpMap {
		if bblist.Get(k) == nil {
			logger.Debugf("jump not found: 0x%x", k)
			e := bblist.Find(k)
			if e == nil {
				prev := bblist.Back()
				if prev == nil {
					logger.Fatalf("          not bb in list?")
				}
				prevBB := prev.Value.(*BB)
				prevBB.Next = k
				prevBB.Cond = R_COND_INV
				bb := newBB(k, end)
				bblist.Set(k, bb)
				//logger.Debugf("          elem is empty, new BB: [0x%0x - 0x%x]", bb.Start, bb.End)
				continue
			} else {
				prev := e.Prev()
				if prev == nil {
					logger.Fatalf("          not bb contain 0x%x", k)
					continue
				}
				prevBB := prev.Value.(*BB)
				bb := newBB(k, prevBB.End)
				bb.Cond = prevBB.Cond
				bb.Next = prevBB.Next
				bb.Left = prevBB.Left
				bb.Right = prevBB.Right
				prevBB.Cond = R_COND_INV
				prevBB.Next = k
				prevBB.Left = BB_INVALID
				prevBB.Right = BB_INVALID
				prevBB.End = k - 4
				bblist.Set(k, bb)
				//logger.Debugf("          match BB: [0x%0x - 0x%x], new BB: [0x%0x - 0x%x]", prevBB.Start, prevBB.End, bb.Start, bb.End)
			}
		}
	}

	return bblist, opList, nil
}
