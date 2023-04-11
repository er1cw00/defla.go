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
	name     string
	base     uint64
	size     int
	capstone *cs.Capstone
	insn     []*cs.Instruction
	list     *skiplist.SkipList
}

func NewBBList(capstone *cs.Capstone, name string, code, start, end uint64) (*BBList, error) {
	size := int(end - start + 4)
	insn, err := capstone.Disassemble(uintptr(code), size, start)
	if err != nil {
		return nil, err
	}
	skipList, err := parseFunction(insn, name, start, end)
	if err != nil {
		return nil, err
	}
	bblist := &BBList{
		capstone: capstone,
		name:     name,
		base:     start,
		size:     size,
		insn:     insn,
		list:     skipList,
	}
	return bblist, nil
}

func parseFunction(insn []*cs.Instruction, name string, start, end uint64) (*skiplist.SkipList, error) {

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
					bb := newBB(s, addr)
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
				bb := newBB(k, end)
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
				bbList.Set(k, bb)
				logger.Debugf("          match BB: [0x%0x - 0x%x], new BB: [0x%0x - 0x%x]", prevBB.Start, prevBB.End, bb.Start, bb.End)
			}
		}
	}

	//trunDotToImage(ss, "svg", )
	return bbList, nil
}

func createDotNode(g *dot.Graph, bb *BB) dot.Node {
	label := fmt.Sprintf("0x%x", bb.Start)
	return g.Node(label)
}

func insnToString(insn []*cs.Instruction) string {
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
func (bbList *BBList) Draw() string {
	g := dot.NewGraph(dot.Directed)
	g.AttributesMap.Attr("bgcolor", "transparent")
	g.NodeInitializer(func(n dot.Node) {
		n.Attr("shape", "box")
		n.Attr("fontname", "arial")
		n.Attr("style", "filled")
		n.Attr("nojustify", "true")
		n.Attr("outputorder", "edgesfirst")
	})
	g.EdgeInitializer(func(e dot.Edge) {

	})

	var prev *dot.Node = nil
	for elem := bbList.list.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		node := createDotNode(g, bb)
		if prev != nil {
			g.Edge(*prev, node)
		}
		prev = &node
		logger.Debugf("BB =>  [0x%0x - 0x%x]  Cond:%s, Next:0x%x, Left:0x%x, Right:0x%x",
			elem.Key().(uint64),
			bb.End,
			opCondToString(bb.Cond),
			bb.Next,
			bb.Left,
			bb.Right)
	}
	return g.String()
}

func (bblist *BBList) GetInstructions(start, end uint64) []*cs.Instruction {
	//	size := int(end - start + 4)
	insn := make([]*cs.Instruction, 0)
	for off := start; off <= end; off += 4 {
		idx := int(off-bblist.base) / 4
		fmt.Printf("off: 0x%x; idx: %d\n", off, idx)
		insn = append(insn, bblist.insn[idx])
	}
	return insn
}

func (bblist *BBList) String() string {
	var sb strings.Builder
	sb.WriteString("[\n")
	for elem := bblist.list.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		insn := insnToString(bblist.GetInstructions(bb.Start, bb.End))
		fmt.Fprintf(&sb, "{\"type\": \"%s\", \"offset\": \"0x%x\", \"insn\": %s}",
			bbTypeLabel(bb.Type),
			bb.Start,
			insn)

		if elem != bblist.list.Back() {
			sb.WriteString(",\n")
		}
	}
	sb.WriteString("]\n")
	return sb.String()
}

/*
var dotExec = "/usr/local/bin/dot"

func runDotToImage(outfname string, format string, t []byte) (string, error) {
	if dotExec == "" {
		dot, err := exec.LookPath("dot")
		if err != nil {
			logger.Fatalf("unable to find program 'dot', please install it or check your PATH\n")
		}
		dotExec = dot
	}

	var img string
	if outfname == "" {
		img = filepath.Join(os.TempDir(), fmt.Sprintf("go-callvis_export.%s", format))
	} else {
		img = fmt.Sprintf("%s.%s", outfname, format)
	}
	cmd := exec.Command(dotExec, fmt.Sprintf("-T%s", format), "-o", img)
	cmd.Stdin = bytes.NewReader(dot)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("command '%v': %v\n%v", cmd, err, stderr.String())
	}
	return img, nil
}
*/