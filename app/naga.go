package app

import (
	//	"unsafe"

	cs "github.com/er1cw00/btx.go/asm/cs"
	ks "github.com/er1cw00/btx.go/asm/ks"
	logger "github.com/er1cw00/btx.go/base/logger"
	emu "github.com/er1cw00/btx.go/emu"
	android "github.com/er1cw00/btx.go/emu/android"
	skiplist "github.com/huandu/skiplist"
	//egn "github.com/er1cw00/btx.go/engine"
)

type NagaLoader struct {
	capstone *cs.Capstone
	keystone *ks.Keystone
	emulator emu.Emulator
}

func NewNagaLoader() (*NagaLoader, error) {
	var err error = nil
	var e emu.Emulator = nil

	var capstone *cs.Capstone = nil
	var keystone *ks.Keystone = nil

	if capstone, err = cs.NewCapstone(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM); err != nil {
		logger.Errorf("create capstone for arm64 fail, error: %v", err)
		return nil, err
	}
	if keystone, err = ks.NewKeystone(ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN); err != nil {
		logger.Errorf("create keystone for arm64 fail, error: %v", err)
		return nil, err
	}

	if e, err = android.NewAndroidEmulator("xloader", emu.ARCH_ARM64); err != nil {
		logger.Errorf("create android arm64 emulator fail, error: %v", err)
		return nil, err
	}

	nagaLoader := &NagaLoader{
		emulator: e,
		capstone: capstone,
		keystone: keystone,
	}
	return nagaLoader, nil

}

func (naga *NagaLoader) Close() {
	if naga.keystone != nil {
		naga.keystone.Close()
		naga.keystone = nil
	}
	if naga.capstone != nil {
		naga.capstone.Close()
		naga.capstone = nil
	}
	if naga.emulator != nil {
		//naga.emulator.Close()
		naga.emulator = nil
	}
}

func (naga *NagaLoader) Run(rootfsPath, xloaderPath string, funcs []FuncModel) error {
	var m emu.Module = nil
	var err error = nil

	fs := naga.emulator.GetFileSystem()
	fs.SetRootfsPath(rootfsPath)
	loader := naga.emulator.GetLoader()
	loader.SetInitFuncFilter(func(loader emu.Loader, module emu.Module) bool {
		return false
	})
	if m, err = loader.LoadLibrary(xloaderPath); err != nil {
		logger.Errorf("load naga's xloader.so fail, error: %v", err)
		return err
	}
	logger.Debugf("load xloader.so at 0x%x", m.GetMapBase())
	for i, fn := range funcs {
		logger.Debugf("  func(%d), name(%s), start(0x%0x), end(0x%x)", i, fn.Name, fn.Start, fn.End)
	}
	fn := funcs[12]

	_ = ParseFunction(naga.capstone, fn.Name, m.GetLoadBase()+fn.Start, fn.Start, fn.End)
	return nil
}

func ParseFunction(capstone *cs.Capstone, name string, code, start, end uint64) error {

	insn, err := capstone.Disassemble(uintptr(code), int(end-start+4), start)
	if err != nil {
		panic(err)
	}
	//g := NewBBG(name, base, size, insn)
	//addrList = append(addrList, base)
	bbList := skiplist.New(skiplist.Uint64Asc)
	jumpMap := make(map[uint64]bool, 0)
	var s uint64 = start
	for i := 0; i < len(insn); i += 1 {
		addr := insn[i].GetAddr()
		logger.Debugf("    %d:  0x%x  %s %s,      jump:%v,  call:%v,  ret:%v,  ir:%v",
			i,
			addr,
			insn[i].GetMnemonic(),
			insn[i].GetOptStr(),
			insn[i].CheckGroup(cs.CS_GRP_JUMP),
			insn[i].CheckGroup(cs.CS_GRP_CALL),
			insn[i].CheckGroup(cs.CS_GRP_RET),
			insn[i].CheckGroup(cs.CS_GRP_BRANCH_RELATIVE))

		if (insn[i].CheckGroup(cs.CS_GRP_JUMP) || insn[i].CheckGroup(cs.CS_GRP_RET)) &&
			!insn[i].CheckGroup(cs.CS_GRP_CALL) {
			if ext := checkOpExtDetail(insn[i]); ext != nil {
				if ext.OpType == R_OP_TYPE_RET ||
					ext.OpType == R_OP_TYPE_JMP ||
					ext.OpType == R_OP_TYPE_CJMP ||
					ext.OpType == R_OP_TYPE_RJMP ||
					ext.OpType == R_OP_TYPE_MCJMP {

					logger.Debugf("         Type:%s, block[0x%x - 0x%x], Jump:0x%x, Fail:0x%x",
						opTypeToString(ext.OpType),
						s, addr,
						ext.Jump, ext.Fail)

					next := addr + 4
					bb := NewBB(s, addr)
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
				bb := NewBB(k, end)
				bbList.Set(k, bb)
				logger.Debugf("          elem is empty, new BB: [0x%0x - 0x%x]", bb.Start, bb.End)
				continue
			}
			prev := e.Prev()
			if prev == nil {
				logger.Fatalf("          not bb contain 0x%x", k)
				continue
			}
			if prevBB := prev.Value.(*BB); prevBB != nil {
				bb := NewBB(k, prevBB.End)
				prevBB.End = k - 4
				bbList.Set(k, bb)
				logger.Debugf("          match BB: [0x%0x - 0x%x], new BB: [0x%0x - 0x%x]", prevBB.Start, prevBB.End, bb.Start, bb.End)
			}

		}

	}

	for elem := bbList.Front(); elem != nil; elem = elem.Next() {
		bb := elem.Value.(*BB)
		logger.Debugf("BB =>  [0x%0x - 0x%x] ", elem.Key().(uint64), bb.End)
	}
	return nil
}

func Run(rootfsPath, xloaderPath, funcPath string) error {
	var err error = nil
	var naga *NagaLoader = nil
	var funcs []FuncModel = nil
	if funcs, err = UnmarshalFunctions(funcPath); err != nil {
		logger.Errorf("load defla func list fail, error: %v", err)
		return err
	}

	if naga, err = NewNagaLoader(); err != nil {
		return err
	}
	naga.Run(rootfsPath, xloaderPath, funcs)

	naga.Close()
	return nil
}
