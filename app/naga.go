package app

import (
	//	"unsafe"

	cs "github.com/er1cw00/btx.go/asm/cs"
	ks "github.com/er1cw00/btx.go/asm/ks"
	logger "github.com/er1cw00/btx.go/base/logger"
	emu "github.com/er1cw00/btx.go/emu"
	android "github.com/er1cw00/btx.go/emu/android"
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

	_ = ParseFunction(naga.capstone, fn.Name, m.GetLoadBase()+fn.Start, fn.End-fn.Start+4, fn.Start)
	return nil
}

func ParseFunction(capstone *cs.Capstone, name string, start, size, base uint64) error {

	insn, err := capstone.Disassemble(uintptr(start), int(size), base)
	if err != nil {
		panic(err)
	}
	//g := NewBBG(name, base, size, insn)
	for i := 0; i < len(insn); i += 1 {
		logger.Debugf("    %d:  0x%x  %s %s, jump:%v, call:%v, ret:%v,br:%v",
			i,
			insn[i].GetAddr(),
			insn[i].GetMnemonic(),
			insn[i].GetOptStr(),
			insn[i].CheckGroup(cs.CS_GRP_JUMP),
			insn[i].CheckGroup(cs.CS_GRP_CALL),
			insn[i].CheckGroup(cs.CS_GRP_RET),
			insn[i].CheckGroup(cs.CS_GRP_BRANCH_RELATIVE))
		d := checkOpDetail(insn[i])
		if d != nil {
			logger.Debugf("         0x%x, 0x%x 0x%x", d.OpType, d.Jump, d.Next)
		}
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
