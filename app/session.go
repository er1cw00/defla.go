package app

import (
	"crypto/md5"
	"io"
	"os"

	cs "github.com/er1cw00/btx.go/asm/cs"
	ks "github.com/er1cw00/btx.go/asm/ks"
	logger "github.com/er1cw00/btx.go/base/logger"
	emu "github.com/er1cw00/btx.go/emu"
	android "github.com/er1cw00/btx.go/emu/android"

	core "github.com/er1cw00/defla.go/core"
	//defla "github.com/er1cw00/defla.go/core/defla"
	//egn "github.com/er1cw00/btx.go/engine"
)

type Session struct {
	Id       string
	Capstone *cs.Capstone
	Keystone *ks.Keystone
	Emulator emu.Emulator
	Module   emu.Module
}

func NewSession() (*Session, error) {
	var err error = nil
	var e emu.Emulator = nil
	var fs emu.FileSystem = nil

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

	fs = e.GetFileSystem()
	fs.SetRootfsPath(core.Config.RootfsPath)

	session := &Session{
		Id:       "",
		Emulator: e,
		Capstone: capstone,
		Keystone: keystone,
		Module:   nil,
	}
	return session, nil

}

func (session *Session) Close() {
	if session.Keystone != nil {
		session.Keystone.Close()
		session.Keystone = nil
	}
	if session.Capstone != nil {
		session.Capstone.Close()
		session.Capstone = nil
	}
	if session.Emulator != nil {
		//session.emulator.Close()
		session.Emulator = nil
	}
}

func md5Sum(libPath string) (string, error) {
	f, err := os.Open(libPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {

		return "", err
	}
	return string(h.Sum(nil)), nil
}
func (session *Session) Load(libPath string) error {
	var err error = nil
	loader := session.Emulator.GetLoader()
	loader.SetInitFuncFilter(func(loader emu.Loader, module emu.Module) bool {
		return false
	})
	if session.Module, err = loader.LoadLibrary(libPath); err != nil {
		logger.Errorf("load [%s] fail, error: %v", libPath, err)
		return err
	}
	if session.Id, err = md5Sum(libPath); err != nil {
		logger.Errorf("md5sum for [%s] fail, error: %v", libPath, err)
	}
	return err
}
