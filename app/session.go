package app

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"

	cs "github.com/er1cw00/btx.go/asm/cs"
	ks "github.com/er1cw00/btx.go/asm/ks"
	logger "github.com/er1cw00/btx.go/base/logger"
	emu "github.com/er1cw00/btx.go/emu"
	android "github.com/er1cw00/btx.go/emu/android"

	defla "github.com/er1cw00/defla.go/app/defla"
	core "github.com/er1cw00/defla.go/core"
	//egn "github.com/er1cw00/btx.go/engine"
)

var ErrorSessionExist = errors.New("Session Exist")
var ErrorSessionNotExist = errors.New("Session Not Exist")
var ErrorSessionLimited = errors.New("Max Session Limited")

const kMaxSession int = 5

var sessions map[string]*Session = make(map[string]*Session)

func CheckLimited() error {
	if len(sessions) >= kMaxSession {
		return ErrorSessionLimited
	}
	return nil
}
func Get(id string) (*Session, error) {
	sess, found := sessions[id]
	if found {
		return sess, nil
	}
	return nil, ErrorSessionNotExist
}

func Append(id string, session *Session) error {
	_, found := sessions[id]
	if found {
		return ErrorSessionExist
	}
	sessions[id] = session
	return nil
}

func Remove(id string) {
	delete(sessions, id)
}

type Function struct {
	defla.BBList
}

type Session struct {
	Id        string
	Functions map[uint64]*Function
	Capstone  *cs.Capstone
	Keystone  *ks.Keystone
	Emulator  emu.Emulator
	Module    emu.Module
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
		Id:        "",
		Functions: make(map[uint64]*Function),
		Emulator:  e,
		Capstone:  capstone,
		Keystone:  keystone,
		Module:    nil,
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
	return hex.EncodeToString(h.Sum(nil)), nil
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

func (session *Session) ParseFunction(name string, start, end uint64) (*Function, error) {
	var fn *Function = nil
	var found bool = false
	if _, found = session.Functions[start]; found {
		delete(session.Functions, start)
	}
	m := session.Module
	bbList, err := defla.NewBBList(session.Capstone, name, m.GetLoadBase()+start, start, end)
	if err != nil {
		return nil, err
	}

	fn = &Function{BBList: *bbList}
	session.Functions[start] = fn
	return fn, nil
}

func (session *Session) FindFunction(offset uint64) *Function {
	if fn, found := session.Functions[offset]; found {
		return fn
	}
	return nil
}
