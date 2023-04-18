package main

import (
	"flag"
	"fmt"
	"os"

	base "github.com/er1cw00/btx.go/base"
	logger "github.com/er1cw00/btx.go/base/logger"
	egn "github.com/er1cw00/btx.go/engine"

	app "github.com/er1cw00/defla.go/app"
	core "github.com/er1cw00/defla.go/core"
	model "github.com/er1cw00/defla.go/core/model"
)

var rootfsPath string = ""
var modulePath string = ""
var funcPath string = ""
var help bool = false

func usage() {
	fmt.Printf("Usage: naga.go [-ch]\r\n")
	fmt.Printf("           -h print this message\r\n")
	fmt.Printf("           -r rootfs path\r\n")
	fmt.Printf("           -i module path\r\n")
	fmt.Printf("           -f func list path\r\n")
}

func init() {
	flag.BoolVar(&help, "h", false, "print help")
	flag.StringVar(&rootfsPath, "r", "", "rootfs path")
	flag.StringVar(&modulePath, "i", "", "library path")
	flag.StringVar(&funcPath, "f", "", "func list json path")
	flag.Usage = usage
}

func Example(modulePath, funcPath string) error {
	var err error = nil
	var session *app.Session = nil
	var fn *app.Function = nil
	var funcs []model.FuncModel = nil
	if funcs, err = model.UnmarshalFuncModel(funcPath); err != nil {
		logger.Errorf("load defla func list fail, error: %v", err)
		return err
	}
	if session, err = app.NewSession(); err != nil {
		logger.Errorf("create session fail, error: %v", err)
		return err
	}
	if err = session.Load(modulePath); err != nil {
		logger.Errorf("load module [%s] fail, error: %v", modulePath, err)
		return err
	}
	m := session.Module
	logger.Debugf("load %s at 0x%x, %s", m.GetName(), m.GetMapBase(), session.Id)

	for i, fn := range funcs {
		logger.Debugf("func(%d), name(%s), start(0x%0x), end(0x%x)", i, fn.Name, fn.Start, fn.End)
	}

	f := funcs[12]
	fn, err = session.ParseFunction(f.Name, f.Start, f.End)
	if err != nil {
		logger.Fatalf("parse function to basic block fail, err: %v", err)
	}
	fmt.Printf("%s\n", fn.Draw())
	//_ = defla.ParseFunction(naga.capstone, fn.Name, m.GetLoadBase()+fn.Start, fn.Start, fn.End)

	session.Close()
	return nil
}

func main() {
	flag.Parse()
	if help {
		usage()
		os.Exit(0)
	}
	core.Config = &core.DeflaConfig{
		RootfsPath: rootfsPath,
	}
	if err := base.Start(); err != nil {
		panic(err)
	}

	egn.Init()

	Example(modulePath, funcPath)

	egn.Close()
	base.Stop()

}
