package main

import (
	"flag"
	"fmt"
	"os"

	base "github.com/er1cw00/btx.go/base"
	egn "github.com/er1cw00/btx.go/engine"

	app "github.com/er1cw00/defla.go/app"
)

var rootfsPath string = ""
var xloaderPath string = ""
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
	flag.StringVar(&xloaderPath, "i", "", "library path")
	flag.StringVar(&funcPath, "f", "", "func list json path")
	flag.Usage = usage
}

func main() {
	flag.Parse()
	if help {
		usage()
		os.Exit(0)
	}
	if err := base.Start(); err != nil {
		panic(err)
	}
	egn.Init()

	app.Run(rootfsPath, xloaderPath, funcPath)

	egn.Close()
	base.Stop()

}
