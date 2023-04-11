package main

import (
	"flag"
	"fmt"
	"os"

	egn "github.com/er1cw00/btx.go/engine"

	//app "github.com/er1cw00/defla.go/app"
	core "github.com/er1cw00/defla.go/core"
	"github.com/er1cw00/defla.go/core/api"
)

var configFile string = ""
var help bool = false

func usage() {
	fmt.Printf("Usage: naga.go [-ch]\r\n")
	fmt.Printf("           -h print this message\r\n")
	fmt.Printf("           -c config file path\r\n")
}

func init() {
	flag.BoolVar(&help, "h", false, "print help")
	flag.StringVar(&configFile, "c", "", "config file path")
	flag.Usage = usage
}

func main() {
	flag.Parse()
	if help {
		usage()
		os.Exit(0)
	}
	if err := core.Start(configFile); err != nil {
		panic(err)
	}
	egn.Init()
	api.Start()

	egn.Close()
	core.Stop()
}
