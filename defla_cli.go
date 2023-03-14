package main

import (
	"github.com/er1cw00/btx.go/base"
	"github.com/er1cw00/btx.go/base/logger"
	egn "github.com/er1cw00/btx.go/engine"
)

func main() {
	if err := base.Start(); err != nil {
		panic(err)
	}
	egn.Init()


	egn.Close()
	base.Stop()

}
