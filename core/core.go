package core

import (
	"github.com/er1cw00/btx.go/base/logger"
)

func Start(confFile string) error {
	err := ParseConfig(confFile)
	if err != nil {
		return err
	}
	err = logger.New(Config.LogLevel, Config.LogPath, "defla.go")
	if err == nil {
		return err
	}

	return err
}

func Stop() {

}
