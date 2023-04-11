package core

import (
	"fmt"
	"io/ioutil"

	utils "github.com/er1cw00/btx.go/base/utils"
	yaml "gopkg.in/yaml.v3"
)

type DeflaConfig struct {
	Address    string `yaml:"address"`
	LogPath    string `yaml:"logPath"`
	LogLevel   string `yaml:"logLevel"`
	RootfsPath string `yaml:"rootfs"`
}

var Config *DeflaConfig = nil

func ParseConfig(filepath string) error {

	if Config == nil {
		Config = new(DeflaConfig)
	}

	yamlFile, err := ioutil.ReadFile(filepath)

	if err != nil {
		fmt.Printf("yamlFile.Get err:%v ", err)
		return err
	}

	//fmt.Printf("yamlFile: \n%s\r\n", string(yamlFile))

	err = yaml.Unmarshal(yamlFile, Config)
	if err != nil {
		fmt.Printf("Unmarshal Fail: %v", err)
		return err
	}

	if len(Config.LogPath) == 0 || !utils.PathExists(Config.LogPath) {
		Config.LogPath = ""
	}
	return nil
}
