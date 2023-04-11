package api

import (
	"github.com/kataras/iris/v12"

	core "github.com/er1cw00/defla.go/core"
)

var webApp *iris.Application = nil

func Start() error {
	webApp = iris.New()
	api := webApp.Party("/api/v1")
	api.Get("/health", apiHealth)
	api.Post("/health", apiHealth)
	err := webApp.Listen(core.Config.Address)
	return err
}
