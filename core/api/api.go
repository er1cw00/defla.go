package api

import (
	"github.com/kataras/iris/v12"
	"strconv"

	core "github.com/er1cw00/defla.go/core"
)

var webApp *iris.Application = nil

const (
	StatusOK            = 0
	StatusServerError   = 1
	StatusBadRequest    = 2
	StatusInternalError = 3
)

type ResponseModel struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func Start() error {
	webApp = iris.New()
	//webApp.StaticContent("/", core.Config.HtmlPath)
	api := webApp.Party("/api/v1")
	api.Get("/health", apiHealth)
	api.Post("/health", apiHealth)

	api.Post("/session", apiCreateSession)
	api.Get("/session/{session:string}/funcs", apiGetFuncList)
	api.Post("/session/{session:string}/func/{func:string}", apiParseFunc)

	err := webApp.Listen(core.Config.Address)
	return err
}

func response(ctx iris.Context, status int, msg string) {
	ctx.StatusCode(iris.StatusOK)
	ctx.JSON(iris.Map{"status": status, "message": msg})
}

func stringToUint64(s string) (uint64, error) {
	var u64 uint64 = 0
	var err error = nil
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		if u64, err = strconv.ParseUint(s[2:], 16, 64); err != nil {
			return 0, err
		}
	} else {
		if u64, err = strconv.ParseUint(s, 16, 64); err != nil {
			return 0, err
		}
	}
	return u64, nil
}
