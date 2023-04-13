package api

import (
	"fmt"
	"github.com/kataras/iris/v12"

	"github.com/er1cw00/btx.go/base/logger"
	app "github.com/er1cw00/defla.go/app"
	model "github.com/er1cw00/defla.go/core/model"
)

func apiCreateSession(ctx iris.Context) {
	var err error = nil
	var session *app.Session = nil
	if err = app.CheckLimited(); err != nil {
		response(ctx, StatusInternalError, fmt.Sprintf("create session fail, error: %v", err))
		return
	}
	if session, err = app.NewSession(); err != nil {
		response(ctx, StatusInternalError, fmt.Sprintf("create session fail, error: %v", err))
		return
	}
	modulePath := "/Users/wadahana/Desktop/tdx/xloader/libxloader.so"
	if err = session.Load(modulePath); err != nil {
		response(ctx, StatusInternalError, fmt.Sprintf("load module [%s] fail, error: %v", modulePath, err))
		return
	}
	if err = app.Append(session.Id, session); err != nil {
		response(ctx, StatusInternalError, fmt.Sprintf("append session fail, error: %v", modulePath, err))
		return
	}
	response(ctx, StatusOK, session.Id)
}

func apiGetFuncList(ctx iris.Context) {
	// ts := time.Now().Unix()
	// ctx.JSON(iris.Map{"status": iris.StatusOK, "timestamp": ts})
}

func apiParseFunc(ctx iris.Context) {
	var err error = nil
	var start uint64 = 0
	var end uint64 = 0
	id := ctx.Params().Get("session")
	if len(id) < 0 {
		response(ctx, StatusBadRequest, "unknonw session id")
		return
	}
	name := ctx.Params().Get("func")
	if len(name) < 0 {
		response(ctx, StatusBadRequest, "unknonw name")
		return
	}
	if start, err = model.HexStringToUint64(ctx.URLParam("start")); err != nil {
		if start, err = model.HexStringToUint64(ctx.PostValue("start")); err != nil {
			response(ctx, StatusBadRequest, "unknonw start")
			return
		}
	}
	if end, err = model.HexStringToUint64(ctx.URLParam("end")); err != nil {
		if end, err = model.HexStringToUint64(ctx.PostValue("end")); err != nil {
			response(ctx, StatusBadRequest, "unknonw 'end' ")
			return
		}
	}
	logger.Debugf("apiParseFunc >> session: %s, name: %s, start: 0x%x, end: 0x%x", id, name, start, end)

	var session *app.Session = nil
	var fn *app.Function = nil
	if session, err = app.Get(id); err != nil {
		msg := fmt.Sprintf("session (%s) not found", id)
		response(ctx, StatusInternalError, msg)
		return
	}
	if fn, err = session.ParseFunction(name, start, end); err != nil {
		msg := fmt.Sprintf("parse function to basic block fail, err: %v", err)
		response(ctx, StatusInternalError, msg)
		return
	}
	ctx.StatusCode(iris.StatusOK)
	ctx.WriteString(fn.String())
	ctx.WriteString("\n")
}
