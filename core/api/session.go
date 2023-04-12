package api

import (
	"fmt"
	"github.com/kataras/iris/v12"

	"github.com/er1cw00/btx.go/base/logger"
	app "github.com/er1cw00/defla.go/app"
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
	if start, err = stringToUint64(ctx.URLParam("start")); err != nil {
		if start, err = stringToUint64(ctx.PostValue("start")); err != nil {
			response(ctx, StatusBadRequest, "unknonw start")
			return
		}
	}
	if end, err = stringToUint64(ctx.URLParam("end")); err != nil {
		if end, err = stringToUint64(ctx.PostValue("end")); err != nil {
			response(ctx, StatusBadRequest, "unknonw 'end' ")
			return
		}
	}
	logger.Debugf("apiParseFunc >> session: %s, name: %s, start: 0x%x, end: 0x%x", session, name, start, end)

	var session *app.Session = nil
	if session, err = app.Get(id); err != nil {
		msg := fmt.Sprintf("session (%s) not found", id)
		response(ctx, StatusInternalError, msg)
		return
	}
	bbList, err := defla.NewBBList(session.Capstone, fn.Name, m.GetLoadBase()+fn.Start, fn.Start, fn.End)
	if err != nil {
		logger.Fatalf("parse function to basic block fail, err: %v", err)
	}
	fmt.Printf("%s\n", bbList.String())

	response(ctx, StatusOK, "success")
}
