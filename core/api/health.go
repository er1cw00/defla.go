package api

import (
	"github.com/kataras/iris/v12"
	"time"
)

func apiHealth(ctx iris.Context) {
	ts := time.Now().Unix()
	ctx.JSON(iris.Map{"status": iris.StatusOK, "timestamp": ts})
}
