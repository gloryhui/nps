package controllers

import (
	"ehang.io/nps/lib/file"
)

type GlobalController struct {
	BaseController
}

var globalDBProvider = file.GetDb

func (s *GlobalController) Index() {
	//if s.Ctx.Request.Method == "GET" {
	//
	//	return
	//}
	s.Data["menu"] = "global"
	s.SetInfo("global")
	s.display("global/index")

	global := globalDBProvider().GetGlobal()
	if global == nil {
		return
	}
	s.Data["serverUrl"] = global.ServerUrl
}

// 添加全局参数
func (s *GlobalController) Save() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "global"
		s.SetInfo("save global")
		s.display()
	} else {
		db := globalDBProvider()
		current := db.GetGlobal()
		t := &file.Glob{
			ServerUrl: s.getEscapeString("serverUrl"),
		}
		if current != nil {
			t.BlackIpList = append([]string(nil), current.BlackIpList...)
		}

		if err := db.SaveGlobal(t); err != nil {
			s.AjaxErr(err.Error())
		}
		s.AjaxOk("save success")
	}
}
