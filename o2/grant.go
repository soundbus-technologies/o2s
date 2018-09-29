// authors: wangoo
// created: 2018-07-26

package o2

import (
	"gopkg.in/oauth2.v3"
	"net/http"
)

type GrantTypeRequestValidator func(r *http.Request) (gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest, err error)

var (
	//自定义授权类型的校验方法Map
	customGrantRequestValidatorMap = make(map[oauth2.GrantType]GrantTypeRequestValidator)
)
