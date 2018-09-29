// authors: wangoo
// created: 2018-07-24

package captcha

import (
	"github.com/golang/glog"
	"github.com/soundbus-technologies/o2s/o2"
	"github.com/soundbus-technologies/o2x"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/errors"
	oauth2Error "gopkg.in/oauth2.v3/errors"
	"net/http"
)

type CaptchaSender func(mobile, captcha string) (err error)

const (
	oauth2UriCaptcha = "/captcha"
)

var (
	oauth2Svr *o2.Oauth2Server

	o2xCaptchaAuthEnable = false
	oauth2CaptchaStore   o2x.CaptchaStore
	oauth2CaptchaSender  CaptchaSender
)

func CaptchaLogSender(mobile, captcha string) (err error) {
	glog.Infof("captcha console sender:%v,%v", mobile, captcha)
	return
}

func SendCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	err := SendCaptcha(w, r)
	if err != nil {
		o2.ErrorResponse(w, err, http.StatusBadRequest)
		return
	}

	o2.HttpResponse(w, "ok", http.StatusOK)
}

//发送短信处理
func SendCaptcha(w http.ResponseWriter, r *http.Request) (err error) {
	mobile := r.FormValue("mobile")
	if mobile == "" {
		err = o2x.ErrValueRequired
		return
	}

	_, err = oauth2Svr.GetUserStore().FindMobile(mobile)
	if err != nil {
		return
	}

	clientID, err := o2.ClientBasicAuth(r)
	if err != nil {
		return
	}

	if fn := oauth2Svr.ClientAuthorizedHandler; fn != nil {
		allowed, verr := fn(clientID, o2x.CaptchaCredentials)
		if verr != nil {
			err = verr
			return
		} else if !allowed {
			err = errors.ErrUnauthorizedClient
			return
		}
	}

	captcha := "123456"

	err = oauth2CaptchaSender(mobile, captcha)
	if err != nil {
		return
	}

	err = oauth2CaptchaStore.Save(mobile, captcha)
	if err != nil {
		return
	}

	return
}

// validate captcha token request
func ValidationCaptchaTokenRequest(r *http.Request) (gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest, err error) {
	if !o2xCaptchaAuthEnable {
		err = oauth2Error.ErrUnsupportedGrantType
		return
	}

	// set the grant_type=password so that the oauth2 framework can recognize it
	gt = oauth2.PasswordCredentials

	mobile := r.FormValue("mobile")
	captcha := r.FormValue("captcha")
	if mobile == "" || captcha == "" {
		err = oauth2Error.ErrInvalidRequest
		return
	}
	valid, err := oauth2CaptchaStore.Valid(mobile, captcha)
	if err != nil {
		return
	}
	if !valid {
		err = o2x.ErrInvalidCaptcha
		return
	}

	clientID, clientSecret, err := oauth2Svr.ClientInfoHandler(r)
	if err != nil {
		return
	}

	tgr = &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	tgr.Scope = r.FormValue("scope")

	user, verr := oauth2Svr.GetUserStore().FindMobile(mobile)
	if verr != nil {
		err = verr
		return
	} else if user == nil {
		err = oauth2Error.ErrInvalidGrant
		return
	}

	tgr.UserID = user.GetID()
	return
}

// enable captcha auth
func EnableCaptchaAuth(s *o2.Oauth2Server, captchaStore o2x.CaptchaStore, sender CaptchaSender) {
	oauth2CaptchaStore = captchaStore
	oauth2CaptchaSender = sender
	o2xCaptchaAuthEnable = true

	s.AddCustomerGrantType(o2x.CaptchaCredentials, ValidationCaptchaTokenRequest, func(mapper o2.HandleMapper) {
		mapper(http.MethodPost, oauth2UriCaptcha, SendCaptchaHandler)
	})
}
