// authors: wangoo
// created: 2018-07-16

package o2

import (
	"net/http"
	"gopkg.in/session.v2"
	"github.com/soundbus-technologies/o2x"
	"context"
)

type HandleMapper func(method, pattern string, handler func(w http.ResponseWriter, r *http.Request))
type HandleConfigurer func(mapper HandleMapper)

func InitServerConfig(cfg *ServerConfig, mapper HandleMapper) {
	if cfg != nil {
		oauth2Cfg = cfg
	} else {
		oauth2Cfg = DefaultServerConfig()
	}

	mapper(http.MethodGet, cfg.UriContext+oauth2UriIndex, IndexHandler)

	mapper(http.MethodGet, cfg.UriContext+oauth2UriLogin, LoginHandler)
	mapper(http.MethodPost, cfg.UriContext+oauth2UriLogin, LoginHandler)

	mapper(http.MethodGet, cfg.UriContext+oauth2UriAuth, AuthHandler)
	mapper(http.MethodPost, cfg.UriContext+oauth2UriAuth, AuthHandler)

	mapper(http.MethodGet, cfg.UriContext+oauth2UriAuthorize, AuthorizeRequestHandler)
	mapper(http.MethodPost, cfg.UriContext+oauth2UriAuthorize, AuthorizeRequestHandler)

	mapper(http.MethodPost, cfg.UriContext+oauth2UriToken, TokenRequestHandler)

	mapper(http.MethodGet, cfg.UriContext+oauth2UriValid, BearerTokenValidator)
	mapper(http.MethodPost, cfg.UriContext+oauth2UriValid, BearerTokenValidator)

	mapper(http.MethodPost, cfg.UriContext+oauth2UriUserAdd, AddUserHandler)
	mapper(http.MethodPost, cfg.UriContext+oauth2UriUserRemove, HandleProcessor(RemoveUserProcessor))
	mapper(http.MethodPost, cfg.UriContext+oauth2UriUserPass, HandleProcessor(UpdatePwdProcessor))
	mapper(http.MethodPost, cfg.UriContext+oauth2UriUserScope, HandleProcessor(UpdateScopeProcessor))

	InitTemplate()
}

func HandleProcessor(processor func(w http.ResponseWriter, r *http.Request) (error)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := processor(w, r)
		if err != nil {
			data, statusCode, _ := oauth2Svr.GetErrorData(err)
			HttpResponse(w, data, statusCode)
			return
		}
		HttpResponse(w, defaultSuccessResponse(), http.StatusOK)
		return
	}
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		redirectToLogin(w, r)
		return
	}
	u, _ := store.Get(SessionUserID)
	if u == nil {
		redirectToLogin(w, r)
		return
	}
	userID := u.(string)
	m := map[string]interface{}{
		"user_id": userID,
	}
	execIndexTemplate(w, r, m)
}

func TokenRequestHandler(w http.ResponseWriter, r *http.Request) {
	err := oauth2Svr.HandleTokenRequest(w, r)
	if err != nil {
		ErrorResponse(w, err, http.StatusBadRequest)
	}
	return
}

func CheckUserAuth(w http.ResponseWriter, r *http.Request) (authorized bool, err error) {
	userID, err := oauth2Svr.UserAuthorizationHandler(w, r)
	if err != nil {
		return
	} else if userID == "" {
		return false, nil
	}

	clientID := clientID(r)
	scope := scope(r)

	if clientID != "" && scope != "" {
		authorized = oauth2Svr.authStore.Exist(&o2x.AuthModel{
			ClientID: clientID,
			UserID:   userID,
			Scope:    scope,
		})
		return
	}
	return false, nil
}

func AuthorizeRequestHandler(w http.ResponseWriter, r *http.Request) {
	authorized, err := CheckUserAuth(w, r)
	if err != nil || !authorized {
		redirectToAuth(w, r)
		return
	}

	if !oauth2Svr.multipleUserTokenEnable && oauth2Svr.o2xTokenAccountSupport && oauth2Svr.tokenStore != nil {
		responseType := responseType(r)
		if responseType == "token" {
			removeAuthToken(w, r)
		}
	}

	err = oauth2Svr.HandleAuthorizeRequest(w, r)
	if err != nil {
		ErrorResponse(w, err, http.StatusInternalServerError)
	}
}

func removeAuthToken(w http.ResponseWriter, r *http.Request) {
	clientID := clientID(r)
	if clientID == "" {
		return
	}
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		return
	}
	u, _ := store.Get(SessionUserID)
	if u == nil {
		return
	}
	userID := u.(string)

	oauth2Svr.o2xTokenStore.RemoveByAccount(userID, clientID)
}

func BearerTokenValidator(w http.ResponseWriter, r *http.Request) {
	tg, validErr := oauth2Svr.ValidationBearerToken(r)
	if validErr != nil {
		ErrorResponse(w, validErr, http.StatusUnauthorized)
		return
	}

	//查询用户是否存在
	user,userErr :=oauth2Svr.userStore.Find(tg.GetUserID())
	if userErr!=nil || user==nil{
		ErrorResponse(w, userErr, http.StatusUnauthorized)
		return
	}

	//查询数据库 看 token是否存在
	nowToken, _ := oauth2Svr.BearerAuth(r)
	tokenInfo,tokenErr :=oauth2Svr.o2xTokenStore.GetByAccess(nowToken)
	if tokenErr!=nil || tokenInfo==nil{
		ErrorResponse(w, tokenErr, http.StatusUnauthorized)
		return
	}

	data := &o2x.ValidResponse{
		ClientID: tg.GetClientID(),
		UserID:   tg.GetUserID(),
		Scope:    tg.GetScope(),
	}

	HttpResponse(w, data, http.StatusOK)
}
