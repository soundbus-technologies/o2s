// authors: wangoo
// created: 2018-05-21
// ouath2 server demo based on redis storage

package o2

import (
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3"

	"github.com/soundbus-technologies/o2x"
	"net/http"
	oauth2Error "gopkg.in/oauth2.v3/errors"
	"github.com/golang/glog"
	"encoding/json"
)

type Oauth2Server struct {
	*server.Server
	mapper HandleMapper
	cfg    *ServerConfig

	clientStore oauth2.ClientStore
	tokenStore  oauth2.TokenStore
	userStore   o2x.UserStore
	authStore   o2x.AuthStore

	// ---------------------------
	// whether the token store support account management
	o2xTokenAccountSupport bool
	o2xTokenStore          o2x.O2TokenStore

	// ---------------------------
	// enable to create multiple token for one user of a client
	multipleUserTokenEnable bool
}

// NewServer create authorization server
func NewServer(cfg *server.Config, manager oauth2.Manager) *Oauth2Server {
	svr := server.NewServer(cfg, manager)
	o2svr := &Oauth2Server{
		Server: svr,
	}

	return o2svr
}

func (s *Oauth2Server) GetUserStore() o2x.UserStore {
	return s.userStore
}

func (s *Oauth2Server) EnableMultipleUserToken() {
	s.multipleUserTokenEnable = true
}

func (s *Oauth2Server) DisableMultipleUserToken() {
	s.multipleUserTokenEnable = false
}

// ValidationTokenRequest the token request validation, add user client scope validation
func (s *Oauth2Server) ValidationTokenRequest(r *http.Request) (gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest, err error) {
	gt = oauth2.GrantType(r.FormValue("grant_type"))

	if fn, ok := customGrantRequestValidatorMap[gt]; ok {
		gt, tgr, err = fn(r)
	} else {
		gt, tgr, err = s.Server.ValidationTokenRequest(r)
	}

	if err != nil {
		return
	}

	// check whether need scope check
	if tgr.Scope == "" || gt != oauth2.PasswordCredentials {
		return
	}

	user, err := s.userStore.Find(tgr.UserID)
	if err != nil {
		return
	}
	scope, ok := user.GetScopes()[tgr.ClientID]
	if ok && o2x.ScopeContains(scope, tgr.Scope) {
		return
	}
	glog.Errorf("the scope of user [%v] for client [%v] is [%v], but request [%v]", tgr.UserID, tgr.ClientID, scope, tgr.Scope)
	err = oauth2Error.ErrInvalidScope
	return
}

// HandleTokenRequest token request handling
func (s *Oauth2Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) (err error) {
	gt, tgr, verr := s.ValidationTokenRequest(r)
	if verr != nil {
		err = s.tokenError(w, verr)
		return
	}

	ti, verr := s.GetAccessToken(gt, tgr)
	if verr != nil {
		err = s.tokenError(w, verr)
		return
	}

	err = s.token(w, s.GetTokenData(ti), nil)
	return
}

// override Server.tokenError
func (s *Oauth2Server) tokenError(w http.ResponseWriter, err error) (uerr error) {
	data, statusCode, header := s.GetErrorData(err)

	uerr = s.token(w, data, header, statusCode)
	return
}

// override Server.token
func (s *Oauth2Server) token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) (err error) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	err = json.NewEncoder(w).Encode(data)
	return
}

func (s *Oauth2Server) AddHandler(method, uri string, handler func(w http.ResponseWriter, r *http.Request)) {
	s.mapper(method, s.cfg.UriContext+uri, handler)
}

func (s *Oauth2Server) AddCustomerGrantType(grantType oauth2.GrantType, validator GrantTypeRequestValidator, handleConfigurer HandleConfigurer) {
	for _, t := range s.Config.AllowedGrantTypes {
		if t == grantType {
			panic("grant type already exist")
		}
	}

	s.Config.AllowedGrantTypes = append(s.Config.AllowedGrantTypes, grantType)
	customGrantRequestValidatorMap[grantType] = validator

	if handleConfigurer != nil {
		handleConfigurer(s.AddHandler)
	}
}

// ---------------------------
func InitOauth2Server(cs oauth2.ClientStore, ts oauth2.TokenStore, us o2x.UserStore, as o2x.AuthStore,
	cfg *ServerConfig, mapper HandleMapper) *Oauth2Server {
	if cs == nil || ts == nil || us == nil {
		panic("store is nil")
	}

	InitServerConfig(cfg, mapper)

	oauth2Mgr = manage.NewDefaultManager()

	oauth2Mgr.MustTokenStorage(ts, nil)
	oauth2Mgr.MustClientStorage(cs, nil)

	DefaultTokenConfig(oauth2Mgr)

	oauth2Svr = NewServer(&server.Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.PasswordCredentials,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
			oauth2.Implicit,
		},
	}, oauth2Mgr)

	oauth2Svr.clientStore = cs
	oauth2Svr.tokenStore = ts
	oauth2Svr.userStore = us

	if as == nil {
		as = o2x.NewAuthStore()
	}
	oauth2Svr.authStore = as

	oauth2Svr.o2xTokenStore, oauth2Svr.o2xTokenAccountSupport = ts.(o2x.O2TokenStore)

	// set mapper
	oauth2Svr.mapper = mapper
	// set cfg
	oauth2Svr.cfg = cfg

	oauth2Svr.SetAllowGetAccessRequest(true)
	oauth2Svr.SetClientInfoHandler(server.ClientBasicHandler)
	oauth2Svr.SetPasswordAuthorizationHandler(PasswordAuthorizationHandler)
	oauth2Svr.SetUserAuthorizationHandler(userAuthorizeHandler)
	oauth2Svr.SetInternalErrorHandler(InternalErrorHandler)
	oauth2Svr.SetResponseErrorHandler(ResponseErrorHandler)
	oauth2Svr.SetClientScopeHandler(ClientScopeHandler)
	oauth2Svr.SetClientAuthorizedHandler(ClientAuthorizedHandler)
	oauth2Svr.SetRefreshingScopeHandler(RefreshingScopeHandler)
	oauth2Svr.SetAuthorizeScopeHandler(AuthorizeScopeHandler)

	return oauth2Svr
}
