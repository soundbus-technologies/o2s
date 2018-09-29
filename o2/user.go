// authors: wangoo
// created: 2018-05-29
// user

package o2

import (
	"context"
	"github.com/golang/glog"
	"github.com/soundbus-technologies/o2x"
	"gopkg.in/session.v2"
	"net/http"

	oauth2Error "gopkg.in/oauth2.v3/errors"
)

//从session中获取userId
func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	store, err := session.Start(context.Background(), w, r)
	if err != nil {
		return
	}
	uid, _ := store.Get(SessionUserID)
	if uid == nil {
		return
	}

	userID = uid.(string)
	return
}

//密码校验，传入userId和被校验的密码
func PasswordAuthorizationHandler(username, password string) (userID string, err error) {
	//先利用userId查询用户信息
	u, err := oauth2Svr.userStore.Find(username)
	if err != nil {
		return
	}

	//然后校验密码
	if u != nil && u.Match(password) {
		uid := u.GetUserID()
		return o2x.UserIdString(uid)
	}
	err = o2x.ErrInvalidCredential
	return
}

// 新增用户操作
func AddUserHandler(w http.ResponseWriter, r *http.Request) {
	err := AddUserProcessor(w, r)
	if err != nil {
		data, statusCode, _ := oauth2Svr.GetErrorData(err)
		data["user_id"] = username(r)
		HttpResponse(w, data, statusCode)
		return
	}
	HttpResponse(w, defaultSuccessResponse(), http.StatusOK)
	return
}

// add new user
func AddUserProcessor(w http.ResponseWriter, r *http.Request) (err error) {
	clientID, err := ClientBasicAuth(r)
	if err != nil {
		return
	}
	username := username(r)
	password := password(r)
	scope := scope(r)
	if anyNil(username, password) {
		err = o2x.ErrValueRequired
		return
	}
	u, err := oauth2Svr.userStore.Find(username)
	if err != nil && err != o2x.ErrNotFound {
		return
	}
	if u != nil {
		err = o2x.ErrDuplicated
		return
	}

	user := &o2x.SimpleUser{
		UserID: username,
	}

	if scope != "" {
		user.Scopes[clientID] = scope
	}

	user.SetRawPassword(password)

	glog.Infof("client %v add user %v", clientID, username)
	err = oauth2Svr.userStore.Save(user)
	if err != nil {
		return
	}

	return
}

// 删除用户操作
func RemoveUserProcessor(w http.ResponseWriter, r *http.Request) (err error) {
	clientID, err := ClientBasicAuth(r)
	if err != nil {
		return
	}
	username := username(r)
	if anyNil(username) {
		err = o2x.ErrValueRequired
		return
	}

	glog.Infof("client %v remove user %v", clientID, username)

	//删除用户表
	err = oauth2Svr.userStore.Remove(username)
	if err != nil {
		return
	}

	//删除token表
	oauth2Svr.o2xTokenStore.RemoveByAccountNoClient(username)

	return
}

// 删除用户下的所有token；
// clientId 没有使用
func RemoveUserAllTokenProcessor(w http.ResponseWriter, r *http.Request) (err error) {
	clientID, err := ClientBasicAuth(r)
	if err != nil {
		return
	}

	username := username(r)
	if anyNil(username) {
		err = o2x.ErrValueRequired
		return
	}
	glog.Infof("client %v remove user %v", clientID, username)

	//删除token表
	oauth2Svr.o2xTokenStore.RemoveByAccountNoClient(username)
	return
}

// 修改用户密码
func UpdatePwdProcessor(w http.ResponseWriter, r *http.Request) (err error) {
	clientID, err := ClientBasicAuth(r)
	if err != nil {
		return
	}

	username := username(r)
	password := password(r)
	if anyNil(username, password) {
		err = o2x.ErrValueRequired
		return
	}

	glog.Infof("client %v update password of user %v", clientID, username)
	u, err := oauth2Svr.userStore.Find(username)
	if err != nil {
		return
	}
	err = oauth2Svr.userStore.UpdatePwd(u.GetUserID(), password)
	if err != nil {
		return
	}
	return
}

//检查用户密码，如果密码正确则返回成功；如果不正确则返回错误；
// clientId 没用
func CheckUserPassProcessor(w http.ResponseWriter, r *http.Request) (err error) {
	clientID, err := ClientBasicAuth(r)
	if err != nil {
		return
	}
	username := username(r)
	password := password(r)
	if anyNil(username, password) {
		err = o2x.ErrValueRequired
		return
	}
	glog.Infof("client %v update password of user %v", clientID, username)

	//开始检验用户密码
	_, verr := PasswordAuthorizationHandler(username, password)
	if verr != nil {
		err = verr
		return
	}
	return
}

// 更新用户scope
func UpdateScopeProcessor(w http.ResponseWriter, r *http.Request) (err error) {
	clientID, err := ClientBasicAuth(r)
	if err != nil {
		return
	}
	username := username(r)
	scope := scope(r)
	if anyNil(username, scope) {
		err = o2x.ErrValueRequired
		return
	}

	glog.Infof("client %v update scope of user %v to %v", clientID, username, scope)
	u, err := oauth2Svr.userStore.Find(username)
	if err != nil {
		return
	}

	//检查当前的scope在这个client下是否允许
	allow, err := oauth2Svr.ClientScopeHandler(clientID, scope)
	if err != nil {
		return
	}
	if !allow {
		err = oauth2Error.ErrInvalidScope
		return
	}

	//更新操作
	err = oauth2Svr.userStore.UpdateScope(u.GetUserID(), clientID, scope)
	if err != nil {
		return
	}
	return
}
