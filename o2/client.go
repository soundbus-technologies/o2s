// authors: wangoo
// created: 2018-07-26

package o2

import (
	"github.com/soundbus-technologies/o2x"
	"gopkg.in/oauth2.v3"
)

//检查在此clientId下，此scope是否允许
func ClientScopeHandler(clientID, scope string) (allowed bool, err error) {
	if scope == "" {
		allowed = true
		return
	}
	cli, err := oauth2Svr.clientStore.GetByID(clientID)
	if err != nil {
		return
	}
	if client, ok := cli.(o2x.O2ClientInfo); ok {
		allowed = o2x.ScopeArrContains(client.GetScopes(), scope)
		return
	}
	allowed = true
	return
}

//判断这个grantType在此clientId下是否允许
func ClientAuthorizedHandler(clientID string, grantType oauth2.GrantType) (allowed bool, err error) {
	cli, err := oauth2Mgr.GetClient(clientID)
	if err != nil {
		return
	}

	if o2ClientInfo, ok := cli.(o2x.O2ClientInfo); ok {
		if o2ClientInfo.GetGrantTypes() != nil {
			for _, t := range o2ClientInfo.GetGrantTypes() {
				if t == grantType {
					return true, nil
				}
			}
			return false, nil
		}
	}

	return true, nil
}
