// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"net/http"
	"net/url"

	"gitea.dev/modules/httplib"
	"gitea.dev/modules/json"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/openidConnect"
)

// Callout redirects request/response pair to authenticate against the provider
func (source *Source) Callout(request *http.Request, response http.ResponseWriter) error {
	// not sure if goth is thread safe (?) when using multiple providers
	request.Header.Set(ProviderHeaderKey, source.AuthSource.Name)

	// don't use the default gothic begin handler to prevent issues when some error occurs
	// normally the gothic library will write some custom stuff to the response instead of our own nice error page
	// gothic.BeginAuthHandler(response, request)

	gothRWMutex.RLock()
	defer gothRWMutex.RUnlock()

	var authURL string
	var err error
	if source.Provider == "openidConnect" {
		authURL, err = source.oidcAuthURL(request, response)
	} else {
		authURL, err = gothic.GetAuthURL(response, request)
	}
	if err == nil {
		http.Redirect(response, request, authURL, http.StatusTemporaryRedirect)
	}
	return err
}

// Callback handles OAuth callback, resolve to a goth user and send back to original url
// this will trigger a new authentication request, but because we save it in the session we can use that
func (source *Source) Callback(request *http.Request, response http.ResponseWriter) (goth.User, error) {
	// not sure if goth is thread safe (?) when using multiple providers
	request.Header.Set(ProviderHeaderKey, source.AuthSource.Name)

	gothRWMutex.RLock()
	defer gothRWMutex.RUnlock()

	if source.Provider == "openidConnect" {
		var err error
		request, err = source.oidcCallbackRequest(request)
		if err != nil {
			return goth.User{}, err
		}
	}

	user, err := gothic.CompleteUserAuth(response, request)
	if err != nil {
		return user, err
	}

	return user, nil
}

func (source *Source) oidcAuthURL(request *http.Request, response http.ResponseWriter) (string, error) {
	providerName := source.AuthSource.Name
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}
	sess, err := provider.BeginAuth(gothic.SetState(request))
	if err != nil {
		return "", err
	}
	openidSession, ok := sess.(*openidConnect.Session)
	if !ok {
		return "", ErrAuthSourceNotActivated
	}
	authURL, err := url.Parse(openidSession.AuthURL)
	if err != nil {
		return "", err
	}
	params := authURL.Query()
	params.Set("redirect_uri", source.oidcCallbackURL(request))
	authURL.RawQuery = params.Encode()
	openidSession.AuthURL = authURL.String()
	if err := gothic.StoreInSession(providerName, sess.Marshal(), request, response); err != nil {
		return "", err
	}
	return openidSession.AuthURL, nil
}

func (source *Source) oidcCallbackRequest(request *http.Request) (*http.Request, error) {
	value, err := gothic.GetFromSession(source.AuthSource.Name, request)
	if err != nil {
		return nil, err
	}
	sess := &openidConnect.Session{}
	if err := json.Unmarshal([]byte(value), sess); err != nil {
		return nil, err
	}
	authURL, err := url.Parse(sess.AuthURL)
	if err != nil {
		return nil, err
	}
	request = request.Clone(request.Context())
	params := request.URL.Query()
	if len(params) == 0 && request.Method == http.MethodPost {
		if err := request.ParseForm(); err != nil {
			return nil, err
		}
		params = request.Form
	}
	// Goth's OIDC session accepts redirect_uri as an exchange parameter; only trust the saved authorization request.
	params.Set("redirect_uri", authURL.Query().Get("redirect_uri"))
	request.URL.RawQuery = params.Encode()
	return request, nil
}

func (source *Source) oidcCallbackURL(request *http.Request) string {
	return httplib.GuessCurrentAppURL(request.Context()) + "user/oauth2/" + url.PathEscape(source.AuthSource.Name) + "/callback"
}
