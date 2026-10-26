// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"gitea.dev/models/auth"
	"gitea.dev/modules/httplib"
	"gitea.dev/modules/json"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCPublicURL(t *testing.T) {
	defer test.MockVariableValue(&setting.AppURL, "https://public.example/")()
	defer test.MockVariableValue(&setting.OAuth2Client.OpenIDConnectScopes, []string{"openid", "email"})()
	store := sessions.NewCookieStore([]byte("oidc-public-url-test-session-key"))
	defer test.MockVariableValue(&gothic.Store, sessions.Store(store))()
	defer test.MockVariableValue(&gothic.SetState, func(*http.Request) string { return uuid.New().String() })()
	defer test.MockVariableValue(&gothic.GetProviderName, func(r *http.Request) (string, error) {
		return r.Header.Get(ProviderHeaderKey), nil
	})()

	var discoveries, exchanges atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discoveries.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
			})
		case "/token":
			exchanges.Add(1)
			if r.FormValue("redirect_uri") != r.FormValue("code") {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			claims, err := json.Marshal(map[string]any{
				"iss":   server.URL,
				"aud":   "test-client",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"sub":   "oidc-subject",
				"oid":   "external-user",
				"email": "oidc@example.com",
			})
			assert.NoError(t, err)
			idToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"id_token":     idToken,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	for _, tc := range []struct {
		name, detection, subpath, method string
		forwarded                        bool
	}{
		{name: "auto", detection: setting.PublicURLAuto, method: http.MethodGet},
		{name: "subpath", detection: setting.PublicURLAuto, subpath: "/gitea", method: http.MethodGet},
		{name: "proxy", detection: setting.PublicURLAuto, method: http.MethodGet, forwarded: true},
		{name: "never", detection: setting.PublicURLNever, method: http.MethodGet},
		{name: "legacy", detection: setting.PublicURLLegacy, method: http.MethodGet},
		{name: "post", detection: setting.PublicURLAuto, method: http.MethodPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.PublicURLDetection, tc.detection)()
			defer test.MockVariableValue(&setting.AppSubURL, tc.subpath)()
			defer test.MockVariableValue(&setting.AppURL, "https://public.example"+tc.subpath+"/")()
			source := &Source{
				Provider: "openidConnect", ClientID: "test-client", ClientSecret: "secret",
				OpenIDConnectAutoDiscoveryURL: server.URL + "/.well-known/openid-configuration",
				ExternalIDClaim:               "oid",
			}
			source.SetAuthSource(&auth.Source{Name: "oidc test+"})
			before := discoveries.Load()
			require.NoError(t, source.RegisterSource())
			t.Cleanup(func() { require.NoError(t, source.UnregisterSource()) })

			type flow struct {
				jar                        http.CookieJar
				origin, callbackURL, state string
			}
			newRequest := func(method, target, body string) *http.Request {
				r := httptest.NewRequest(method, target, strings.NewReader(body))
				if method == http.MethodPost {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if tc.forwarded {
					r.TLS = nil
					r.Header.Set("X-Forwarded-Proto", "https")
				}
				ctx := reqctx.NewRequestContextForTest(t)
				r = httplib.RequestWithContext(r, ctx)
				httplib.MarkRequestSupportPublicURL(ctx)
				return r
			}
			var flows []flow
			for _, origin := range []string{"https://public.example", "https://tailnet.example:8443"} {
				r := newRequest(http.MethodGet, origin+tc.subpath+"/user/oauth2/oidc%20test+", "")
				w := httptest.NewRecorder()
				require.NoError(t, source.Callout(r, w))
				require.Equal(t, http.StatusTemporaryRedirect, w.Code)
				authURL, err := url.Parse(w.Header().Get("Location"))
				require.NoError(t, err)
				callbackOrigin := origin
				if tc.detection == setting.PublicURLNever || tc.detection == setting.PublicURLLegacy {
					callbackOrigin = "https://public.example"
				}
				callbackURL := callbackOrigin + tc.subpath + "/user/oauth2/oidc%20test+/callback"
				require.Equal(t, callbackURL, authURL.Query().Get("redirect_uri"))
				assert.Contains(t, strings.Fields(authURL.Query().Get("scope")), "email")
				jar, err := cookiejar.New(nil)
				require.NoError(t, err)
				jar.SetCookies(r.URL, w.Result().Cookies())
				assert.Empty(t, jar.Cookies(&url.URL{Scheme: "https", Host: "unrelated.example", Path: "/"}))
				flows = append(flows, flow{jar: jar, origin: origin, callbackURL: callbackURL, state: authURL.Query().Get("state")})
			}

			for _, f := range slices.Backward(flows) {
				params := url.Values{"code": {f.callbackURL}, "state": {f.state}, "redirect_uri": {"https://untrusted.example/callback"}}
				target, body := f.origin+tc.subpath+"/user/oauth2/oidc%20test+/callback", ""
				if tc.method == http.MethodPost {
					body = params.Encode()
				} else {
					target += "?" + params.Encode()
				}
				r := newRequest(tc.method, target, body)
				for _, cookie := range f.jar.Cookies(r.URL) {
					r.AddCookie(cookie)
				}
				if tc.name == "auto" {
					missing := r.Clone(r.Context())
					missing.Header.Del("Cookie")
					_, err := source.Callback(missing, httptest.NewRecorder())
					require.EqualError(t, err, "could not find a matching session for this request")
					invalid := r.Clone(r.Context())
					query := invalid.URL.Query()
					query.Set("state", "wrong-state")
					invalid.URL.RawQuery = query.Encode()
					count := exchanges.Load()
					_, err = source.Callback(invalid, httptest.NewRecorder())
					require.EqualError(t, err, "state token mismatch")
					assert.Equal(t, count, exchanges.Load())
				}
				user, err := source.Callback(r, httptest.NewRecorder())
				require.NoError(t, err)
				assert.Equal(t, "external-user", user.UserID)
				if tc.method == http.MethodGet {
					assert.Equal(t, "https://untrusted.example/callback", r.URL.Query().Get("redirect_uri"))
				} else {
					assert.Empty(t, r.URL.RawQuery)
				}
			}
			assert.Equal(t, before+1, discoveries.Load())
			provider, err := goth.GetProvider(source.AuthSource.Name)
			require.NoError(t, err)
			oidcProvider, ok := provider.(*openidConnect.Provider)
			require.True(t, ok)
			assert.Equal(t, setting.AppURL+"user/oauth2/oidc%20test+/callback", oidcProvider.CallbackURL)
			sess, err := provider.BeginAuth("state")
			require.NoError(t, err)
			rawAuthURL, err := sess.GetAuthURL()
			require.NoError(t, err)
			authURL, err := url.Parse(rawAuthURL)
			require.NoError(t, err)
			assert.Equal(t, oidcProvider.CallbackURL, authURL.Query().Get("redirect_uri"))
		})
	}
}
