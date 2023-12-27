// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AthenZ/athenz-client-sidecar/v2/config"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/kpango/ntokend"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
)

// AccessService represents an interface to automatically refresh the access token, and an access token provider function pointer.
type AccessService interface {
	StartAccessUpdater(context.Context) <-chan error
	RefreshAccessTokenCache(ctx context.Context) <-chan error
	GetAccessProvider() AccessProvider
	TokenCacheLen() int
	TokenCacheSize() int64
}

// accessService represents the implementation of Athenz AccessService
type accessService struct {
	cfg                   config.AccessToken
	token                 ntokend.TokenProvider
	athenzURL             string
	athenzPrincipleHeader string
	tokenCache            gache.Gache
	memoryUsage           int64
	group                 singleflight.Group
	expiry                time.Duration
	httpClient            atomic.Value
	rootCAs               *x509.CertPool
	certPath              string
	certKeyPath           string

	refreshPeriod    time.Duration
	errRetryMaxCount int
	errRetryInterval time.Duration
}

type accessCacheData struct {
	token             string
	domain            string
	role              string
	proxyForPrincipal string
	expiresIn         int64  // cache user request parameter
	expiry            int64  // cache ZTS response
	scope             string // cache ZTS response
}

// AccessTokenResponse represents the AccessTokenResponse from postAccessTokenRequest.
type AccessTokenResponse struct {
	// AccessToken
	AccessToken string `json:"access_token"`

	// TokenType e.g. Bearer
	TokenType string `json:"token_type"`

	// Expiry in seconds
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// Scope of the access token e.g. openid (delimited by space)
	Scope string `json:"scope,omitempty"`

	// RefreshToken
	RefreshToken string `json:"refresh_token,omitempty"`

	// IDToken
	IDToken string `json:"id_token,omitempty"`
}

// AccessProvider represents a function pointer to retrieve the access token.
type AccessProvider func(ctx context.Context, domain string, role string, proxyForPrincipal string, expiresIn int64) (*AccessTokenResponse, error)

var (
	// ErrAccessTokenRequestFailed represents the error when failed to fetch the access token from Athenz server.
	ErrAccessTokenRequestFailed = errors.New("Failed to fetch AccessToken")
)

const (
	// scopeSeparator is the separator for scope
	scopeSeparator = " "
)

// NewAccessService returns a AccessService to update and fetch the access token from Athenz.
func NewAccessService(cfg config.AccessToken, token ntokend.TokenProvider) (AccessService, error) {
	var (
		err              error
		exp              = defaultExpiry
		refreshPeriod    = defaultRefreshPeriod
		errRetryInterval = defaultErrRetryInterval
	)

	if !cfg.Enable {
		return nil, ErrDisabled
	}

	if cfg.Expiry != "" {
		if exp, err = time.ParseDuration(cfg.Expiry); err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, "Expiry: "+err.Error())
		}
	}
	if cfg.RefreshPeriod != "" {
		if refreshPeriod, err = time.ParseDuration(cfg.RefreshPeriod); err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, "RefreshPeriod: "+err.Error())
		}
	}
	if cfg.Retry.Delay != "" {
		if errRetryInterval, err = time.ParseDuration(cfg.Retry.Delay); err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, "ErrRetryInterval: "+err.Error())
		}
	}

	// if user set the expiry time and refresh period > expiry time then return error
	if exp != 0 && refreshPeriod > exp {
		return nil, errors.Wrap(ErrInvalidSetting, "refresh period > token expiry time")
	}

	errRetryMaxCount := defaultErrRetryMaxCount
	if cfg.Retry.Attempts > 0 {
		errRetryMaxCount = cfg.Retry.Attempts
	} else if cfg.Retry.Attempts != 0 {
		return nil, errors.Wrap(ErrInvalidSetting, "ErrRetryMaxCount < 0")
	}

	if token == nil && cfg.CertPath == "" {
		return nil, errors.Wrap(ErrInvalidSetting, "Neither NToken nor client certificate is set.")
	}

	var cp *x509.CertPool
	if cfg.AthenzCAPath != "" {
		var err error
		caPath := config.GetActualValue(cfg.AthenzCAPath)
		_, err = os.Stat(caPath)
		if os.IsNotExist(err) {
			return nil, errors.Wrap(ErrInvalidSetting, "Athenz CA not exist")
		}
		cp, err = NewX509CertPool(caPath)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidSetting, err.Error())
		}
	}

	certPath := cfg.CertPath
	certKeyPath := cfg.CertKeyPath
	// prevent using client certificate (ntoken has priority)
	if token != nil {
		certPath = ""
		certKeyPath = ""
	}

	tlsConfig, err := NewTLSClientConfig(cp, certPath, certKeyPath)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidSetting, err.Error())
	}

	var httpClient atomic.Value
	httpClient.Store(&http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsConfig,
		},
	})

	return &accessService{
		cfg:                   cfg,
		token:                 token,
		athenzURL:             cfg.AthenzURL,
		athenzPrincipleHeader: cfg.PrincipalAuthHeader,
		tokenCache:            gache.New(),
		memoryUsage:           0,
		expiry:                exp,
		httpClient:            httpClient,
		rootCAs:               cp,
		certPath:              certPath,
		certKeyPath:           certKeyPath,
		refreshPeriod:         refreshPeriod,
		errRetryMaxCount:      errRetryMaxCount,
		errRetryInterval:      errRetryInterval,
	}, nil
}

// StartAccessUpdater returns AccessService.
// This function will periodically refresh the access token.
func (a *accessService) StartAccessUpdater(ctx context.Context) <-chan error {
	glg.Info("Starting access token updater")

	ech := make(chan error, 100)
	go func() {
		defer close(ech)

		ticker := time.NewTicker(a.refreshPeriod)
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping access token updater...")
				ticker.Stop()
				ech <- ctx.Err()
				return
			case <-ticker.C:
				for err := range a.RefreshAccessTokenCache(ctx) {
					ech <- errors.Wrap(err, "error update access token")
				}
			}
		}
	}()

	a.tokenCache.StartExpired(ctx, cachePurgePeriod)
	a.tokenCache.EnableExpiredHook().SetExpiredHook(func(ctx context.Context, k string) {
		glg.Warnf("unexpected cache expiry, please review your refreshPeriod and expiry configuration, and related token expiry in the request body, key: %v", k)
		glg.Warnf("the expired token data is still counted in the cache memory usage estimation even the allocated memory is freed, which causes over-estimation in the cache memory usage log message")
	})
	return ech
}

// GetAccessProvider returns a function pointer to get the access token.
func (a *accessService) GetAccessProvider() AccessProvider {
	return a.getAccessToken
}

// getAccessToken returns AccessTokenResponse struct or error.
// This function will return the access token stored inside the cache, or fetch the access token from Athenz when corresponding access token cannot be found in the cache.
func (a *accessService) getAccessToken(ctx context.Context, domain, role, proxyForPrincipal string, expiresIn int64) (*AccessTokenResponse, error) {
	cd, ok := a.getCache(domain, role, proxyForPrincipal)
	if !ok {
		return a.updateAccessToken(ctx, domain, role, proxyForPrincipal, expiresIn)
	}
	atResponse := &AccessTokenResponse{
		AccessToken: cd.token,
		ExpiresIn:   int64(time.Unix(cd.expiry, 0).Sub(time.Now()).Seconds()),
		TokenType:   "Bearer", // hardcoded in the same way as ZTS, https://github.com/AthenZ/athenz/blob/a85f48666763759ee28fda114acc4c8d2cafc28e/servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSImpl.java#L2656C10-L2656C10
	}
	if cd.scope != "" {
		atResponse.Scope = cd.scope // set scope ONLY when non-nil & non-empty, https://github.com/AthenZ/athenz/blob/a85f48666763759ee28fda114acc4c8d2cafc28e/core/zts/src/main/java/com/yahoo/athenz/zts/AccessTokenResponse.java#L21C14-L21C14
	}

	return atResponse, nil
}

// RefreshAccessTokenCache returns the error channel when it is updated.
func (a *accessService) RefreshAccessTokenCache(ctx context.Context) <-chan error {
	glg.Info("RefreshAccessTokenCache started")

	echan := make(chan error, a.tokenCache.Len()*(a.errRetryMaxCount+1))
	go func() {
		defer close(echan)

		a.tokenCache.Foreach(ctx, func(key string, val interface{}, exp int64) bool {
			domain, role, principal := decode(key)
			cd := val.(*accessCacheData)

			for err := range a.updateAccessTokenWithRetry(ctx, domain, role, principal, cd.expiresIn) {
				echan <- err
			}
			return true
		})
	}()

	return echan
}

func (a *accessService) TokenCacheLen() int {
	cacheLen := 0
	a.tokenCache.Foreach(context.Background(), func(key string, val interface{}, exp int64) bool {
		cacheLen += 1
		return true
	})
	return cacheLen
}

func (a *accessService) TokenCacheSize() int64 {
	// To estimate the memory usage of the cache,
	// we multiply memoryUsage by 1.125　to account for overhead of map structure
	return int64(float64(a.memoryUsage) * 1.125)
}

// updateAccessTokenWithRetry wraps updateAccessToken with retry logic.
func (a *accessService) updateAccessTokenWithRetry(ctx context.Context, domain, role, proxyForPrincipal string, expiresIn int64) <-chan error {
	glg.Debugf("updateAccessTokenWithRetry started, domain: %s, role: %s, proxyForPrincipal: %s, expiresIn: %d", domain, role, proxyForPrincipal, expiresIn)

	echan := make(chan error, a.errRetryMaxCount+1)
	go func() {
		defer close(echan)

		for i := 0; i <= a.errRetryMaxCount; i++ {
			if _, err := a.updateAccessToken(ctx, domain, role, proxyForPrincipal, expiresIn); err != nil {
				echan <- err
				time.Sleep(a.errRetryInterval)
			} else {
				glg.Debug("update success")
				break
			}
		}
	}()

	return echan
}

// updateAccessToken returns AccessTokenResponse struct or error.
// This function ask Athenz to generate access token and return, or return any error when generating the access token.
func (a *accessService) updateAccessToken(ctx context.Context, domain, role, proxyForPrincipal string, expiresIn int64) (*AccessTokenResponse, error) {
	key := encode(domain, role, proxyForPrincipal)
	expTimeDelta := fastime.Now().Add(time.Minute)

	at, err, _ := a.group.Do(key, func() (interface{}, error) {
		at, e := a.fetchAccessToken(ctx, domain, role, proxyForPrincipal, expiresIn)
		if e != nil {
			return nil, e
		}

		tok, _, err := jwt.NewParser().ParseUnverified(at.AccessToken, &jwt.RegisteredClaims{})
		if err != nil {
			return nil, fmt.Errorf("jwt.ParseUnverified() err: %v", err)
		}

		expTime, err := tok.Claims.GetExpirationTime()
		if err != nil {
			return nil, fmt.Errorf("jwt.GetExpirationTime() err: %v", err)
		}

		acd := &accessCacheData{
			token:             at.AccessToken,
			domain:            domain,
			role:              role,
			proxyForPrincipal: proxyForPrincipal,
			expiresIn:         expiresIn,
			expiry:            expTime.Unix(),
			scope:             at.Scope,
		}

		a.storeTokenCache(key, acd, expTimeDelta, expTime)
		glg.Debugf("token is cached, domain: %s, role: %s, proxyForPrincipal: %s, expiry time: %v", domain, role, proxyForPrincipal, expTime.Unix())
		return at, nil
	})
	if err != nil {
		return nil, err
	}

	return at.(*AccessTokenResponse), err
}

func (a *accessService) storeTokenCache(key string, acd *accessCacheData, expTimeDelta time.Time, expTime *jwt.NumericDate) {
	oldTokenCacheData, _ := a.tokenCache.Get(key)
	a.tokenCache.SetWithExpire(key, acd, expTime.Sub(expTimeDelta))
	if oldTokenCacheData != nil {
		if oldTokenCache, ok := oldTokenCacheData.(*accessCacheData); ok {
			oldTokenCacheSize := accessCacheMemoryUsage(oldTokenCache)
			a.memoryUsage += accessCacheMemoryUsage(acd) - oldTokenCacheSize
			return
		}
		a.memoryUsage += accessCacheMemoryUsage(acd)
		return
	}
	a.memoryUsage += accessCacheMemoryUsage(acd) + int64(len(key))
	return
}

func accessCacheMemoryUsage(acd *accessCacheData) int64 {
	structSize := int64(unsafe.Sizeof(*acd))
	stringSize := int64(len(acd.token) + len(acd.domain) + len(acd.role) + len(acd.proxyForPrincipal) + len(acd.scope))

	return structSize + stringSize
}

// fetchAccessToken fetches the access token from Athenz server, and returns the AccessTokenResponse or any error occurred.
// P.S. Do not call fetchAccessToken() outside singleflight group, as behavior of concurrent request is not tested
func (a *accessService) fetchAccessToken(ctx context.Context, domain, role, proxyForPrincipal string, expiry int64) (*AccessTokenResponse, error) {
	glg.Debugf("get access token, domain: %s, role: %s, proxyForPrincipal: %s, expiry: %d", domain, role, proxyForPrincipal, expiry)

	scope := createScope(domain, role)
	glg.Debugf("request access token scope: %v", scope)

	// prepare request object
	req, err := a.createPostAccessTokenRequest(scope, proxyForPrincipal, expiry)
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}
	glg.Debugf("request url: %v", req.URL)

	// prepare Athenz credentials
	if a.token != nil {
		token, err := a.token()
		if err != nil {
			return nil, err
		}
		req.Header.Set(a.athenzPrincipleHeader, token)
	} else if a.certPath != "" {
		// prepare TLS config (certificate file may refresh)
		tcc, err := NewTLSClientConfig(a.rootCAs, a.certPath, a.certKeyPath)
		if err != nil {
			return nil, err
		}
		a.httpClient.Store(&http.Client{
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: tcc,
			},
		})
	} else {
		return nil, ErrNoCredentials
	}

	// send request
	res, err := a.httpClient.Load().(*http.Client).Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	// process response
	defer flushAndClose(res.Body)
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(res.Body); err != nil {
			glg.Debugf("cannot read response body, err: %v", err)
		}
		glg.Debugf("error return from server, response:%+v, body: %v", res, buf.String())
		return nil, ErrAccessTokenRequestFailed
	}

	var atRes *AccessTokenResponse
	if err = json.NewDecoder(res.Body).Decode(&atRes); err != nil {
		return nil, err
	}

	return atRes, nil
}

// createScope create OAuth scope.
// The format of scope is like `[domain]:role.[role1] [domain]:role.[role2]`.
// If role is empty, the format is `[domain]:domain`.
func createScope(domain, role string) string {
	if role != "" {
		roles := strings.Split(role, roleSeparator)
		scopes := make([]string, len(roles))
		for i, r := range roles {
			scopes[i] = domain + ":role." + r
		}
		return strings.Join(scopes, scopeSeparator)
	}
	return domain + ":domain"
}

func (a *accessService) getCache(domain, role, principal string) (*accessCacheData, bool) {
	val, ok := a.tokenCache.Get(encode(domain, role, principal))
	if !ok {
		return nil, false
	}
	return val.(*accessCacheData), ok
}

// createGetAccessTokenRequest creates Athenz's postAccessTokenRequest.
func (a *accessService) createPostAccessTokenRequest(scope, proxyForPrincipal string, expiry int64) (*http.Request, error) {
	u := fmt.Sprintf("https://%s/oauth2/token", strings.TrimPrefix(strings.TrimPrefix(a.athenzURL, "https://"), "http://"))

	// create URL query
	q := url.Values{}
	q.Add("grant_type", "client_credentials")
	q.Add("scope", scope)
	if proxyForPrincipal != "" {
		q.Add("proxy_for_principal", proxyForPrincipal)
	}
	if expiry <= 0 {
		expiry = int64(a.expiry / time.Second)
	}
	if expiry > 0 {
		q.Add("expires_in", strconv.FormatInt(expiry, 10))
	}

	// create request
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(q.Encode()))
	if err != nil {
		glg.Debugf("fail to create request object, error: %s", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}
