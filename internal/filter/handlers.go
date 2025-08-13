/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	//
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"oauthep/internal/utils"
	"oauthep/internal/validator"
)

const (
	CookieNameAccessToken  = "access_token"
	CookieNameIdToken      = "id_token"
	CookieNameRefreshToken = "refresh_token"

	//
)

var (
	CompiledConfigExpansionEnvExpression = regexp.MustCompile(`\$\{env:([^}]+)\}`)
	CompiledConfigExpansionSdsExpression = regexp.MustCompile(`\$\{sds:([^}]+)\}`)
)

func (f *HttpFilter) expandConfigurationStringField(value string) string {

	// Process env vars
	result := CompiledConfigExpansionEnvExpression.ReplaceAllStringFunc(value, func(match string) string {
		submatch := CompiledConfigExpansionEnvExpression.FindStringSubmatch(match)
		key := submatch[1]

		secret := os.Getenv(key)
		if secret != "" {
			return secret
		}

		return match
	})

	// Process generic secrets coming from SDS
	result = CompiledConfigExpansionSdsExpression.ReplaceAllStringFunc(result, func(match string) string {
		submatch := CompiledConfigExpansionSdsExpression.FindStringSubmatch(match)
		key := submatch[1]

		secret, secretFound := f.callbacks.SecretManager().GetGenericSecret(key)
		if secretFound {
			return secret
		}

		return match
	})

	return result
}

// expandConfigurationPlaceholders loop over the configuration fields looking for those being strings.
// When a string is found, call the string expander.
func (f *HttpFilter) expandConfigurationPlaceholders() {

	configValue := reflect.ValueOf(&f.config).Elem()

	for i := 0; i < configValue.NumField(); i++ {
		field := configValue.Field(i)

		// Field is exported? otherwise can not be changed
		if !field.CanSet() {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			currentValue := field.String()

			//
			processedValue := f.expandConfigurationStringField(currentValue)
			field.SetString(processedValue)

		case reflect.Slice:
			// Manage slices of strings
			if field.Type().Elem().Kind() == reflect.String {

				for j := 0; j < field.Len(); j++ {
					element := field.Index(j)
					currentValue := element.String()

					//
					processedValue := f.expandConfigurationStringField(currentValue)
					element.SetString(processedValue)
				}
			}
		default:
			// Nothing happens
		}
	}
}

// logHeaders TODO
func (f *HttpFilter) logHeaders(reqHeaderMap api.RequestHeaderMap) {
	if !f.config.LogAllHeaders {
		return
	}

	allHeaders := reqHeaderMap.GetAllHeaders()
	var headerLogAttrs []interface{}

	for headerKey, headerValues := range allHeaders {
		if slices.Contains(f.config.ExcludeLogHeaders, strings.ToLower(headerKey)) {
			continue
		}
		headerLogAttrs = append(headerLogAttrs, headerKey, headerValues)
	}

	f.callbacks.Log(api.Info, utils.CreateLogString(f.config.LogFormat, slog.LevelInfo, "request headers output", headerLogAttrs...))
}

// shouldSkipPath TODO
func (f *HttpFilter) shouldSkipPath(path string) bool {
	for _, expression := range f.compiledExcludedPathsExpressions {
		if expression.MatchString(path) {
			return true
		}
	}
	return false
}

func (f *HttpFilter) handleLogout() {

	//
	responseHeaders := map[string][]string{
		"Location": {
			f.config.LogoutRedirectAfterUri,
		},
		"Cache-Control": {
			"no-cache, no-store, must-revalidate",
		},
	}

	// Set the cookies for the user
	cookieContent := utils.CookieContent{
		Prefix: f.config.SessionCookiePrefix,
		Path:   f.config.SessionCookiePath,
	}

	//
	responseHeaders["Set-Cookie"] = []string{}
	cookiesToDelete := []string{CookieNameAccessToken, CookieNameIdToken, CookieNameRefreshToken}
	for _, cookieName := range cookiesToDelete {
		cookieContent.Name = cookieName
		cookieValue := utils.CreateCookieContent(cookieContent)
		responseHeaders["Set-Cookie"] = append(responseHeaders["Set-Cookie"], cookieValue)
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to the original site",
		responseHeaders, -1, "")
}

type OauthTokenEndpointResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

func (f *HttpFilter) handleOAuthProviderAuthCallback(currentUrl url.URL) {

	var err error

	defer func() {
		if err != nil {
			f.callbacks.Log(api.Error, utils.CreateLogString(f.config.LogFormat, slog.LevelError, "failed handling oauth provider auth callback", "error", err.Error()))
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "Authentication failed. Please try logging in again.",
				map[string][]string{}, -1, "")
		}
	}()

	code := currentUrl.Query().Get("code")
	state := currentUrl.Query().Get("state")

	if strings.EqualFold(code, "") || strings.EqualFold(state, "") {
		err = fmt.Errorf(`code or state not found in URI`)
		return
	}

	//
	originalUrlFromState, stateValid := utils.ValidateState(f.config.OauthClientSecret, state)
	if !stateValid {
		err = fmt.Errorf(`failed validating state. Try again from the beginning`)
		return
	}

	// Craft the request to exchange code for a token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", f.config.OauthClientId)
	data.Set("client_secret", f.config.OauthClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", f.config.OauthRedirectUri)
	encodedData := data.Encode()

	//
	bodyReader := bytes.NewReader([]byte(encodedData))

	req, err := http.NewRequest(http.MethodPost, f.config.OauthTokenUri, bodyReader)
	if err != nil {
		err = fmt.Errorf(`could not create request to token endpoint: %s`, err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf(`error calling token endpoint: %s`, err.Error())
		return
	}

	//
	if res.StatusCode > 299 {
		err = fmt.Errorf(`token endpoint responded with failure. code: %d - status: %s`, res.StatusCode, res.Status)
		return
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf(`could not read response body from token endpoint: %s`, err.Error())
		return
	}

	responseObj := &OauthTokenEndpointResponse{}
	err = json.Unmarshal(resBody, responseObj)
	if err != nil {
		err = fmt.Errorf(`failed decoding the response from token endpoint: %s`, err.Error())
		return
	}

	//
	responseHeaders := map[string][]string{
		"Location": {
			originalUrlFromState,
		},
		"Cache-Control": {
			"no-cache, no-store, must-revalidate",
		},
	}

	// Set the cookies for the user
	cookieContent := utils.CookieContent{
		Prefix:   f.config.SessionCookiePrefix,
		Domain:   f.config.SessionCookieDomain,
		Path:     f.config.SessionCookiePath,
		Secure:   f.config.SessionCookieSecure,
		HttpOnly: f.config.SessionCookieHttpOnly,
		SameSite: f.config.SessionCookieSameSite,
		Duration: f.config.SessionCookieDuration,
	}

	//
	cookiesToCreate := map[string]string{
		CookieNameAccessToken:  responseObj.AccessToken,
		CookieNameIdToken:      responseObj.IdToken,
		CookieNameRefreshToken: responseObj.RefreshToken,
	}

	for cookieName, cookiePayload := range cookiesToCreate {
		if cookiePayload == "" {
			continue
		}

		cookieContent.Name = cookieName
		cookieContent.Payload = cookiePayload

		if f.config.SessionCookieCompressionEnabled &&
			(cookieName == CookieNameAccessToken || cookieName == CookieNameIdToken || cookieName == CookieNameRefreshToken) {

			accessTokenParts := strings.Split(cookieContent.Payload, ".")
			if len(accessTokenParts) != 3 {
				err = fmt.Errorf("access token doesn't match the pattern header.payload.signature")
				return
			}

			var accessTokenHeader string
			accessTokenHeader, err = utils.CompressBrotliBase64(accessTokenParts[0])
			if err != nil {
				err = fmt.Errorf("failed compressing cookie content: access token header: %s", err.Error())
				return
			}

			var accessTokenPayload string
			accessTokenPayload, err = utils.CompressBrotliBase64(accessTokenParts[1])
			if err != nil {
				err = fmt.Errorf("failed compressing cookie content: access token payload: %s", err.Error())
				return
			}
			cookieContent.Payload = fmt.Sprintf("%s.%s.%s", accessTokenHeader, accessTokenPayload, accessTokenParts[2])
		}

		rawCookieContent := utils.CreateCookieContent(cookieContent)
		responseHeaders["Set-Cookie"] = append(responseHeaders["Set-Cookie"], rawCookieContent)
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to the original site",
		responseHeaders, -1, "")
}

// isRequestAuthenticated TODO
func (f *HttpFilter) isRequestAuthenticated(reqHeaderMap api.RequestHeaderMap) (bool, error) {
	// Get JWKS
	jwksCerts, _, err := f.getJwks()
	if err != nil {
		return false, fmt.Errorf("failed getting JWKS: %s", err.Error())
	}

	// Extract cookies
	cookieHeader, found := reqHeaderMap.Get("cookie")
	if !found {
		return false, nil
	}

	// Extract access token
	accessTokenCookieName := f.config.SessionCookiePrefix + CookieNameAccessToken
	accessTokenCookieValue := utils.ExtractCookieValue(cookieHeader, accessTokenCookieName)

	if accessTokenCookieValue == "" {
		return false, nil
	}
	accessToken := accessTokenCookieValue

	if f.config.SessionCookieCompressionEnabled {
		accessTokenParts := strings.Split(accessTokenCookieValue, ".")
		if len(accessTokenParts) != 3 {
			return false, fmt.Errorf("access token doesn't match the pattern header.payload.signature")
		}

		var accessTokenHeader string
		accessTokenHeader, err = utils.DecompressBrotliBase64(accessTokenParts[0])
		if err != nil {
			return false, fmt.Errorf("failed decompressing cookie content: access token header: %s", err.Error())
		}

		var accessTokenPayload string
		accessTokenPayload, err = utils.DecompressBrotliBase64(accessTokenParts[1])
		if err != nil {
			return false, fmt.Errorf("failed decompressing cookie content: access token payload: %s", err.Error())
		}
		accessToken = fmt.Sprintf("%s.%s.%s", accessTokenHeader, accessTokenPayload, accessTokenParts[2])
	}

	// Validate token
	isValid, err := validator.IsTokenValid(jwksCerts, accessToken)
	if err != nil {
		return false, fmt.Errorf("failed validating token: %s", err.Error())
	}

	return isValid, nil
}

func (f *HttpFilter) redirectToOAuthProvider(currentUrl url.URL) {

	// Craft 'state' (CSRF protection + original URL to come back)
	state := utils.GenerateState(f.config.OauthClientSecret, currentUrl.String())

	// Craft authorization URI
	// TODO: Discover the endpoint from .well-known/openid-configuration
	authURL := fmt.Sprintf("%s?"+
		"client_id=%s&"+
		"response_type=code&"+
		"scope=%s&"+
		"redirect_uri=%s&"+
		"state=%s",
		f.config.OauthAuthUri,
		url.QueryEscape(f.config.OauthClientId),
		url.QueryEscape(strings.Join(f.config.OauthScopes, " ")),
		url.QueryEscape(f.config.OauthRedirectUri),
		url.QueryEscape(state))

	// Send redirect to the user
	headers := map[string][]string{
		"Location": {
			authURL,
		},
		"Cache-Control": {
			"no-cache, no-store, must-revalidate",
		},
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to OAuth provider",
		headers, -1, "")
}

type JwksCacheFile struct {
	JWKS      *validator.JWKS `json:"jwks"`
	Timestamp time.Time       `json:"timestamp"`
}

func (f *HttpFilter) getJwks() (*validator.JWKS, *time.Time, error) {

	ttlDur, err := time.ParseDuration(f.config.OauthJwksCacheTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing TTL for JWKS local cache")
	}

	// Try to read from file cache
	jwks, timestamp, err := f.readJwksFromFile(f.config.OauthJwksCacheFile)
	if err == nil && timestamp.After(time.Now().Add(-ttlDur)) {
		return jwks, &timestamp, nil
	}

	// Fetch from remote
	resp, err := http.Get(f.config.OauthJwksUri)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting JWKS from remote: %s", err.Error())
	}
	defer resp.Body.Close()

	jwksCerts := validator.JWKS{}
	err = json.NewDecoder(resp.Body).Decode(&jwksCerts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding JWKS from remote: %s", err.Error())
	}

	jwksCertsAt := time.Now()

	// Save to file cache
	err = f.writeJwksToFile(f.config.OauthJwksCacheFile, &jwksCerts, jwksCertsAt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed writing in fs: %s", err.Error())
	}

	return &jwksCerts, &jwksCertsAt, nil
}

func (f *HttpFilter) readJwksFromFile(filename string) (*validator.JWKS, time.Time, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer file.Close()

	// Lock for reading
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH) // Shared lock
	if err != nil {
		return nil, time.Time{}, err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, time.Time{}, err
	}

	var cache JwksCacheFile
	err = json.Unmarshal(data, &cache)
	if err != nil {
		return nil, time.Time{}, err
	}

	return cache.JWKS, cache.Timestamp, nil
}

// writeJwksToFile TODO
func (f *HttpFilter) writeJwksToFile(filename string, jwks *validator.JWKS, timestamp time.Time) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("failed creating cache directory: %v", err)
	}

	// Open/create file for writing
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed opening cache file: %v", err)
	}
	defer file.Close()

	// Exclusive lock for writing
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		return fmt.Errorf("failed locking cache file: %v", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	cache := JwksCacheFile{
		JWKS:      jwks,
		Timestamp: timestamp,
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("failed marshaling cache: %v", err)
	}

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed writing cache file: %v", err)
	}

	return nil
}
