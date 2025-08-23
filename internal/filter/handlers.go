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
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"net"
	"net/http"
	"net/url"
	"oauthep/internal/config"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	//
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"oauthep/internal/utils"
	"oauthep/internal/validator"
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

		f.logger.Debug("looking for secret in environment variables", "variable", key)
		secret := os.Getenv(key)
		if secret != "" {
			f.logger.Debug("secret found in environment variables", "variable", key, "value", secret)
			return secret
		}

		f.logger.Debug("secret not found in environment variables", "variable", key)
		return match
	})

	// Process generic secrets coming from SDS
	result = CompiledConfigExpansionSdsExpression.ReplaceAllStringFunc(result, func(match string) string {
		submatch := CompiledConfigExpansionSdsExpression.FindStringSubmatch(match)
		key := submatch[1]

		f.logger.Debug("looking for generic secret in SDS secret manager", "secret_name", key)
		secret, secretFound := f.callbacks.SecretManager().GetGenericSecret(key)
		if secretFound {
			f.logger.Debug("generic secret found in SDS secret manager", "secret_name", key, "value", secret)
			return secret
		}

		f.logger.Debug("generic secret not found in SDS secret manager", "secret_name", key)
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

	f.logger.Info("request headers output", headerLogAttrs...)
}

// shouldSkipFromPath TODO
func (f *HttpFilter) shouldSkipFromPath(path string) bool {
	for _, expression := range f.compiledExcludedPathsExpressions {
		if expression.MatchString(path) {
			return true
		}
	}
	return false
}

// shouldSkipAuthFromIp TODO
func (f *HttpFilter) shouldSkipAuthFromIp(xffHeaderValue []string) (bool, error) {

	// Assume Envoy is getting the real IP by default
	clientRealIpRaw := f.callbacks.StreamInfo().DownstreamRemoteAddress()
	clientRealIpHost, _, err := net.SplitHostPort(clientRealIpRaw)
	if err != nil {
		return false, fmt.Errorf("failed parsing downstream address: %s", err.Error())
	}

	clientRealIp := net.ParseIP(clientRealIpHost)
	if clientRealIp == nil {
		return false, fmt.Errorf("invalid downstream IP address: %s", clientRealIpHost)
	}

	// Calculate from XFF when requested by config
	if f.config.TrustedProxiesMode == "xforwarded" {

		if len(xffHeaderValue) == 0 || xffHeaderValue[0] == "" {
			return false, fmt.Errorf("x-forwarded-for header is empty")
		}

		sourceIPs := utils.GetHopsFromChainedHops(xffHeaderValue[0])
		if len(sourceIPs) == 0 {
			return false, fmt.Errorf("no valid IPs in X-Forwarded-For header")
		}

		xffClientIp, xffClientIpFound := utils.GetRealClientIpFromXFF(f.trustedProxiesCidrs, sourceIPs)
		if !xffClientIpFound {
			return false, fmt.Errorf("failed calculating real client ip from XFF. Client ip could be accidetally trusted")
		}

		clientRealIp = xffClientIp
	}

	return utils.IsTrustedIp(f.skipAuthCidrs, clientRealIp), nil
}

// TODO
func (f *HttpFilter) getAuthCookies(reqHeaderMap api.RequestHeaderMap) (tokenMap map[string]string, err error) {
	// Extract cookies
	cookieHeader, found := reqHeaderMap.Get(utils.CookieRequestHeaderName)
	if !found {
		return nil, fmt.Errorf("cookie header not found")
	}

	//
	tokenValueMap := map[string]string{
		utils.CookieNameAccessToken:  "",
		utils.CookieNameIdToken:      "",
		utils.CookieNameRefreshToken: "",
	}

	for tokenName, _ := range tokenValueMap {
		// Extract tokens from cookies
		tokenCookieName := f.config.SessionCookiePrefix + tokenName

		tokenCookieValue := utils.ExtractCookieValue(cookieHeader, tokenCookieName)
		if tokenCookieValue == "" {
			continue
		}

		// Decompress?
		if f.config.SessionCookieCompressionEnabled {
			decompressedTokenCookieValue, err := utils.DecompressJWT(tokenCookieValue)
			if err == nil {
				tokenCookieValue = decompressedTokenCookieValue
			}

			// Errors decompressing are silently ignored
		}
		tokenValueMap[tokenName] = tokenCookieValue
	}

	return tokenValueMap, nil
}

// TODO
func (f *HttpFilter) setAuthCookies(responseHeaders map[string][]string, tokens *OauthTokenEndpointResponse) error {

	cookieContent := utils.CookieContent{
		Prefix:   f.config.SessionCookiePrefix,
		Domain:   f.config.SessionCookieDomain,
		Path:     f.config.SessionCookiePath,
		Secure:   f.config.SessionCookieSecure,
		HttpOnly: f.config.SessionCookieHttpOnly,
		SameSite: f.config.SessionCookieSameSite,
		Duration: f.config.SessionCookieDuration,
	}

	cookiesToCreate := map[string]string{
		utils.CookieNameAccessToken:  tokens.AccessToken,
		utils.CookieNameIdToken:      tokens.IdToken,
		utils.CookieNameRefreshToken: tokens.RefreshToken,
	}

	for cookieName, cookiePayload := range cookiesToCreate {
		if cookiePayload == "" {
			continue
		}

		cookieContent.Name = cookieName
		cookieContent.Payload = cookiePayload

		//
		if f.config.SessionCookieCompressionEnabled && validator.IsParsableAsJWT(cookiePayload) {
			compressedPayload, err := utils.CompressJWT(cookiePayload)
			if err != nil {
				return fmt.Errorf("failed compressing cookie %s: %w", cookieName, err)
			}
			cookieContent.Payload = compressedPayload
		}

		rawCookieContent := utils.CreateCookieContent(cookieContent)
		responseHeaders[utils.CookieResponseHeaderName] = append(responseHeaders[utils.CookieResponseHeaderName], rawCookieContent)
	}

	return nil
}

// TODO
func (f *HttpFilter) handleLogout() {

	responseHeaders := map[string][]string{
		"Location":      {f.config.LogoutRedirectAfterUri},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
		"Set-Cookie":    utils.GenerateCleanCookiesHeader(f.config.SessionCookiePrefix, f.config.SessionCookiePath),
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		302,
		"Redirecting to the original site",
		responseHeaders,
		-1,
		"")
}

type OauthTokenEndpointResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TODO
func (f *HttpFilter) handleOAuthProviderAuthCallback(currentUrl url.URL) {

	var err error

	defer func() {
		if err != nil {
			f.logger.Error("failed handling oauth provider auth callback", "error", err.Error())
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

	// Check required fields for exchange
	tokenRequiredFields := map[string]string{
		"client_id":     f.config.OauthClientId,
		"client_secret": f.config.OauthClientSecret,
		"code":          code,
		"redirect_uri":  f.config.OauthRedirectUri,
	}

	f.logger.Debug("params set for code exchange", "params", tokenRequiredFields)
	for reqFieldName, reqFieldValue := range tokenRequiredFields {
		if strings.EqualFold(reqFieldValue, "") {
			err = fmt.Errorf(`required field empty for code exchange: %s`, reqFieldName)
			return
		}
	}

	// Craft the request to exchange code for a token
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", f.config.OauthClientId)
	data.Set("client_secret", f.config.OauthClientSecret)
	data.Set("redirect_uri", f.config.OauthRedirectUri)
	data.Set("grant_type", "authorization_code")
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
		"Location":      {originalUrlFromState},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	// Set the cookies in the user browser
	err = f.setAuthCookies(responseHeaders, responseObj)
	if err != nil {
		err = fmt.Errorf("failed setting cookies: %s", err.Error())
		return
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to the original site",
		responseHeaders, -1, "")
}

// refreshAccessToken perform a request to refresh the tokens and return them
func (f *HttpFilter) refreshAccessToken(refreshToken string) (*OauthTokenEndpointResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", f.config.OauthClientId)
	data.Set("client_secret", f.config.OauthClientSecret)

	bodyReader := bytes.NewReader([]byte(data.Encode()))
	req, err := http.NewRequest(http.MethodPost, f.config.OauthTokenUri, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 {
		return nil, fmt.Errorf("refresh failed: %d", res.StatusCode)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	responseObj := &OauthTokenEndpointResponse{}
	err = json.Unmarshal(resBody, responseObj)
	return responseObj, err
}

// checkRequestAuthentication retrieve the tokens from the cookies and validate them.
// When they are expired, try to refresh and store them in Envoy's metadata.
func (f *HttpFilter) checkRequestAuthentication(reqHeaderMap api.RequestHeaderMap) error {
	// Get JWKS in lazy mode
	jwksCerts, _, err := f.getJwks()
	if err != nil {
		return fmt.Errorf("failed getting JWKS: %s", err.Error())
	}

	// Extract cookies
	tokenValueMap, err := f.getAuthCookies(reqHeaderMap)
	if err != nil {
		return fmt.Errorf("failed getting tokens from cookies: %s", err.Error())
	}

	// Time to validate the token, bruh.
	// The process depends on the provider as not all of them are super standard
	var validationError error
	switch f.config.Provider {
	case config.ProviderGoogle:
		// Token types: https://cloud.google.com/docs/authentication/token-types
		// https://cloud.google.com/iap/docs/authentication-howto
		validationError = validator.ValidateJsonWebToken(jwksCerts, tokenValueMap[utils.CookieNameIdToken])
	default:
		validationError = validator.ValidateJsonWebToken(jwksCerts, tokenValueMap[utils.CookieNameAccessToken])
	}

	// JWT is valid, give the good news to the user
	if validationError == nil {
		return nil
	}

	// Token invalid and issue is NOT expiration
	if !errors.As(validationError, &jwt.ErrTokenExpired) {
		return fmt.Errorf("failed token validation: %s", validationError.Error())
	}

	f.logger.Info("expired token detected. refresh in process")

	// No refresh_token found
	if tokenValueMap[utils.CookieNameRefreshToken] == "" {
		return fmt.Errorf("refresh token not found")
	}

	// Try to refresh tokens
	newTokens, refreshError := f.refreshAccessToken(tokenValueMap[utils.CookieNameRefreshToken])
	if refreshError != nil {
		return fmt.Errorf("failed refreshing tokens: %s", refreshError.Error())
	}

	// New tokens achieved, store them and allow entrance
	f.logger.Debug("tokens have been refreshed")
	f.callbacks.StreamInfo().DynamicMetadata().Set("oauthep", "new_tokens", newTokens)
	return nil
}

// redirectToOAuthProvider redirect the user to Oauth2 provider
func (f *HttpFilter) redirectToOAuthProvider(currentUrl url.URL) {

	// Craft 'state' (CSRF protection + original URL to come back)
	state := utils.GenerateState(f.config.OauthClientSecret, currentUrl.String())

	// Craft authorization URI
	// TODO: Discover the endpoint from .well-known/openid-configuration
	authURL := fmt.Sprintf("%s?"+
		"response_type=code&"+
		"client_id=%s&"+
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
		"Location":      {authURL},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to OAuth provider",
		headers, -1, "")
}
