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
	"io"
	"net"
	"net/http"
	"net/url"
	"oauthep/internal/config"
	"oauthep/internal/validator"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	//
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/golang-jwt/jwt/v5"
	"oauthep/internal/utils"
)

const (
	// TODO: Move this to another place.
	// Error codes for AuthContext

	ErrorCodeTokenInvalid = 1 // Token structurally invalid
	ErrorCodeStateInvalid = 2 // State validation failed (CSRF)
	ErrorCodeRedirectLoop = 3 // Too many redirects detected
)

var (
	CompiledConfigExpansionEnvExpression = regexp.MustCompile(`\$\{env:([^}]+)\}`)
	CompiledConfigExpansionSdsExpression = regexp.MustCompile(`\$\{sds:([^}]+)\}`)

	// TODO: Move this to another place

	ErrorCodeMessages = map[int]string{
		ErrorCodeTokenInvalid: "Invalid authentication token",
		ErrorCodeStateInvalid: "Invalid authentication state",
		ErrorCodeRedirectLoop: "Too many authentication attempts",
	}
)

// AuthContext structure for cookie storage
type AuthContext struct {
	Attempts     int   `json:"attempts"`
	FirstAttempt int64 `json:"first_attempt"`
	ErrorCode    int   `json:"error_code"`
}

// WithErrorCode sets error code and automatically increments attempts
func (ctx *AuthContext) WithErrorCode(code int) *AuthContext {
	ctx.ErrorCode = code
	ctx.Attempts++
	if ctx.FirstAttempt == 0 {
		ctx.FirstAttempt = time.Now().Unix()
	}
	return ctx
}

// Reset clears the context
func (ctx *AuthContext) Reset() *AuthContext {
	ctx.Attempts = 0
	ctx.FirstAttempt = 0
	ctx.ErrorCode = 0
	return ctx
}

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

// logHeaders log all the request/response headers excluding those set in configuration
func (f *HttpFilter) logHeaders(reqHeaderMap api.RequestHeaderMap, resHeaderMap api.ResponseHeaderMap) {
	if !f.config.LogAllHeaders {
		return
	}

	allReqHeaders := reqHeaderMap.GetAllHeaders()
	var headerLogAttrs []interface{}

	for headerKey, headerValues := range allReqHeaders {

		if slices.Contains(f.config.ExcludeLogHeaders, "request:"+strings.ToLower(headerKey)) {
			continue
		}
		headerLogAttrs = append(headerLogAttrs, "request:"+headerKey, headerValues)
	}

	allResHeaders := resHeaderMap.GetAllHeaders()
	for headerKey, headerValues := range allResHeaders {

		if slices.Contains(f.config.ExcludeLogHeaders, "response:"+strings.ToLower(headerKey)) {
			continue
		}
		headerLogAttrs = append(headerLogAttrs, "response:"+headerKey, headerValues)
	}

	f.logger.Info("headers output", headerLogAttrs...)
}

// shouldSkipFromPath return true when a path is matching with excluded ones set in configuration
func (f *HttpFilter) shouldSkipFromPath(path string) bool {
	for _, expression := range f.compiledExcludedPathsExpressions {
		if expression.MatchString(path) {
			return true
		}
	}
	return false
}

// shouldSkipAuthFromIp return true when an IP from passed XFF header is matching with excluded CIDRs set in configuration
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

// getCookies return a map with plugin-related cookies.
// This function only processes cookies pre-registered in utils.CookiesToHandle
func (f *HttpFilter) getCookies(reqHeaderMap api.RequestHeaderMap) (map[string]string, error) {
	// Extract cookies
	cookieHeader, found := reqHeaderMap.Get(utils.CookieRequestHeaderName)
	if !found {
		return nil, fmt.Errorf("cookie header not found")
	}

	//
	cookieNameToContentMap := map[string]string{}

	for _, cookieName := range utils.CookiesToHandle {
		// Extract tokens from cookies
		prefixedCookieName := f.config.SessionCookiePrefix + cookieName

		tokenCookieValue := utils.ExtractCookieValue(cookieHeader, prefixedCookieName)
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
		cookieNameToContentMap[cookieName] = tokenCookieValue
	}

	return cookieNameToContentMap, nil
}

// setCookies set cookies with the content of cookieData map. It maps cookie's name -> content
// This function only processes cookies pre-registered in utils.CookiesToHandle
func (f *HttpFilter) setCookies(responseHeaders map[string][]string, cookieData map[string]string) error {

	cookieContent := utils.CookieContent{
		Prefix:   f.config.SessionCookiePrefix,
		Domain:   f.config.SessionCookieDomain,
		Path:     f.config.SessionCookiePath,
		Secure:   f.config.SessionCookieSecure,
		HttpOnly: f.config.SessionCookieHttpOnly,
		SameSite: f.config.SessionCookieSameSite,
		Duration: f.config.SessionCookieDuration,
	}

	// Iterar solo por cookies registradas (como hace getCookies)
	for _, cookieName := range utils.CookiesToHandle {

		cookiePayload := cookieData[cookieName]
		if cookiePayload == "" {
			continue // Skip cookies vacías
		}

		cookieContent.Name = cookieName
		cookieContent.Payload = cookiePayload

		// Comprimir solo si es JWT
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

// FIXME: This function is here for backward compatibility
// setAuthCookies set auth cookies in passed response headers.
// Values for auth cookies are passed as an OauthTokenEndpointResponse object
func (f *HttpFilter) setAuthCookies(responseHeaders map[string][]string, tokens *OauthTokenEndpointResponse) error {
	cookieData := map[string]string{
		utils.CookieNameAccessToken:  tokens.AccessToken,
		utils.CookieNameIdToken:      tokens.IdToken,
		utils.CookieNameRefreshToken: tokens.RefreshToken,
	}
	return f.setCookies(responseHeaders, cookieData)
}

// refreshAccessToken perform a request to refresh the tokens and return the response as bytes
func (f *HttpFilter) refreshAccessToken(refreshToken string) ([]byte, error) {
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

	responseBodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return responseBodyBytes, err
}

// checkRequestAuthentication retrieve the tokens from the cookies and validate them.
// When they are expired, try to refresh and store them in Envoy's metadata.
func (f *HttpFilter) checkRequestAuthentication(reqHeaderMap api.RequestHeaderMap) error {

	////////////////////////////
	// Validation phase
	////////////////////////////

	// Get JWKS in lazy mode
	jwksCerts, _, err := f.getJwks()
	if err != nil {
		return fmt.Errorf("failed getting JWKS: %s", err.Error())
	}

	// Extract cookies
	cookieNameToContentMap, err := f.getCookies(reqHeaderMap)
	if err != nil {
		return fmt.Errorf("failed getting tokens from cookies: %s", err.Error())
	}

	// Time to validate the token, bruh.
	// The process depends on the provider as not all of them are super standard
	var parsedToken *jwt.Token
	var validationError error
	switch f.config.Provider {
	case config.ProviderGoogle:
		// Token types: https://cloud.google.com/docs/authentication/token-types
		// Authentication docs: https://cloud.google.com/iap/docs/authentication-howto
		parsedToken, validationError = validator.ValidateJsonWebToken(jwksCerts, cookieNameToContentMap[utils.CookieNameIdToken])
	default:
		parsedToken, validationError = validator.ValidateJsonWebToken(jwksCerts, cookieNameToContentMap[utils.CookieNameAccessToken])
	}

	// Critical validation issue: Token structurally invalid
	// These cannot be fixed with refresh
	if parsedToken == nil {
		f.authContext.WithErrorCode(ErrorCodeTokenInvalid)
		if validationError != nil {
			return fmt.Errorf("token structurally invalid: %s", validationError.Error())
		}
		return fmt.Errorf("token structurally invalid: unknown error")
	}

	////////////////////////////
	// Claims check phase
	////////////////////////////

	// Token is structurally valid - evaluate CEL regardless of expiration
	for _, celProgram := range f.celPrograms {
		out, _, err := (*celProgram).Eval(map[string]interface{}{
			"payload": parsedToken.Claims,
		})

		if err != nil {
			return fmt.Errorf("cel program evaluation error: %s", err.Error())
		}

		if out.Value() != true {
			return fmt.Errorf("claim does not meet cel conditions")
		}
	}

	////////////////////////////
	// Decision phase
	////////////////////////////

	// Token is valid and passes CEL
	if validationError == nil {
		return nil
	}

	// Token passes CEL but has validation issues - check if it's just expiration
	if !errors.As(validationError, &jwt.ErrTokenExpired) {
		// Not expiration - some other issue we can't fix with refresh
		return fmt.Errorf("token validation failed: %s", validationError.Error())
	}

	////////////////////////////
	// Refresh flow phase
	////////////////////////////

	f.logger.Debug("expired token detected. refresh in process")

	// No refresh_token found
	if cookieNameToContentMap[utils.CookieNameRefreshToken] == "" {
		return fmt.Errorf("refresh token not found")
	}

	// Try to refresh tokens
	newTokensBytes, refreshError := f.refreshAccessToken(cookieNameToContentMap[utils.CookieNameRefreshToken])
	if refreshError != nil {
		return fmt.Errorf("failed refreshing tokens: %s", refreshError.Error())
	}

	// New tokens achieved, store them and allow entrance
	f.logger.Debug("tokens have been refreshed")
	f.callbacks.StreamInfo().DynamicMetadata().Set("oauthep", "new_tokens", string(newTokensBytes))

	return nil
}

////////////////////////////////////////////////////
// Experiments from here
////////////////////////////////////////////////////

// getAuthContextFromCookies retrieves and decrypts auth context from cookies
func (f *HttpFilter) getAuthContextFromCookies(reqHeaderMap api.RequestHeaderMap) (*AuthContext, error) {
	// Get all cookies
	cookieMap, err := f.getCookies(reqHeaderMap)
	if err != nil {
		return nil, fmt.Errorf("failed getting cookies: %w", err)
	}

	// Look for context cookie
	encodedContext, exists := cookieMap[utils.CookieNameContext]
	if !exists || encodedContext == "" {
		// Return empty context if no cookie found
		return &AuthContext{}, nil
	}

	// Decrypt and decode
	decryptedBytes, err := utils.DecryptData(encodedContext, f.config.OauthClientSecret)
	if err != nil {
		f.logger.Warn("failed to decrypt auth context, returning empty", "error", err.Error())
		return &AuthContext{}, nil
	}

	var context AuthContext
	err = json.Unmarshal(decryptedBytes, &context)
	if err != nil {
		f.logger.Warn("failed to unmarshal auth context, returning empty", "error", err.Error())
		return &AuthContext{}, nil
	}

	return &context, nil
}

// setAuthContextInCookies encrypts and stores auth context in response headers
func (f *HttpFilter) setAuthContextInCookies(responseHeaders map[string][]string, context *AuthContext) error {
	// Serialize context
	jsonBytes, err := json.Marshal(context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	// Encrypt
	encodedContext, err := utils.EncryptData(jsonBytes, f.config.OauthClientSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt context: %w", err)
	}

	// Set cookie using existing function
	cookieData := map[string]string{
		utils.CookieNameContext: encodedContext,
	}

	return f.setCookies(responseHeaders, cookieData)
}

const (
	MaxAuthAttempts = 3
	AttemptWindow   = 5 * 60 // 5 minutes in seconds
)

// shouldRedirectToError determines if we should show error page instead of redirecting to login
func (f *HttpFilter) shouldRedirectToError() bool {
	if f.authContext == nil {
		return false
	}

	now := time.Now().Unix()

	// When too many attempts happened in time window
	if f.authContext.Attempts >= MaxAuthAttempts &&
		now-f.authContext.FirstAttempt <= AttemptWindow {
		return true
	}

	return false
}
