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
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"io"
	"net/http"
	"net/url"
	"strings"
	//
	"oauthep/internal/config"
	"oauthep/internal/utils"
)

type ErrorInfo struct {
	ErrorType    string   `json:"error_type"`
	ErrorMessage string   `json:"error_message"`
	Attempts     int      `json:"attempts"`
	LastErrors   []string `json:"last_errors"`
	Timestamp    int64    `json:"timestamp"`
	Suggestions  []string `json:"suggestions"`
}

func (f *HttpFilter) handleErrorRedirect() {

	responseHeaders := map[string][]string{
		"Location":      {f.config.ErrorPath},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		302,
		"Redirecting to the original site",
		responseHeaders,
		-1,
		"")
}

func (f *HttpFilter) handleError(reqHeaderMap api.RequestHeaderMap) {

	f.logger.Debug("Handling error page request")

	//
	cookies, err := f.getCookies(reqHeaderMap)
	if err != nil {
		f.logger.Debug("No cookies found for error page", "error", err.Error())
		cookies = map[string]string{}
	}

	// Extract context content
	contextJSON := cookies["context"]
	_ = contextJSON

	// TODO
	// Generate a nice error page
	// Clean context and auth cookies
	// Send error page too user
}

// handleLogout handles auth cookies removal and redirection to the URL defined in configuration param 'logout_redirect_after_uri'
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

// handleOauthProviderAuthCallback handles callback->code<->token exchange flow between the plugin and OpenID provider.
func (f *HttpFilter) handleOauthProviderAuthCallback(currentUrl url.URL) {

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
		f.authContext.WithErrorCode(ErrorCodeStateInvalid)
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

	for reqFieldName, reqFieldValue := range tokenRequiredFields {
		if strings.EqualFold(reqFieldValue, "") {
			err = fmt.Errorf(`required field empty in code <-> token exchange flow: %s`, reqFieldName)
			return
		}
	}

	f.logger.Debug("code <-> token exchange flow prepared", "params", tokenRequiredFields)

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

// handleOauthProviderRedirection remove the cookies and redirect the user to OpenID provider.
// Handles login->code->callback flow for non-authenticated users
func (f *HttpFilter) handleOauthProviderRedirection(currentUrl url.URL) {

	// Craft 'state' (CSRF protection + original URL to come back)
	state := utils.GenerateState(f.config.OauthClientSecret, currentUrl.String())

	// Craft authorization URI
	// TODO: Discover the endpoint from .well-known/openid-configuration
	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("client_id", f.config.OauthClientId)
	data.Set("scope", strings.Join(f.config.OauthScopes, " "))
	data.Set("redirect_uri", f.config.OauthRedirectUri)
	data.Set("state", state)

	// Force Google to provide refresh_token
	if f.config.Provider == config.ProviderGoogle {
		data.Set("access_type", "offline")
	}
	authURL := fmt.Sprintf("%s?%s", f.config.OauthAuthUri, data.Encode())

	// Send redirect to the user
	headers := map[string][]string{
		"Location":      {authURL},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
		"Set-Cookie":    utils.GenerateCleanCookiesHeader(f.config.SessionCookiePrefix, f.config.SessionCookiePath),
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to OAuth provider",
		headers, -1, "")
}
