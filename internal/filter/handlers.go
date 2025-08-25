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
	"net/http"
	"net/url"
	"strings"

	//
	"oauthep/internal/config"
	"oauthep/internal/utils"
)

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

// handleErrorRedirect handle the redirection to the actual error page sending the FlowContext cookie to the user
func (f *HttpFilter) handleErrorRedirect() {
	responseHeaders := map[string][]string{
		"Location":      {f.config.ErrorPath},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	// Build and set context cookie
	err := f.setFlowContextInCookies(responseHeaders, f.flowContext)
	if err != nil {
		f.logger.Debug("failed setting flow context cookie to the user")
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302,
		"Redirecting to error page", responseHeaders, -1, "")
}

// handleError shows an error page to the user. It gets the content from the FlowContext
func (f *HttpFilter) handleError() {

	f.logger.Debug("Handling error page request", "auth_context", f.flowContext)

	// Parent function will handle context retrieval from cookies.
	// AuthContext is already stored in the filter object.
	// Just make it shine, bruh.

	//
	var errCode int
	if len(f.flowContext.Errors) > 0 {
		errCode = f.flowContext.Errors[len(f.flowContext.Errors)-1].Code
	} else {
		errCode = ErrorCodeNoErrorFound
	}

	//
	responseHeaders := map[string][]string{
		"Content-Type":  {"text/html; charset=utf-8"},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
		"Pragma":        {"no-cache"},
		"Expires":       {"0"},
	}
	errorPageContent := f.generateErrorPageHTML(errCode, f.flowContext.Attempts)

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(200,
		errorPageContent, responseHeaders, -1, "")
}

// handleOauthProviderAuthCallback handles callback->code<->token exchange flow between the plugin and OpenID provider.
func (f *HttpFilter) handleOauthProviderAuthCallback(currentUrl url.URL) (err error) {

	code := currentUrl.Query().Get("code")
	state := currentUrl.Query().Get("state")

	if strings.EqualFold(code, "") || strings.EqualFold(state, "") {
		return fmt.Errorf(`code or state not found in URI`)
	}

	//
	originalUrlFromState, stateValid := utils.ValidateState(f.config.OauthClientSecret, state)
	if !stateValid {
		return StateInvalidError{Reason: "validation failed. Try again from the beginning"}
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
			return fmt.Errorf(`required field empty in code <-> token exchange flow: %s`, reqFieldName)
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
		return fmt.Errorf(`could not create request to token endpoint: %s`, err.Error())
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf(`error calling token endpoint: %s`, err.Error())
	}

	//
	if res.StatusCode > 299 {
		return fmt.Errorf(`token endpoint responded with failure. code: %d - status: %s`, res.StatusCode, res.Status)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf(`could not read response body from token endpoint: %s`, err.Error())
	}

	responseObj := &OauthTokenEndpointResponse{}
	err = json.Unmarshal(resBody, responseObj)
	if err != nil {
		return fmt.Errorf(`failed decoding the response from token endpoint: %s`, err.Error())
	}

	//
	responseHeaders := map[string][]string{
		"Location":      {originalUrlFromState},
		"Cache-Control": {"no-cache, no-store, must-revalidate"},
	}

	// Set the cookies in the user browser
	err = f.setAuthCookies(responseHeaders, responseObj)
	if err != nil {
		return fmt.Errorf("failed setting cookies: %s", err.Error())
	}

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(302, "Redirecting to the original site",
		responseHeaders, -1, "")
	return nil
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
