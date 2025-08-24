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
	"encoding/json"
	"log"
	"log/slog"
	"net"
	"os"
	"regexp"

	//
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
	cfg "oauthep/internal/config"
	"oauthep/internal/utils"
)

var (
	LogLevelMap = map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}
)

type HttpFilter struct {
	// Implement Decoder and Encoder filters at once
	api.StreamFilter

	//
	callbacks api.FilterCallbackHandler
	config    cfg.Configuration
	logger    *slog.Logger

	// Extra carried stuff
	trustedProxiesCidrs              []*net.IPNet
	skipAuthCidrs                    []*net.IPNet
	compiledExcludedPathsExpressions []*regexp.Regexp
	celPrograms                      []*cel.Program
}

func NewStreamFilter(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {

	log.Print("NewStreamFilter function executed")

	streamFilter := &HttpFilter{}

	//
	config, ok := c.(*cfg.Configuration)
	if !ok {
		log.Fatalf("Unexpected configuration provided")
	}

	// Configure the logger
	var handler slog.Handler
	logLevel, logLevelFound := LogLevelMap[config.LogLevel]
	if !logLevelFound {
		logLevel = slog.LevelInfo
	}

	switch config.LogFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	default:
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	logger := slog.New(handler).With("plugin-call", uuid.New())

	// Parse all CIDRs from config
	trustedProxiesCidrs, err := utils.GetParsedCidrs(config.TrustedProxies)
	if err != nil {
		logger.Error("failed parsing trusted_proxies CIDRs", "error", err.Error())
		os.Exit(1)
	}

	skipAuthCidrs, err := utils.GetParsedCidrs(config.SkipAuthCidr)
	if err != nil {
		logger.Error("failed parsing skip_auth_cidr CIDRs", "error", err.Error())
		os.Exit(1)
	}

	// Precompile path regular expressions
	// Failed expressions will be ignored
	compiledRegex := make([]*regexp.Regexp, 0, len(config.SkipAuthRegex))

	for _, pattern := range config.SkipAuthRegex {
		if re, err := regexp.Compile(pattern); err == nil {
			compiledRegex = append(compiledRegex, re)
		}
	}

	// Precompile and check CEL expressions to fail-fast and safe resources.
	// They will be truly used later.
	allowConditionsEnv, err := cel.NewEnv(
		cel.Variable("payload", cel.DynType),
	)
	if err != nil {
		logger.Error("cel environment creation error", "error", err.Error())
		os.Exit(1)

	}

	for _, allowCondition := range config.OauthClaimAllowConditions {

		// Compile and prepare the expressions
		ast, issues := allowConditionsEnv.Compile(allowCondition.Expression)
		if issues != nil && issues.Err() != nil {
			logger.Error("cel expression compilation exited with error", "error", issues.Err())
			os.Exit(1)
		}

		prg, err := allowConditionsEnv.Program(ast)
		if err != nil {
			logger.Error("cel program construction error", "error", err.Error())
			os.Exit(1)
		}
		_ = prg
		streamFilter.celPrograms = append(streamFilter.celPrograms, &prg)
	}

	//
	streamFilter.callbacks = callbacks
	streamFilter.config = *config
	streamFilter.logger = logger
	streamFilter.trustedProxiesCidrs = trustedProxiesCidrs
	streamFilter.skipAuthCidrs = skipAuthCidrs
	streamFilter.compiledExcludedPathsExpressions = compiledRegex

	// Some configuration params can be expanded by using Env or SDS.
	// This can only happen on runtime after initializing the filter.
	// This is the moment, bruh.
	streamFilter.expandConfigurationPlaceholders()

	return streamFilter
}

////////////////////////////
// REQUEST PATH
////////////////////////////

func (f *HttpFilter) DecodeHeaders(reqHeaderMap api.RequestHeaderMap, endStream bool) api.StatusType {
	allHeaders := reqHeaderMap.GetAllHeaders()

	// 1. Check excluded CIDRs
	headerXForwardedFor, _ := allHeaders["x-forwarded-for"]
	shouldSkipIp, err := f.shouldSkipAuthFromIp(headerXForwardedFor)
	if err != nil {
		f.logger.Error("failed to determine client IP for auth bypass check",
			"error", err.Error(),
			"xff_header", headerXForwardedFor,
			"trusted_proxies_mode", f.config.TrustedProxiesMode)
	}

	if shouldSkipIp {
		f.logger.Debug("skipping authentication for trusted client IP",
			"trusted_proxies_mode", f.config.TrustedProxiesMode)
		return api.Continue
	}

	// 2. Check excluded paths
	requestURL := utils.GetRequestURL(allHeaders)
	if f.shouldSkipFromPath(requestURL.Path) {
		return api.Continue
	}

	// 3. Handle logout
	if requestURL.Path == f.config.LogoutPath {
		f.handleLogout()
		return api.Continue
	}

	// 4. Handle OAuth callback
	if requestURL.Path == f.config.CallbackPath {
		f.handleOauthProviderAuthCallback(requestURL)
		return api.Continue
	}

	// 5. Validate the token
	err = f.checkRequestAuthentication(reqHeaderMap)
	if err != nil {
		f.logger.Error("failed checking request authentication", "error", err.Error())
	}

	if err == nil {
		return api.Continue
	}

	// 6. Redirect to OAuth if not authenticated
	f.handleOauthProviderRedirection(requestURL)
	return api.Continue
}

func (f *HttpFilter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	return api.Continue
}

func (f *HttpFilter) DecodeTrailers(trailers api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

////////////////////////////
// RESPONSE PATH
////////////////////////////

func (f *HttpFilter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	storedValues := f.callbacks.StreamInfo().DynamicMetadata().Get("oauthep")

	newTokensValueRaw, newTokensFound := storedValues["new_tokens"]
	if !newTokensFound {
		f.logger.Debug("metadata: new_tokens not found, skipping cookie setting")
		return api.Continue
	}

	if newTokensValueRaw == nil {
		f.logger.Debug("metadata: new_tokens value is nil")
		return api.Continue
	}

	newTokensValue, assertOk := newTokensValueRaw.(string)
	if !assertOk {
		f.logger.Error("metadata: failed to cast 'new_tokens' to string")
		return api.Continue
	}

	newTokensObj := &OauthTokenEndpointResponse{}
	err := json.Unmarshal([]byte(newTokensValue), newTokensObj)
	if err != nil {
		f.logger.Error("failed to decode 'new_tokens' into OauthTokenEndpointResponse object")
		return api.Continue
	}

	responseHeaders := map[string][]string{}
	err = f.setAuthCookies(responseHeaders, newTokensObj)
	if err != nil {
		f.logger.Error("failed setting auth cookies", "error", err.Error())
		return api.Continue
	}

	for _, headerValue := range responseHeaders[utils.CookieResponseHeaderName] {
		header.Add(utils.CookieResponseHeaderName, headerValue)
	}

	return api.Continue
}

func (f *HttpFilter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	return api.Continue
}

func (f *HttpFilter) EncodeTrailers(trailers api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

////////////////////////////
// NOT IMPLEMENTED
////////////////////////////

func (f *HttpFilter) OnLog(reqHeaders api.RequestHeaderMap, reqTrailers api.RequestTrailerMap,
	respHeaders api.ResponseHeaderMap, respTrailers api.ResponseTrailerMap) {
	f.logHeaders(reqHeaders, respHeaders)
}

func (f *HttpFilter) OnDestroy(reason api.DestroyReason) {}
func (f *HttpFilter) OnStreamComplete()                  {}
