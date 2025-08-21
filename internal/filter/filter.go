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
	"log"
	"log/slog"
	"os"
	"regexp"
	//
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	cfg "oauthep/internal/config"
	"oauthep/internal/utils"
)

type HttpFilter struct {
	// Implement Decoder and Encoder filters at once
	api.StreamFilter

	//
	callbacks api.FilterCallbackHandler
	config    cfg.Configuration

	// Extra carried stuff
	logger                           *slog.Logger
	compiledExcludedPathsExpressions []*regexp.Regexp
}

func NewStreamFilter(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {

	config, ok := c.(*cfg.Configuration)
	if !ok {
		log.Fatalf("Unexpected configuration provided")
	}

	// Configure the logger
	var handler slog.Handler
	switch config.LogFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	default:
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	}

	// Precompile path regular expressions
	// Failed expressions will be ignored
	compiledRegex := make([]*regexp.Regexp, 0, len(config.SkipAuthRegex))

	for _, pattern := range config.SkipAuthRegex {
		if re, err := regexp.Compile(pattern); err == nil {
			compiledRegex = append(compiledRegex, re)
		}
	}

	//
	streamFilter := &HttpFilter{
		callbacks: callbacks,
		config:    *config,

		//
		compiledExcludedPathsExpressions: compiledRegex,
		logger:                           slog.New(handler),
	}

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

	defer f.logHeaders(reqHeaderMap)

	// 1. Check excluded paths
	requestURL := utils.GetRequestURL(reqHeaderMap.GetAllHeaders())
	if f.shouldSkipPath(requestURL.Path) {
		return api.Continue
	}

	// 2. Handle logout
	if requestURL.Path == f.config.LogoutPath {
		f.handleLogout()
		return api.Continue
	}

	// 3. Handle OAuth callback
	if requestURL.Path == f.config.CallbackPath {
		f.handleOAuthProviderAuthCallback(requestURL)
		return api.Continue
	}

	// 4. Validate JWT
	isAuthenticated, err := f.isRequestAuthenticated(reqHeaderMap)
	if err != nil {
		log.Print("failed checking request authentication: ", err.Error())
	}

	if isAuthenticated {
		return api.Continue
	}

	// 5. Redirect to OAuth if not authenticated
	f.redirectToOAuthProvider(requestURL)
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
	//log.Print("RESPUESTA: ", respHeaders.GetAllHeaders())
}

func (f *HttpFilter) OnDestroy(reason api.DestroyReason) {}
func (f *HttpFilter) OnStreamComplete()                  {}
