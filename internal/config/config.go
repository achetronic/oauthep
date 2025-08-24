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

package config

import (
	"encoding/json"
	"fmt"

	//
	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	ProviderOpenid = "openid"
	ProviderGoogle = "google"
)

var (
	Providers = []string{ProviderOpenid, ProviderGoogle}
)

// Configuration TODO
type Configuration struct {
	// LogFormat represents the format of the logs
	// Possible values are: json, console
	LogFormat string `json:"log_format,omitempty"`

	// LogLevel ...
	LogLevel string `json:"log_level,omitempty"`

	// LogAllHeaders represents a flag to log all the headers or not
	// Disabled by default
	LogAllHeaders bool `json:"log_all_headers,omitempty"`

	// ExcludeLogHeaders represent a list of headers that will be excluded when 'log_all_headers' is enabled
	ExcludeLogHeaders []string `json:"exclude_log_headers,omitempty"`

	//
	TrustedProxiesMode string   `json:"trusted_proxies_mode,omitempty"`
	TrustedProxies     []string `json:"trusted_proxies_cidr,omitempty"`

	// Authentication exclusions
	SkipAuthCidr  []string `json:"skip_auth_cidr,omitempty"`
	SkipAuthRegex []string `json:"skip_auth_regex,omitempty"`

	// TODO: Explain the stuff
	CallbackPath           string `json:"callback_path,omitempty"`
	LogoutPath             string `json:"logout_path,omitempty"`
	LogoutRedirectAfterUri string `json:"logout_redirect_after_uri,omitempty"`

	//
	Provider string `json:"provider,omitempty"`

	//
	OauthAuthUri       string   `json:"oauth_auth_uri"`
	OauthTokenUri      string   `json:"oauth_token_uri"`
	OauthJwksUri       string   `json:"oauth_jwks_uri"`
	OauthJwksCacheTTL  string   `json:"oauth_jwks_cache_ttl,omitempty"`
	OauthJwksCacheFile string   `json:"oauth_jwks_cache_file,omitempty"`
	OauthClientId      string   `json:"oauth_client_id"`
	OauthClientSecret  string   `json:"oauth_client_secret"`
	OauthRedirectUri   string   `json:"oauth_redirect_uri"`
	OauthScopes        []string `json:"oauth_scopes,omitempty"`

	//
	SessionCookiePrefix   string `json:"session_cookie_prefix,omitempty"`
	SessionCookieDomain   string `json:"session_cookie_domain,omitempty"`
	SessionCookiePath     string `json:"session_cookie_path,omitempty"`
	SessionCookieSecure   bool   `json:"session_cookie_secure,omitempty"`
	SessionCookieHttpOnly bool   `json:"session_cookie_httponly,omitempty"`
	SessionCookieSameSite string `json:"session_cookie_samesite,omitempty"`
	SessionCookieDuration string `json:"session_cookie_duration,omitempty"`

	SessionCookieCompressionEnabled bool `json:"session_cookie_compression_enabled,omitempty"`
}

func NewConfigWithDefaults() *Configuration {
	return &Configuration{
		LogFormat:         "json",
		LogLevel:          "info",
		LogAllHeaders:     true,
		ExcludeLogHeaders: []string{},

		//
		TrustedProxiesMode: "default",
		TrustedProxies:     []string{},

		//
		SkipAuthCidr:  []string{},
		SkipAuthRegex: []string{},

		//
		CallbackPath:           "/oauth/callback",
		LogoutPath:             "/oauth/logout",
		LogoutRedirectAfterUri: "/",

		//
		Provider: ProviderOpenid,

		//
		OauthJwksCacheTTL:  "10m",
		OauthJwksCacheFile: "/tmp/jwks_cache.json",
		OauthScopes:        []string{"openid", "profile", "email"},

		//
		SessionCookiePrefix:   "oauthep_",
		SessionCookieDomain:   "",
		SessionCookiePath:     "/",
		SessionCookieSecure:   true,
		SessionCookieHttpOnly: true,
		SessionCookieSameSite: "Lax",
		SessionCookieDuration: "2d",

		SessionCookieCompressionEnabled: true,
	}
}

// ConfigParser TODO
type ConfigParser struct {
	api.StreamFilterConfigParser
}

func (p ConfigParser) Parse(pluginConfig *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {

	// Parse TypedStruct
	var configStruct xds.TypedStruct
	if err := pluginConfig.UnmarshalTo(&configStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TypedStruct: %w", err)
	}

	// Convert protobuf Struct to JSON for easier parsing
	structValue := configStruct.GetValue()
	if structValue == nil {
		return nil, fmt.Errorf("TypedStruct value is nil")
	}

	// Marshal the struct to JSON
	jsonBytes, err := protojson.Marshal(structValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct to JSON: %w", err)
	}

	// Unmarshal JSON to Configuration struct
	configObjWithDefaults := NewConfigWithDefaults()
	if err = json.Unmarshal(jsonBytes, configObjWithDefaults); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return configObjWithDefaults, nil
}

func (p ConfigParser) Merge(parentConfig interface{}, childConfig interface{}) interface{} {
	panic("not implemented")
}
