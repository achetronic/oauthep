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

package utils

import (
	"net/http"
	"strings"
	"time"
)

const (
	CookieNameAccessToken  = "access_token"
	CookieNameIdToken      = "id_token"
	CookieNameRefreshToken = "refresh_token"

	//
	CookieRequestHeaderName  = "Cookie"
	CookieResponseHeaderName = "Set-Cookie"
)

var (
	CookiesToHandle = []string{CookieNameAccessToken, CookieNameIdToken, CookieNameRefreshToken}
)

type CookieContent struct {
	Name    string
	Prefix  string
	Payload string

	Domain   string
	Path     string
	Secure   bool
	HttpOnly bool
	SameSite string

	Duration string
}

// CreateCookieContent TODO
func CreateCookieContent(params CookieContent) string {

	cookie := http.Cookie{}

	cookie.Name = params.Prefix + params.Name
	cookie.Value = params.Payload
	cookie.HttpOnly = params.HttpOnly
	cookie.Secure = params.Secure
	cookie.Path = params.Path
	cookie.Domain = params.Domain

	var sameSiteMap = map[string]http.SameSite{
		"Strict": http.SameSiteStrictMode,
		"Lax":    http.SameSiteLaxMode,
		"None":   http.SameSiteNoneMode,
	}

	if sameSite, valid := sameSiteMap[params.SameSite]; valid {
		cookie.SameSite = sameSite
	}

	if params.Duration == "" || strings.HasPrefix(params.Duration, "-") {
		cookie.MaxAge = -1
	} else {
		duration, err := time.ParseDuration(params.Duration)
		if err != nil {
			duration = 5 * 24 * time.Hour // On errors, defaults to 5 days
		}
		cookie.MaxAge = int(duration.Seconds())
	}

	return cookie.String()
}

// ExtractCookieValue TODO
func ExtractCookieValue(cookieHeader, name string) string {
	cookies := strings.Split(cookieHeader, ";")
	for _, cookie := range cookies {
		cookie = strings.TrimSpace(cookie)
		if strings.HasPrefix(cookie, name+"=") {
			return strings.TrimPrefix(cookie, name+"=")
		}
	}
	return ""
}

// GenerateCleanCookiesHeader TODO
func GenerateCleanCookiesHeader(cookieNamePrefix, cookiePath string) (responseHeader []string) {

	// Set the cookies for the user
	cookieContent := CookieContent{
		Prefix: cookieNamePrefix,
		Path:   cookiePath,
	}

	//
	cookiesToDelete := []string{CookieNameAccessToken, CookieNameIdToken, CookieNameRefreshToken}
	for _, cookieName := range cookiesToDelete {
		cookieContent.Name = cookieName
		cookieValue := CreateCookieContent(cookieContent)
		responseHeader = append(responseHeader, cookieValue)
	}

	return responseHeader
}
