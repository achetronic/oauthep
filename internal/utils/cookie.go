// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

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
	CookieNameContext      = "context"

	//
	CookieRequestHeaderName  = "Cookie"
	CookieResponseHeaderName = "Set-Cookie"
)

var (
	CookiesToHandle = []string{CookieNameAccessToken, CookieNameIdToken, CookieNameRefreshToken, CookieNameContext}
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
// TODO: Refactor this to do it make more sense being here
func GenerateCleanCookiesHeader(cookieNamePrefix, cookiePath string) (responseHeader []string) {

	// Set the cookies for the user
	cookieContent := CookieContent{
		Prefix: cookieNamePrefix,
		Path:   cookiePath,
	}

	//
	for _, cookieName := range CookiesToHandle {
		cookieContent.Name = cookieName
		cookieValue := CreateCookieContent(cookieContent)
		responseHeader = append(responseHeader, cookieValue)
	}

	return responseHeader
}
