// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	StateInternalSeparator = "|~|"
)

// GenerateState TODO
func GenerateState(secret string, originalURL string) string {

	// Create payload with timestamp and originalURL
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%d%s%s", timestamp, StateInternalSeparator, originalURL)

	// Create payload HMAC-SHA256 with client_secret
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Combine payload and signature
	state := base64.URLEncoding.EncodeToString([]byte(payload + StateInternalSeparator + signature))
	return state
}

// ValidateState TODO
func ValidateState(secret string, state string) (string, bool) {

	// Decode from base64
	decoded, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return "", false
	}

	//
	stateParts := strings.Split(string(decoded), StateInternalSeparator)
	if len(stateParts) != 3 { // timestamp, url and signature
		return "", false
	}

	// Verify HMAC
	timestamp, originalURL := stateParts[0], stateParts[1]
	expectedSignature := stateParts[2]

	payload := timestamp + StateInternalSeparator + originalURL
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	actualSignature := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expectedSignature), []byte(actualSignature)) {
		return "", false
	}

	// Verify timestamp (less than 10 minutes)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "", false
	}

	if time.Now().Unix()-ts > 600 { // 10 minutes
		return "", false
	}

	return originalURL, true
}

// GetRequestURL TODO
func GetRequestURL(headerMap map[string][]string) url.URL {

	scheme := "https"
	headerXForwardedProto, headerFound := headerMap["x-forwarded-proto"]
	if headerFound && len(headerXForwardedProto) != 0 {
		scheme = headerXForwardedProto[0]
	}

	//
	host := ""
	headerHost, headerFound := headerMap["host"]
	if headerFound && len(headerHost) != 0 {
		host = headerHost[0]
	}

	headerHost, headerFound = headerMap[":authority"] // HTTP/2
	if headerFound && len(headerHost) != 0 {
		host = headerHost[0]
	}

	//
	path := ""
	headerPath, headerFound := headerMap[":path"]
	if headerFound && len(headerPath) != 0 {
		path = headerPath[0]
	}

	pathParts := strings.SplitN(path, "?", 2)

	tmpUri := url.URL{
		Scheme: scheme,
		Host:   host,
	}

	if len(pathParts) == 2 {
		tmpUri.Path = pathParts[0]
		tmpUri.RawQuery = pathParts[1]
	}

	if len(pathParts) == 1 {
		tmpUri.Path = pathParts[0]
	}

	return tmpUri
}
