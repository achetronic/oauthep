package filter

import "fmt"

const (
	// Special error codes
	ErrorCodeNoErrorFound       = 0 // No error, what the hell are you doing here?
	ErrorCodeDifferentErrorLoop = 1 // Too many different errors in a sort time window

	// Callback errors
	ErrorCodeStateInvalid          = 20 // State validation failed (CSRF)
	ErrorCodeCallbackMalformed     = 28 // OAuth callback parameters missing/invalid
	ErrorCodeProviderCommunication = 29 // Failed communicating with OAuth provider
	ErrorCodeProviderResponse      = 30 // OAuth provider returned error response
	ErrorCodeCookieSet             = 31 // Failed setting authentication cookies

	// Authentication check errors
	ErrorCodeTokenInvalid        = 21 // Token invalid with unrecoverable state: structure, signature, etc
	ErrorCodeClaimsFailed        = 22 // Claims doesn't meet operator conditions
	ErrorCodeMissingCredentials  = 23 // Required authentication cookies not found
	ErrorCodePublicKeysRetrieval = 24 // Failed retrieving public keys (JWKS)
	ErrorCodeRequestMalformed    = 25 // Malformed request (headers, cookies, etc)
	ErrorCodeCELEvaluation       = 26 // CEL program evaluation failed
	ErrorCodeTokenRefresh        = 27 // Token refresh process failed
)

var ErrorCodeMessages = map[int]string{
	// Special error codes
	ErrorCodeNoErrorFound:       "No error found. What are you doing here?",
	ErrorCodeDifferentErrorLoop: "Too many errors in a sort time window",

	// Callback errors
	ErrorCodeStateInvalid:          "Invalid authentication state",
	ErrorCodeCallbackMalformed:     "OAuth callback parameters invalid",
	ErrorCodeProviderCommunication: "OAuth provider communication failed",
	ErrorCodeProviderResponse:      "OAuth provider response error",
	ErrorCodeCookieSet:             "Failed setting authentication cookies",

	// Authentication check errors
	ErrorCodeTokenInvalid:        "Invalid authentication token",
	ErrorCodeClaimsFailed:        "Invalid authentication token claims",
	ErrorCodeMissingCredentials:  "Required authentication cookies not found",
	ErrorCodePublicKeysRetrieval: "Failed retrieving public keys (JWKS)",
	ErrorCodeRequestMalformed:    "Malformed authentication request",
	ErrorCodeCELEvaluation:       "CEL program evaluation failed",
	ErrorCodeTokenRefresh:        "Token refresh failed",
}

////////////////////////////////////////////
// Callback errors
////////////////////////////////////////////

// StateInvalidError TODO
type StateInvalidError struct {
	Reason string
}

func (e StateInvalidError) Error() string {
	return fmt.Sprintf("state invalid: %s", e.Reason)
}

type CallbackMalformedError struct {
	Reason string
}

func (e CallbackMalformedError) Error() string {
	return fmt.Sprintf("callback malformed: %s", e.Reason)
}

type ProviderCommunicationError struct {
	Reason string
}

func (e ProviderCommunicationError) Error() string {
	return fmt.Sprintf("provider communication error: %s", e.Reason)
}

type ProviderResponseError struct {
	Reason string
}

func (e ProviderResponseError) Error() string {
	return fmt.Sprintf("provider response error: %s", e.Reason)
}

type CookieSetError struct {
	Reason string
}

func (e CookieSetError) Error() string {
	return fmt.Sprintf("cookie set error: %s", e.Reason)
}

////////////////////////////////////////////
// Authentication check errors
////////////////////////////////////////////

// TokenInvalidError TODO
type TokenInvalidError struct {
	Reason string
}

func (e TokenInvalidError) Error() string {
	return fmt.Sprintf("token invalid: %s", e.Reason)
}

// ClaimsFailedError TODO
type ClaimsFailedError struct {
	Reason string
}

func (e ClaimsFailedError) Error() string {
	return fmt.Sprintf("claims validation failed: %s", e.Reason)
}

// MissingCredentialsError TODO
type MissingCredentialsError struct {
	Reason string
}

func (e MissingCredentialsError) Error() string {
	return fmt.Sprintf("missing credentials: %s", e.Reason)
}

type JwksRetrievalError struct {
	Reason string
}

func (e JwksRetrievalError) Error() string {
	return fmt.Sprintf("configuration error: %s", e.Reason)
}

type RequestMalformedError struct {
	Reason string
}

func (e RequestMalformedError) Error() string {
	return fmt.Sprintf("request malformed: %s", e.Reason)
}

type CELEvaluationError struct {
	Reason string
}

func (e CELEvaluationError) Error() string {
	return fmt.Sprintf("CEL evaluation error: %s", e.Reason)
}

type TokenRefreshError struct {
	Reason string
}

func (e TokenRefreshError) Error() string {
	return fmt.Sprintf("token refresh error: %s", e.Reason)
}
