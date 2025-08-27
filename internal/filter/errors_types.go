package filter

import "fmt"

const (
	// Special error codes
	ErrorCodeNoErrorFound       = 0 // No error, what the hell are you doing here?
	ErrorCodeDifferentErrorLoop = 1 // Too many different errors in a sort time window

	// Auth flow specific error codes
	ErrorCodeStateInvalid = 20 // State validation failed (CSRF)
	ErrorCodeTokenInvalid = 21 // Token invalid with unrecoverable state: structure, signature, etc
	ErrorCodeClaimsFailed = 22 // Claims doesn't meet operator conditions
)

var ErrorCodeMessages = map[int]string{
	//
	ErrorCodeNoErrorFound:       "No error found. What are you doing here?",
	ErrorCodeDifferentErrorLoop: "Too many errors in a sort time window",

	//
	ErrorCodeStateInvalid: "Invalid authentication state",
	ErrorCodeTokenInvalid: "Invalid authentication token",
	ErrorCodeClaimsFailed: "Invalid authentication token claims",
}

type StateInvalidError struct {
	Reason string
}

func (e StateInvalidError) Error() string {
	return fmt.Sprintf("state invalid: %s", e.Reason)
}

type TokenInvalidError struct {
	Reason string
}

func (e TokenInvalidError) Error() string {
	return fmt.Sprintf("token invalid: %s", e.Reason)
}

type ClaimsFailedError struct {
	Reason string
}

func (e ClaimsFailedError) Error() string {
	return fmt.Sprintf("claims validation failed: %s", e.Reason)
}
