package flowcontext

import (
	"time"
)

type FlowContextOptions struct {
	PluginCall string

	//
	MaxStoredErrors      int
	MaxFailedAttempts    int
	AttemptWindowMinutes int
}

// FlowContext structure for cookie storage
type FlowContext struct {
	options FlowContextOptions

	//
	Attempts     int          `json:"attempts"`
	FirstAttempt int64        `json:"first_attempt"` // timestamp
	Errors       []ErrorEntry `json:"errors"`        // Max 5, sorted from old -> new
}

type ErrorEntry struct {
	PluginCall string `json:"plugin_call"`
	Code       int    `json:"code"`      // 1, 2, 3, etc
	Timestamp  int64  `json:"timestamp"` // Unix timestamp
}

// AddAttempt TODO
func (ctx *FlowContext) addAttempt() *FlowContext {
	ctx.Attempts++
	if ctx.FirstAttempt == 0 {
		ctx.FirstAttempt = time.Now().Unix()
	}

	return ctx
}

func (ctx *FlowContext) WithOptions(opts *FlowContextOptions) *FlowContext {
	ctx.options = *opts
	return ctx
}

// Reset clears the context
func (ctx *FlowContext) Reset() *FlowContext {
	ctx.Attempts = 0
	ctx.FirstAttempt = 0
	ctx.Errors = []ErrorEntry{}

	return ctx
}

// WithErrorCode sets error code and automatically increments attempts
func (ctx *FlowContext) WithErrorCode(code int) *FlowContext {

	ctx.addAttempt()

	// Add new error in the end (more recent)
	newError := ErrorEntry{
		PluginCall: ctx.options.PluginCall,
		Code:       code,
		Timestamp:  time.Now().Unix(),
	}
	ctx.Errors = append(ctx.Errors, newError)

	// Keep just some of them
	if len(ctx.Errors) > ctx.options.MaxStoredErrors {
		ctx.Errors = ctx.Errors[1:] // Delete the oldest
	}

	return ctx
}

// WithUniqueErrorCode sets error code and automatically increments attempts
// but only if the last error code is different from the one being added
func (ctx *FlowContext) WithUniqueErrorCode(code int) *FlowContext {
	if len(ctx.Errors) > 0 {
		lastError := ctx.Errors[len(ctx.Errors)-1]
		if lastError.Code == code {
			return ctx
		}
	}

	// Different code or first error
	return ctx.WithErrorCode(code)
}

// HasTooManyErrors detects if there are too many errors in the time window
func (ctx *FlowContext) HasTooManyErrors() bool {

	if len(ctx.Errors) < ctx.options.MaxFailedAttempts {
		return false
	}
	now := time.Now().Unix()

	// Check if we have maxErrors within the time window
	errorsInWindow := 0
	for _, errorEntry := range ctx.Errors {
		if now-errorEntry.Timestamp <= int64(ctx.options.AttemptWindowMinutes*60) {
			errorsInWindow++
		}
	}

	return errorsInWindow >= ctx.options.MaxFailedAttempts
}
