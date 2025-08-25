package flowcontext

import (
	"time"
)

const (
	MaxAttempts   = 3
	AttemptWindow = 5 * 60 // 5 minutes in seconds
)

// FlowContext structure for cookie storage
type FlowContext struct {
	Attempts     int          `json:"attempts"`
	FirstAttempt int64        `json:"first_attempt"` // timestamp
	Errors       []ErrorEntry `json:"errors"`        // Max 5, sorted from old -> new
}

type ErrorEntry struct {
	Code      int   `json:"code"`      // 1, 2, 3, etc
	Timestamp int64 `json:"timestamp"` // Unix timestamp
}

// AddAttempt TODO
func (ctx *FlowContext) addAttempt() *FlowContext {
	ctx.Attempts++
	if ctx.FirstAttempt == 0 {
		ctx.FirstAttempt = time.Now().Unix()
	}

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
		Code:      code,
		Timestamp: time.Now().Unix(),
	}
	ctx.Errors = append(ctx.Errors, newError)

	// Keep just 5
	if len(ctx.Errors) > 5 {
		ctx.Errors = ctx.Errors[1:] // Delete the oldest
	}

	return ctx
}

// HasSameErrorLoop detects if there's a loop pattern in recent errors
func (ctx *FlowContext) HasSameErrorLoop() bool {
	if len(ctx.Errors) < 2 {
		return false
	}

	// Check if last 2 errors are the same type
	lastError := ctx.Errors[len(ctx.Errors)-1]
	prevError := ctx.Errors[len(ctx.Errors)-2]

	if lastError.Code == prevError.Code {
		return true
	}

	// Optional: Check if all 3 are the same (more strict)
	if len(ctx.Errors) == 3 {
		firstError := ctx.Errors[0]
		if firstError.Code == lastError.Code && firstError.Code == prevError.Code {
			return true
		}
	}

	return false
}

// HasTooManyErrors detects if there are too many errors in the time window
func (ctx *FlowContext) HasTooManyErrors(maxErrors int, windowSeconds int64) bool {
	if len(ctx.Errors) < maxErrors {
		return false
	}

	now := time.Now().Unix()

	// Check if we have maxErrors within the time window
	errorsInWindow := 0
	for _, errorEntry := range ctx.Errors {
		if now-errorEntry.Timestamp <= windowSeconds {
			errorsInWindow++
		}
	}

	return errorsInWindow >= maxErrors
}
