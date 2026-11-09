package toolcall

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Status of a Parse.
const (
	StatusOK            = "ok"
	StatusNoCall        = "no_call"
	StatusTruncated     = "truncated"
	StatusInvalidJSON   = "invalid_json"
	StatusSchema        = "schema"
	StatusDisallowed    = "disallowed_tool"
	StatusSensitiveDeny = "sensitive_denied"
	StatusLimits        = "limits"
	StatusHiddenUnicode = "hidden_unicode"
	StatusExfil         = "exfil"
	StatusDescMismatch  = "description_mismatch"
	StatusParseError    = "parse_error"
)

// Call is one validated tool invocation.
type Call struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
	Class     string                 `json:"class,omitempty"`
	Raw       string                 `json:"raw,omitempty"`
}

// ModelError is a structured message suitable to feed back to the model.
type ModelError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	Hint      string `json:"hint,omitempty"`
}

// String renders a compact feedback line for the tool role.
func (e ModelError) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "toolcall error [%s]: %s", e.Code, e.Message)
	if e.Hint != "" {
		fmt.Fprintf(&b, " (%s)", e.Hint)
	}
	if e.Retryable {
		b.WriteString(" [retryable]")
	}
	return b.String()
}

// Result is the outcome of Parse. Only the first complete valid call is kept.
type Result struct {
	Status          string      `json:"status"`
	Call            *Call       `json:"call,omitempty"`
	TrailingJunk    bool        `json:"trailing_junk"`
	TrailingPreview string      `json:"trailing_preview,omitempty"`
	DroppedBytes    int         `json:"dropped_bytes,omitempty"`
	HiddenUnicode   []string    `json:"hidden_unicode,omitempty"`
	StopSequences   []string    `json:"stop_sequences,omitempty"`
	ProfileID       string      `json:"profile_id,omitempty"`
	ModelError      *ModelError `json:"model_error,omitempty"`
	RetryBudget     int         `json:"retry_budget,omitempty"`
	Approved        bool        `json:"approved,omitempty"`
}

// Feedback returns the model-facing error string, or "" on success.
func (r *Result) Feedback() string {
	if r.ModelError == nil {
		return ""
	}
	return r.ModelError.String()
}

func fail(code, msg, hint string, retryable bool, budget int) *Result {
	return &Result{
		Status: code,
		ModelError: &ModelError{
			Code:      code,
			Message:   msg,
			Retryable: retryable,
			Hint:      hint,
		},
		RetryBudget: budget,
	}
}

// MarshalJSON keeps Call.Arguments object-shaped even when empty.
func (c Call) MarshalJSON() ([]byte, error) {
	type alias Call
	a := alias(c)
	if a.Arguments == nil {
		a.Arguments = map[string]interface{}{}
	}
	return json.Marshal(a)
}
