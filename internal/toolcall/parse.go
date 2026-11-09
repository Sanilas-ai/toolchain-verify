package toolcall

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Parse takes raw model generation, keeps the FIRST complete valid tool call,
// and discards the rest. Model output is treated as untrusted.
func Parse(ctx context.Context, input string, opt Options) *Result {
	opt.Normalize()
	budget := opt.Limits.MaxRetries
	res := &Result{
		StopSequences: append([]string{}, opt.Profile.StopSequences...),
		ProfileID:     opt.Profile.ID,
		RetryBudget:   budget,
	}

	if len(input) > opt.Limits.MaxInputBytes {
		return fail(StatusLimits, fmt.Sprintf("input larger than %d bytes", opt.Limits.MaxInputBytes), "truncate generation", true, budget)
	}

	hits := ScanHidden(input)
	cleaned := input
	if len(hits) > 0 {
		res.HiddenUnicode = describeHidden(hits)
		cleaned = StripHidden(input)
	}

	raw, trailing, err := extractFirst(opt.Profile.Format, cleaned)
	if err != nil {
		switch {
		case errors.Is(err, errNoCall):
			res.Status = StatusNoCall
			res.ModelError = &ModelError{Code: StatusNoCall, Message: "no complete tool call found", Retryable: true, Hint: "emit one call using the profile delimiters then stop"}
			return res
		case errors.Is(err, errTruncated):
			res.Status = StatusTruncated
			res.ModelError = &ModelError{Code: StatusTruncated, Message: "tool call truncated before closing delimiter", Retryable: true, Hint: "finish the call then stop"}
			return res
		case errors.Is(err, errInvalidJSON):
			res.Status = StatusInvalidJSON
			res.ModelError = &ModelError{Code: StatusInvalidJSON, Message: err.Error(), Retryable: true, Hint: "emit valid JSON arguments"}
			return res
		default:
			res.Status = StatusParseError
			res.ModelError = &ModelError{Code: StatusParseError, Message: err.Error(), Retryable: true}
			return res
		}
	}
	if trailing {
		res.TrailingJunk = true
		rest := strings.TrimSpace(cleaned[raw.End:])
		res.DroppedBytes = len(rest)
		if len(rest) > 120 {
			rest = rest[:120] + "…"
		}
		res.TrailingPreview = rest
	}
	if len(hits) > 0 {
		// hidden unicode in a call is never executed
		res.Status = StatusHiddenUnicode
		res.ModelError = &ModelError{
			Code:      StatusHiddenUnicode,
			Message:   "hidden Unicode (tags/bidi/zero-width) in model output",
			Retryable: true,
			Hint:      "re-emit the call with plain ASCII/UTF-8 text only",
		}
		res.Call = &Call{Name: raw.Name, Arguments: raw.Arguments, Raw: raw.Raw} // for diagnostics only
		return res
	}

	spec, ok := findTool(opt.Tools, raw.Name)
	if !ok {
		res.Status = StatusDisallowed
		res.ModelError = &ModelError{
			Code:      StatusDisallowed,
			Message:   fmt.Sprintf("tool %q is not in the per-task allowlist", raw.Name),
			Retryable: true,
			Hint:      "call only an allowlisted tool name",
		}
		return res
	}
	if spec.DescriptionSHA256 != "" {
		got := HashDescription(spec.Description)
		if got != spec.DescriptionSHA256 {
			res.Status = StatusDescMismatch
			res.ModelError = &ModelError{
				Code:      StatusDescMismatch,
				Message:   fmt.Sprintf("tool %q description hash mismatch (possible rug-pull / MCP poisoning)", raw.Name),
				Retryable: false,
				Hint:      "refuse; refresh the pinned description hash after human review",
			}
			return res
		}
	}
	class := spec.Class
	if class == "" {
		class = "safe"
	}
	// Never allow eval/shell via argument tricks: class wins.
	if class == "eval" || class == "shell" {
		// still go through the gate; never auto-run
	}

	if err := ValidateArgs(spec.Schema, raw.Arguments, opt.Limits.MaxNesting, opt.Limits.MaxArgBytes); err != nil {
		res.Status = StatusSchema
		res.ModelError = &ModelError{
			Code:      StatusSchema,
			Message:   err.Error(),
			Retryable: true,
			Hint:      "fix arguments to match the tool JSON Schema",
		}
		return res
	}

	call := Call{Name: raw.Name, Arguments: raw.Arguments, Class: class, Raw: raw.Raw}

	if opt.CheckExfil {
		if hit := detectExfil(call.Arguments); hit != "" {
			res.Status = StatusExfil
			res.Call = &call
			res.ModelError = &ModelError{
				Code:      StatusExfil,
				Message:   "argument looks like secret/.env exfiltration: " + hit,
				Retryable: false,
				Hint:      "do not pass secrets, .env contents or private keys into tools",
			}
			return res
		}
	}

	if IsSensitive(class) {
		ok, err := opt.Approver.Approve(ctx, call)
		if err != nil {
			res.Status = StatusSensitiveDeny
			res.Call = &call
			res.ModelError = &ModelError{
				Code:      StatusSensitiveDeny,
				Message:   "sensitive tool requires human confirmation: " + err.Error(),
				Retryable: false,
			}
			return res
		}
		if !ok {
			res.Status = StatusSensitiveDeny
			res.Call = &call
			res.ModelError = &ModelError{
				Code:      StatusSensitiveDeny,
				Message:   fmt.Sprintf("sensitive tool %q (class %s) denied (no tty approval)", call.Name, class),
				Retryable: false,
				Hint:      "human must type 'yes' on /dev/tty",
			}
			return res
		}
		res.Approved = true
	}

	res.Status = StatusOK
	res.Call = &call
	res.ModelError = nil
	return res
}

func findTool(tools []ToolSpec, name string) (ToolSpec, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return ToolSpec{}, false
}
