package toolcall

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Sensitive classes that always require a human on a real TTY.
var sensitiveClasses = map[string]bool{
	"secrets":     true,
	"wallet":      true,
	"file_write":  true,
	"file_delete": true,
	"network":     true,
	"shell":       true,
	"eval":        true,
	"env":         true,
}

// IsSensitive reports whether class needs a human gate.
func IsSensitive(class string) bool {
	return sensitiveClasses[strings.ToLower(strings.TrimSpace(class))]
}

// Approver decides whether a sensitive call may proceed.
type Approver interface {
	Approve(ctx context.Context, c Call) (bool, error)
}

// DenyAll is the non-interactive default (no TTY → deny).
type DenyAll struct{}

// Approve always refuses.
func (DenyAll) Approve(context.Context, Call) (bool, error) { return false, nil }

// AllowAll is for tests only.
type AllowAll struct{}

// Approve always allows.
func (AllowAll) Approve(context.Context, Call) (bool, error) { return true, nil }

// TTY asks on the controlling terminal (not stdin, which an agent may own).
type TTY struct {
	Path    string // default /dev/tty
	Timeout time.Duration
}

// Approve prints the request and waits for an exact "yes".
func (t TTY) Approve(ctx context.Context, c Call) (bool, error) {
	p := t.Path
	if p == "" {
		p = "/dev/tty"
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("no terminal for approval: %w", err)
	}
	defer f.Close()
	argsPreview, _ := jsonPreview(c.Arguments, 240)
	fmt.Fprintf(f, "\n=== toolchain-verify toolcall: approval required ===\n tool : %s\n class: %s\n args : %s\nType 'yes' to allow: ",
		c.Name, c.Class, argsPreview)
	ch := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(f).ReadString('\n')
		ch <- strings.TrimSpace(s)
	}()
	to := t.Timeout
	if to == 0 {
		to = 2 * time.Minute
	}
	select {
	case s := <-ch:
		return s == "yes", nil
	case <-time.After(to):
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func jsonPreview(v interface{}, max int) (string, error) {
	s := PrettyJSON(v)
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s, nil
}
