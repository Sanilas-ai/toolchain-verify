package pipeline

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Subject is who is asking. It is written on the mediator line.
type Subject struct {
	UID       int    `json:"uid"`
	Container bool   `json:"container"`
	Repo      string `json:"repo,omitempty"`
	Session   string `json:"session,omitempty"`
}

// Allows reports whether current may receive an allow. An empty list does
// not add a subject gate. A non-empty list allows only an equal uid,
// container flag and repo. Session is recorded and is not part of the match.
func Allows(current Subject, list []Subject) bool {
	if len(list) == 0 {
		return true
	}
	for _, a := range list {
		if a.UID == current.UID && a.Container == current.Container && samePath(a.Repo, current.Repo) {
			return true
		}
	}
	return false
}

// ParseSubject parses "uid=1,container=true,repo=/work".
func ParseSubject(s string) (Subject, error) {
	var out Subject
	var sawUID, sawContainer bool
	for _, part := range strings.Split(s, ",") {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || key == "" {
			return Subject{}, fmt.Errorf("bad subject %q", s)
		}
		switch key {
		case "uid":
			n, err := strconv.Atoi(val)
			if err != nil {
				return Subject{}, fmt.Errorf("bad uid %q", val)
			}
			out.UID = n
			sawUID = true
		case "container":
			out.Container = val == "true" || val == "1"
			sawContainer = true
		case "repo":
			out.Repo = val
		case "session":
			out.Session = val
		default:
			return Subject{}, fmt.Errorf("unknown subject field %q", key)
		}
	}
	if !sawUID || !sawContainer || out.Repo == "" {
		return Subject{}, fmt.Errorf("subject needs uid, container and repo")
	}
	return out, nil
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
