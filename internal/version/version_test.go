package version

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"1.2.3", "1.2.3", false},
		{"v1.22", "1.22.0", false},
		{"3", "3.0.0", false},
		{" 2.0.0-beta.1+build5 ", "2.0.0-beta.1", false},
		{"3.13.0rc1", "3.13.0-rc1", false},
		{"1.2.3.4", "", true},
		{"abc", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		v, err := Parse(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("Parse(%q) err = %v, wantErr %v", tc.in, err, tc.err)
			continue
		}
		if !tc.err && v.String() != tc.want {
			t.Errorf("Parse(%q) = %s, want %s", tc.in, v, tc.want)
		}
	}
}

func TestExtract(t *testing.T) {
	tests := map[string]string{
		"go version go1.22.3 linux/amd64":      "1.22.3",
		"v22.11.0\n":                           "22.11.0",
		"Python 3.10.12":                       "3.10.12",
		"Python 3.13.0rc1":                     "3.13.0-rc1",
		"git version 2.34.1":                   "2.34.1",
		"git version 2.39.3 (Apple Git-145)":   "2.39.3",
		"openjdk 21.0.4 2024-07-16 LTS":        "21.0.4",
		"cargo 1.80.0-beta.3 (abc 2024-06-01)": "1.80.0-beta.3",
		"tool 1.2.3-amd64":                     "1.2.3",
		"jq-1.7":                               "1.7.0",
	}
	for in, want := range tests {
		v, err := Extract(in)
		if err != nil {
			t.Errorf("Extract(%q): %v", in, err)
			continue
		}
		if v.String() != want {
			t.Errorf("Extract(%q) = %s, want %s", in, v, want)
		}
	}
	if _, err := Extract("no digits here"); err == nil {
		t.Error("Extract without version: want error")
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-rc.1", "1.0.0-beta.11", 1},
	}
	for _, tc := range tests {
		a, b := mustParse(t, tc.a), mustParse(t, tc.b)
		if got := Compare(a, b); got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := Compare(b, a); got != -tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

func mustParse(t *testing.T, s string) Version {
	t.Helper()
	v, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return v
}
