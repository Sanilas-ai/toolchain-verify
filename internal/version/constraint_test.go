package version

import "testing"

func TestConstraintCheck(t *testing.T) {
	tests := []struct {
		c     string
		match []string
		miss  []string
	}{
		{"", []string{"0.0.1", "99.0.0"}, nil},
		{"*", []string{"1.0.0"}, nil},
		{"any", []string{"1.0.0"}, nil},
		{"1.22.3", []string{"1.22.3"}, []string{"1.22.4", "1.22.2", "1.22.3-rc1"}},
		{"=1.22.3", []string{"1.22.3"}, []string{"1.22.4"}},
		{"==1.22.3", []string{"1.22.3"}, []string{"1.22.4"}},
		{"1.22", []string{"1.22.0", "1.22.9"}, []string{"1.21.9", "1.23.0"}},
		{"1.22.x", []string{"1.22.5"}, []string{"1.23.0"}},
		{"1.*", []string{"1.0.0", "1.99.0"}, []string{"2.0.0", "0.9.0"}},
		{"3", []string{"3.0.0", "3.12.1"}, []string{"4.0.0", "2.7.18"}},
		{">=1.22", []string{"1.22.0", "2.0.0"}, []string{"1.21.99"}},
		{">= 1.22", []string{"1.22.0"}, []string{"1.21.0"}},
		{">1.2.3", []string{"1.2.4"}, []string{"1.2.3"}},
		{">1.2", []string{"1.3.0"}, []string{"1.2.9"}},
		{"<2", []string{"1.99.99"}, []string{"2.0.0"}},
		{"<=1.2.3", []string{"1.2.3"}, []string{"1.2.4"}},
		{"<=1.2", []string{"1.2.99"}, []string{"1.3.0"}},
		{"!=1.2.3", []string{"1.2.4"}, []string{"1.2.3"}},
		{">=1.20, <1.23", []string{"1.20.0", "1.22.9"}, []string{"1.19.9", "1.23.0"}},
		{">=1.20 <1.23", []string{"1.21.0"}, []string{"1.23.0"}},
		{"~1.2.3", []string{"1.2.3", "1.2.9"}, []string{"1.2.2", "1.3.0"}},
		{"~1.2", []string{"1.2.0", "1.2.9"}, []string{"1.3.0"}},
		{"~1", []string{"1.0.0", "1.9.0"}, []string{"2.0.0"}},
		{"^1.2.3", []string{"1.2.3", "1.9.0"}, []string{"1.2.2", "2.0.0"}},
		{"^0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.3.0"}},
		{"^0.0.3", []string{"0.0.3"}, []string{"0.0.4"}},
		{"^0", []string{"0.9.9"}, []string{"1.0.0"}},
		{"^20 || ^22", []string{"20.1.0", "22.11.0"}, []string{"21.0.0", "18.0.0"}},
		{">=2.0.0-rc1", []string{"2.0.0-rc2", "2.0.0"}, []string{"2.0.0-beta", "1.9.9"}},
	}
	for _, tc := range tests {
		c, err := ParseConstraint(tc.c)
		if err != nil {
			t.Errorf("ParseConstraint(%q): %v", tc.c, err)
			continue
		}
		for _, s := range tc.match {
			if !c.Check(mustParse(t, s)) {
				t.Errorf("%q should match %s", tc.c, s)
			}
		}
		for _, s := range tc.miss {
			if c.Check(mustParse(t, s)) {
				t.Errorf("%q should not match %s", tc.c, s)
			}
		}
	}
}

func TestParseConstraintErrors(t *testing.T) {
	for _, s := range []string{
		"abc", ">=", ">= ", "1.x.3", "!=1.2", "1.2 ||", ">=1.2.3.4", "~>1.2", "1.2-rc1", ">*",
	} {
		if _, err := ParseConstraint(s); err == nil {
			t.Errorf("ParseConstraint(%q): want error", s)
		}
	}
}
