package hostsec

import "testing"

func TestCompareDebVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1:1.0", "2.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"5.15.0-202.212", "5.15.0-181.191", 1},
		{"5.15.0-202.212", "5.15.0-202", 1},
		{"5.15.0-180.190", "5.15.0-181.191", -1},
		{"2.35-0ubuntu3.8", "2.35-0ubuntu3.10", -1},
		{"1.2.3+dfsg-1", "1.2.3-1", 1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0+", -1},
		{"0", "0~", 1},
		{"6.8.0-124.124~22.04.1", "6.8.0-124.124", -1},
	}
	for _, c := range cases {
		if got := CompareDebVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareDebVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareDebVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareDebVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
