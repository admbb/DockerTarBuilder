package routeros

import "testing"

func TestDecodeLeaseName(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"HYH\xb5\xc4\xd3\xce\xcf\xb7\xbb\xfa", "HYH的游戏机"},
		{"中文设备", "中文设备"},
		{"plain-device", "plain-device"},
	} {
		if got := decodeLeaseName(tt.in); got != tt.want {
			t.Errorf("decodeLeaseName(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}
}
