package file

import "testing"

func TestGlobIsBlackIPUsesTrimmedIndex(t *testing.T) {
	global := &Glob{BlackIpList: []string{" 192.0.2.10 ", "2001:db8::10"}}
	global.RebuildBlackIPSet()

	tests := []struct {
		name string
		addr string
		want bool
	}{
		{name: "ipv4 with port", addr: "192.0.2.10:54321", want: true},
		{name: "ipv4 not listed", addr: "192.0.2.11:54321", want: false},
		{name: "ipv6 with port", addr: "[2001:db8::10]:54321", want: true},
		{name: "ipv6 not listed", addr: "[2001:db8::11]:54321", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := global.IsBlackIP(tt.addr); got != tt.want {
				t.Fatalf("IsBlackIP(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}
