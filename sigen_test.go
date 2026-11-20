package sigen

import (
	"bytes"
	"testing"
)

func TestEncryptPassword(t *testing.T) {
	const (
		in   = "setec-astronomy"
		want = "BKfd6tac+QjTvYrff0UzLg=="
	)
	if got := encryptPassword(in); got != want {
		t.Errorf("encryptPassword(%q) = %q, want %q", in, got, want)
	}
}

func TestPkcs7Pad(t *testing.T) {
	tests := []struct {
		in   string
		want []byte
	}{
		{"abc", []byte("abc\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D")},
		{"abcdefghijk", []byte("abcdefghijk\x05\x05\x05\x05\x05")},
		{"abcdefghijklmnop", []byte("abcdefghijklmnop\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")},
	}
	for _, test := range tests {
		got := pkcs7Pad(test.in)
		if !bytes.Equal(got, test.want) {
			t.Errorf("pkcs7Pad(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}
