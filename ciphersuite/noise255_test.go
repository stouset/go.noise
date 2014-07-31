package ciphersuite

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNoise255ImplementsCiphersuite(t *testing.T) {
	var (
		noise255    = reflect.TypeOf(Noise255)
		ciphersuite = reflect.TypeOf((*Ciphersuite)(nil)).Elem()
	)

	if !noise255.Implements(ciphersuite) {
		t.Error("Noise255 doesn't implement the Ciphersuite interface")
	}
}

func TestNewKeypairPrivateKeyLength(t *testing.T) {
	pair := Noise255.NewKeypair()

	if len(pair.Private) != curve25519_privKeyLen {
		t.Errorf(
			"len(NewKeypair().Private) = %d; want %d",
			len(pair.Private),
			curve25519_privKeyLen,
		)
	}

}

func TestNewKeypairPublicKeyLength(t *testing.T) {
	pair := Noise255.NewKeypair()

	if len(pair.Public) != curve25519_pubKeyLen {
		t.Errorf(
			"len(NewKeypair().Public) = %d; want %d",
			len(pair.Public),
			curve25519_pubKeyLen,
		)
	}

}

func TestNewKeypairPrivateKeyContents(t *testing.T) {
	var (
		pair  = Noise255.NewKeypair()
		empty = make([]byte, curve25519_privKeyLen)
	)

	if bytes.Equal(pair.Private, empty) {
		t.Error(
			"NewKeypair().Private = { 0x00 , ... }; want random",
		)
	}
}

func TestNewKeypairPublicKeyContents(t *testing.T) {
	var (
		pair  = Noise255.NewKeypair()
		empty = make([]byte, curve25519_pubKeyLen)
	)

	if bytes.Equal(pair.Public, empty) {
		t.Error(
			"NewKeypair().Public = { 0x00 , ... }; want random",
		)
	}
}

func TestNewKeypairKeysDistinct(t *testing.T) {
	pair := Noise255.NewKeypair()

	if bytes.Equal(pair.Private, pair.Public) {
		t.Error(
			"NewKeypair().Public = NewKeypair().private; want random",
		)
	}
}

func TestDH(t *testing.T) {
	var (
		private  = []byte("\xc0\x94\x79\x59\xc2\xfd\x54\x27\xa2\xf3\x9b\xd8\x80\x41\x1d\xfc\x96\xb8\x36\x11\x3d\xbc\x0f\xec\x61\xee\x17\x07\x67\xe3\x7f\x5a")
		public   = []byte("\x1d\x76\x54\xef\xd5\xc2\x01\x23\xa2\x3b\x14\x49\x23\x32\xb4\x87\x58\x68\xcb\x1d\x87\x5c\xd9\x5e\x0c\x35\x1a\xa2\x0f\xb6\x3d\x7c")
		expected = []byte("\x12\xa4\xe0\x6c\x7b\xf4\x45\x39\x53\xa1\xe1\x85\x5c\xe3\x4d\x5d\x33\x0f\x92\xb7\xf7\x19\x63\xaa\xf1\xcb\x59\x5c\x64\x69\xf9\x61")
	)

	dh := Noise255.DH(private, public)

	if !bytes.Equal(dh, expected) {
		t.Errorf(
			"DH(0x%x, 0x%x) = 0x%x; want 0x%x",
			private,
			public,
			dh,
			expected,
		)
	}
}
