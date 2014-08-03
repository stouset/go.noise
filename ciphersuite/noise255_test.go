package ciphersuite

import (
	"reflect"
	"testing"

	"github.com/stouset/go.secrets"
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
	pair, err := Noise255.NewKeypair()

	if err != nil {
		t.Error("NewKeypair() = _, err; want nil")
	}

	if pair.Private.Len() != curve25519_privKeyLen {
		t.Errorf(
			"NewKeypair().Private.Len() = %d; want %d",
			pair.Private.Len(),
			curve25519_privKeyLen,
		)
	}

}

func TestNewKeypairPublicKeyLength(t *testing.T) {
	pair, err := Noise255.NewKeypair()

	if err != nil {
		t.Error("NewKeypair() = _, err; want nil")
	}

	if pair.Public.Len() != curve25519_pubKeyLen {
		t.Errorf(
			"NewKeypair().Public.Len() = %d; want %d",
			pair.Public.Len(),
			curve25519_pubKeyLen,
		)
	}

}

func TestNewKeypairPrivateKeyContents(t *testing.T) {
	pair, err := Noise255.NewKeypair()

	if err != nil {
		t.Error("NewKeypair() = _, err; want nil")
	}

	empty, err := secrets.NewSecret(curve25519_privKeyLen)

	if err != nil {
		t.Errorf("NewSecret(%d) = _, err; want nil", curve25519_privKeyLen)
	}

	if pair.Private.Equal(*empty) {
		t.Error(
			"NewKeypair().Private = { 0x00 , ... }; want random",
		)
	}
}

func TestNewKeypairPublicKeyContents(t *testing.T) {
	pair, err := Noise255.NewKeypair()

	if err != nil {
		t.Error("NewKeypair() = _, err; want nil")
	}

	empty, err := secrets.NewSecret(curve25519_pubKeyLen)

	if err != nil {
		t.Errorf("NewSecret(%d) = _, err; want nil", curve25519_pubKeyLen)
	}

	if pair.Public.Equal(*empty) {
		t.Error(
			"NewKeypair().Public = { 0x00 , ... }; want random",
		)
	}
}

func TestNewKeypairKeysDistinct(t *testing.T) {
	pair1, err := Noise255.NewKeypair()

	if err != nil {
		t.Error("NewKeypair() = _, err; want nil")
	}

	pair2, err := Noise255.NewKeypair()

	if err != nil {
		t.Error("NewKeypair() = _, err; want nil")
	}

	if pair1.Private.Equal(pair2.Private.Secret) {
		t.Error(
			"NewKeypair().Private = NewKeypair().private; want random",
		)
	}
}

func TestDH(t *testing.T) {
	var (
		private  = []byte("\xc0\x94\x79\x59\xc2\xfd\x54\x27\xa2\xf3\x9b\xd8\x80\x41\x1d\xfc\x96\xb8\x36\x11\x3d\xbc\x0f\xec\x61\xee\x17\x07\x67\xe3\x7f\x5a")
		public   = []byte("\x1d\x76\x54\xef\xd5\xc2\x01\x23\xa2\x3b\x14\x49\x23\x32\xb4\x87\x58\x68\xcb\x1d\x87\x5c\xd9\x5e\x0c\x35\x1a\xa2\x0f\xb6\x3d\x7c")
		expected = []byte("\x12\xa4\xe0\x6c\x7b\xf4\x45\x39\x53\xa1\xe1\x85\x5c\xe3\x4d\x5d\x33\x0f\x92\xb7\xf7\x19\x63\xaa\xf1\xcb\x59\x5c\x64\x69\xf9\x61")
	)

	var (
		priv, _ = secrets.NewSecretFromBytes(private)
		pub, _  = secrets.NewSecretFromBytes(public)
		exp, _  = secrets.NewSecretFromBytes(expected)
		dh, _   = Noise255.DH(PrivateKey{*priv}, PublicKey{*pub})
		ret     = dh.Equal(*exp)
	)

	if !ret {
		t.Errorf(
			"DH(0x%x, 0x%x) = 0x%x; want 0x%x",
			private,
			public,
			dh,
			expected,
		)
	}
}
