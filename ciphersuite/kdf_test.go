package ciphersuite

import (
	"github.com/stouset/go.secrets"
	"testing"
)

var testVectors = []struct {
	secret []byte
	extra  []byte
	info   []byte
	outLen int

	out []byte
}{
	{
		[]byte{},
		[]byte{},
		[]byte{},
		8,
		[]byte("\x39\xa9\x19\x6f\x32\xae\xe7\x39"),
	}, {
		[]byte{0x00},
		[]byte{0x00},
		[]byte{0x00},
		8,
		[]byte("\xc4\x90\xf6\xe4\x6a\xe8\x1a\xbb"),
	}, {
		[]byte{0x00},
		[]byte{0x00},
		[]byte{0x00},
		16,
		[]byte("\xc4\x90\xf6\xe4\x6a\xe8\x1a\xbb\x59\x01\x32\xc6\xf1\x40\xb3\x7e"),
	}, {
		[]byte("secret"),
		[]byte("extra"),
		[]byte("info"),
		8,
		[]byte("\xad\x5c\x1b\x3f\x13\xce\x4b\x45"),
	}, {
		[]byte("\xff\xff\xff\xff"),
		[]byte("\xee\xee\xee\xee"),
		[]byte("\xdd\xdd\xdd\xdd"),
		128,
		[]byte("\x8d\x60\xe9\x6a\x29\xb6\x96\x2f\xf4\x59\xea\xf0\x5a\x3e\xd2\xf1\x82\x80\x63\xc6\xee\x93\x66\x2d\x89\xab\xb2\xff\x56\xb6\x97\xd2\x78\x27\xbe\x44\xf9\xc4\xab\xad\x58\x0d\x4f\xfe\x86\x68\x80\xba\xb4\xbd\x5f\xc1\xa3\xec\xd9\x48\xa3\x24\x35\xa2\xde\x5e\xab\x1d\x76\x86\xc2\x3c\x4f\xf9\x88\xc1\xf8\x1d\x10\xe8\x94\x41\x8e\xe2\x5a\xa8\x59\xaf\xad\x08\xea\x4f\xfe\x5f\x5c\x66\x91\x13\xde\x4a\x75\xc9\x16\xd3\x9e\x72\x67\x8b\x7f\x04\x10\x4b\x0c\x66\x34\xcc\x37\x1a\xe7\x0e\x8d\x4a\x46\x9d\x1f\x54\xe6\x9e\xf7\x33\x63\x3b"),
	}, {
		[]byte("\x00\x01\x02\x03"),
		[]byte("\x04\x05\x06\x07"),
		[]byte("\x08\x09\x0a\x0b"),
		3,
		[]byte("\x47\x5a\xae"),
	},
}

func TestKdfTestVectors(t *testing.T) {
	for _, test := range testVectors {
		var (
			secret, _ = secrets.NewSecretFromBytes(test.secret)
			extra, _  = secrets.NewSecretFromBytes(test.extra)
			out, _    = secrets.NewSecretFromBytes(test.out)
		)

		key, err := kdf(
			*secret,
			*extra,
			test.info,
			test.outLen,
		)

		if err != nil {
			secret.Read()
			extra.Read()
			key.Read()
			out.Read()

			t.Errorf(
				"kdf(0x%x, 0x%x, 0x%x, %d) = _, err; want nil",
				secret.Slice(),
				extra.Slice(),
				test.info,
				test.outLen,
			)
		}

		if !key.Equal(*out) {
			secret.Read()
			extra.Read()
			key.Read()
			out.Read()

			t.Errorf(
				"kdf(0x%x, 0x%x, 0x%x, %d) = 0x%x, _; want 0x%x",
				secret.Slice(),
				extra.Slice(),
				test.info,
				test.outLen,
				key.Slice(),
				out.Slice(),
			)
		}
	}
}
