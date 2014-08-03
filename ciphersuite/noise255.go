package ciphersuite

import "github.com/stouset/go.secrets"

var Noise255 = &noise255{
	ciphersuite{
		name:   [24]byte{'N', 'o', 'i', 's', 'e', '2', '5', '5'},
		dhLen:  curve25519_dhLen,
		macLen: poly1305_macLen,
		ccLen:  40,
		cvLen:  48,
	},
}

type noise255 struct{ ciphersuite }

func (n *noise255) NewKeypair() (*Keypair, error) {
	var (
		privKey *secrets.Secret
		pubKey  *secrets.Secret
		err     error
	)

	privKey, err = secrets.NewSecret(curve25519_privKeyLen)

	if err != nil {
		return nil, err
	}

	pubKey, err = secrets.NewSecret(curve25519_pubKeyLen)

	if err != nil {
		return nil, err
	}

	privKey.Write()
	defer privKey.Lock()

	pubKey.Write()
	defer pubKey.Lock()

	noise_curve25519_keypair(
		privKey.Slice(),
		pubKey.Slice(),
	)

	return &Keypair{
		Private: PrivateKey{*privKey},
		Public:  PublicKey{*pubKey},
	}, nil
}

func (n *noise255) DH(
	privKey PrivateKey,
	pubKey PublicKey,
) (
	*SymmetricKey,
	error,
) {
	dh, err := secrets.NewSecret(curve25519_dhLen)

	if err != nil {
		return nil, err
	}

	privKey.Read()
	defer privKey.Lock()

	pubKey.Read()
	defer pubKey.Lock()

	dh.Write()
	defer dh.Lock()

	noise_curve25519_dh(
		dh.Slice(),
		privKey.Slice(),
		pubKey.Slice(),
	)

	return &SymmetricKey{*dh}, err
}

func (n *noise255) Encrypt(
	cc CipherContext,
	plaintext []byte,
	authtext []byte,
) []byte {
	cc.ReadWrite()
	defer cc.Lock()

	return noise_chacha20poly1305_encrypt(
		cc.Slice(),
		plaintext,
		authtext,
	)
}

func (n *noise255) Decrypt(
	cc CipherContext,
	ciphertext []byte,
	authtext []byte,
) ([]byte, error) {
	cc.ReadWrite()
	defer cc.Lock()

	return noise_chacha20poly1305_decrypt(
		cc.Slice(),
		ciphertext,
		authtext,
	)
}
