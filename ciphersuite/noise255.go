package ciphersuite

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

func (n *noise255) NewKeypair() Keypair {
	var keypair = Keypair{
		Private: make([]byte, curve25519_privKeyLen),
		Public:  make([]byte, curve25519_pubKeyLen),
	}

	noise_curve25519_keypair(keypair.Private, keypair.Public)

	return keypair
}

func (n *noise255) DH(privKey PrivateKey, pubKey PublicKey) SymmetricKey {
	dh := make([]byte, n.dhLen)

	noise_curve25519_dh(dh, privKey, pubKey)

	return dh
}

func (n *noise255) Encrypt(
	cc CipherContext,
	plaintext []byte,
	authtext []byte,
) []byte {
	return noise_chacha20poly1305_encrypt(cc, plaintext, authtext)
}

func (n *noise255) Decrypt(
	cc CipherContext,
	ciphertext []byte,
	authtext []byte,
) ([]byte, error) {
	return noise_chacha20poly1305_decrypt(cc, ciphertext, authtext)
}
