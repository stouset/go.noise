package ciphersuite

type PublicKey []byte
type PrivateKey []byte
type SharedKey []byte

type Keypair struct {
	Public  PublicKey
	Private PrivateKey
}

type ciphersuite interface {
	Name() [24]byte
	DHLen() int
	CCLen() int
	MACLen() int

	Keypair() Keypair

	DH(privKey PrivateKey, pubKey PublicKey) SharedKey
	Encrypt(cc []byte, authtext []byte, plaintext []byte) []byte
}
