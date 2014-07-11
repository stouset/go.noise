package ciphersuite

type PublicKey []byte
type PrivateKey []byte
type SymmetricKey []byte

type Keypair struct {
	Public  PublicKey
	Private PrivateKey
}

type Ciphersuite interface {
	Name() [24]byte
	DHLen() int
	CCLen() int
	CVLen() int
	MACLen() int

	NewKeypair() *Keypair

	DH(privKey PrivateKey, pubKey PublicKey) SymmetricKey
	Encrypt(cc []byte, authtext []byte, plaintext []byte) []byte
}
