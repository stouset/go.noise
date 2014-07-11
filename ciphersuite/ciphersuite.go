package ciphersuite

type publicKey []byte
type privateKey []byte
type sharedKey []byte

type keypair struct {
	Public  publicKey
	Private privateKey
}

type ciphersuite interface {
	Name() [24]byte
	DHLen() int
	CCLen() int
	CVLen() int
	MACLen() int

	NewKeypair() *keypair

	DH(privKey privateKey, pubKey publicKey) sharedKey
	Encrypt(cc []byte, authtext []byte, plaintext []byte) []byte
}
