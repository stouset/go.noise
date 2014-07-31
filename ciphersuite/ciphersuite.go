/*
Package ciphersuite implements the ciphersuites defined in the
Noise specification. All ciphersuites implement the Ciphersuite
interface.
*/
package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/core.h>
import "C"

type (
	// TODO: ensure SymmetricKeys and PrivateKeys are always mlock'd
	SymmetricKey []byte
	PrivateKey   []byte
	PublicKey    []byte
)

type (
	// TODO: ensure CipherContexts and ChainVariables are always mlock'd
	CipherContext []byte
	ChainVariable []byte
)

type Keypair struct {
	Private PrivateKey
	Public  PublicKey
}

type Ciphersuite interface {
	NewKeypair() Keypair
	NewChain() ChainVariable

	// TODO: are these still necessary?
	DHLen() int
	MACLen() int

	DH(
		private PrivateKey,
		public PublicKey,
	) SymmetricKey

	Encrypt(
		cc CipherContext,
		plaintext []byte,
		authtext []byte,
	) []byte

	Decrypt(
		cc CipherContext,
		ciphertext []byte,
		authtext []byte,
	) ([]byte, error)

	DeriveCVCC(
		cv ChainVariable,
		key SymmetricKey,
		kdfNum int8,
	) (ChainVariable, CipherContext)

	DeriveCCCC(
		cv ChainVariable,
	) (client CipherContext, server CipherContext)
}

type ciphersuite struct {
	name   [24]byte
	dhLen  int
	macLen int
	ccLen  int
	cvLen  int
}

func (c *ciphersuite) NewChain() ChainVariable {
	return make([]byte, c.cvLen)
}

func (c *ciphersuite) DHLen() int  { return c.dhLen }
func (c *ciphersuite) MACLen() int { return c.macLen }

func (c *ciphersuite) DeriveCVCC(
	cv ChainVariable,
	key SymmetricKey,
	kdfNum int8,
) (
	ChainVariable,
	CipherContext,
) {
	var (
		secret = key
		extra  = cv
		info   = append(c.name[:], byte(kdfNum))
		outLen = c.cvLen + c.ccLen

		pair = kdf(secret, extra, info, outLen)
	)

	return pair[:c.cvLen], pair[c.cvLen:]
}

func (c *ciphersuite) DeriveCCCC(
	cv ChainVariable,
) (
	client CipherContext,
	server CipherContext,
) {
	var (
		secret = cv
		extra  = make([]byte, c.cvLen)
		info   = append(c.name[:], byte(6))
		outLen = c.ccLen * 2

		pair = kdf(secret, extra, info, outLen)
	)

	return pair[:c.ccLen], pair[c.ccLen:]
}

func init() {
	if int(C.sodium_init()) != 0 {
		panic("noise/ciphersuite: libsodium couldn't be initialized")
	}
}
