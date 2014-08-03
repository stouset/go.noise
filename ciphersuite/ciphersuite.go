/*
Package ciphersuite implements the ciphersuites defined in the
Noise specification. All ciphersuites implement the Ciphersuite
interface.
*/
package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/core.h>
import "C"

import "github.com/stouset/go.secrets"

type (
	SymmetricKey struct{ secrets.Secret }
	PrivateKey   struct{ secrets.Secret }
	PublicKey    struct{ secrets.Secret }
)

type (
	CipherContext struct{ secrets.Secret }
	ChainVariable struct{ secrets.Secret }
)

type Keypair struct {
	Private PrivateKey
	Public  PublicKey
}

type Ciphersuite interface {
	NewKeypair() (*Keypair, error)
	NewChainVariable() (*ChainVariable, error)

	// TODO: are these still necessary?
	// DHLen() int
	// MACLen() int

	DH(
		private PrivateKey,
		public PublicKey,
	) (*SymmetricKey, error)

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
	) (*ChainVariable, *CipherContext, error)

	DeriveCCCC(
		cv ChainVariable,
	) (client *CipherContext, server *CipherContext, err error)
}

type ciphersuite struct {
	name   [24]byte
	dhLen  int
	macLen int
	ccLen  int
	cvLen  int
}

func (c *ciphersuite) NewChainVariable() (*ChainVariable, error) {
	cv, err := secrets.NewSecret(c.cvLen)

	return &ChainVariable{*cv}, err
}

// func (c *ciphersuite) DHLen() int  { return c.dhLen }
// func (c *ciphersuite) MACLen() int { return c.macLen }

func (c *ciphersuite) DeriveCVCC(
	cv ChainVariable,
	key SymmetricKey,
	kdfNum int8,
) (
	*ChainVariable,
	*CipherContext,
	error,
) {
	var (
		secret = key.Secret
		extra  = cv.Secret
		info   = append(c.name[:], byte(kdfNum))
		keyLen = c.cvLen + c.ccLen

		newcv, err = kdf(secret, extra, info, keyLen)

		newcc *secrets.Secret
	)

	if err != nil {
		return nil, nil, err
	}

	newcc, err = newcv.Split(c.cvLen)

	if err != nil {
		return nil, nil, err
	}

	return &ChainVariable{*newcv}, &CipherContext{*newcc}, nil
}

func (c *ciphersuite) DeriveCCCC(
	cv ChainVariable,
) (
	client *CipherContext,
	server *CipherContext,
	err error,
) {
	var (
		zeroes   *ChainVariable
		clientcc *secrets.Secret
		servercc *secrets.Secret
	)

	zeroes, err = c.NewChainVariable()

	if err != nil {
		return nil, nil, err
	}

	var (
		secret = cv.Secret
		extra  = zeroes.Secret
		info   = append(c.name[:], byte(6))
		keyLen = c.ccLen * 2
	)

	clientcc, err = kdf(secret, extra, info, keyLen)

	if err != nil {
		return nil, nil, err
	}

	servercc, err = clientcc.Split(c.ccLen)

	if err != nil {
		return nil, nil, err
	}

	return &CipherContext{*clientcc}, &CipherContext{*servercc}, nil
}

func init() {
	if int(C.sodium_init()) == -1 {
		panic("noise/ciphersuite: libsodium couldn't be initialized")
	}
}
