package box

import "github.com/stouset/go.noise/ciphersuite"

type Context struct {
	suite ciphersuite.Ciphersuite

	selfEphemeralKey *ciphersuite.Keypair
	selfKey          *ciphersuite.Keypair
	peerEphemeralKey *ciphersuite.PublicKey
	peerKey          *ciphersuite.PublicKey

	cv []byte
}

func NewContext(
	suite ciphersuite.Ciphersuite,
	selfKey *ciphersuite.Keypair,
	counterStart int8,
) (
	ctx *Context,
) {
	var selfEphemeralKey *ciphersuite.Keypair

	if selfKey == nil {
		selfKey = suite.NewKeypair()
		selfEphemeralKey = selfKey
	}

	if selfEphemeralKey == nil {
		selfEphemeralKey = suite.NewKeypair()
	}

	return &Context{
		suite:            suite,
		selfKey:          selfKey,
		selfEphemeralKey: selfEphemeralKey,
		peerKey:          new(ciphersuite.PublicKey),
		peerEphemeralKey: new(ciphersuite.PublicKey),
		cv:               make([]byte, suite.CVLen()),
	}
}

func (c *Context) EphemeralPublicKey() ciphersuite.PublicKey {
	return c.selfEphemeralKey.Public
}

func (c *Context) PeerPublicKey() ciphersuite.PublicKey {
	return *c.peerKey
}

func (c *Context) Terminate() {
	*c = *new(Context)
}

func (c *Context) Init(peerEphemeralKey ciphersuite.PublicKey) {
	*c.peerEphemeralKey = peerEphemeralKey
}

func (c *Context) Shut(data []byte, kdfId int8, padLen uint32) (box []byte) {
	return shutBox(
		c.suite,
		c.selfEphemeralKey,
		c.selfKey,
		c.peerEphemeralKey,
		c.peerKey,
		&c.cv,
		kdfId*2,
		padLen,
		data,
	)
}

func (c *Context) Open(box []byte, kdfId int8) (data []byte, err error) {
	return openBox(
		c.suite,
		c.selfEphemeralKey,
		c.selfKey,
		c.peerEphemeralKey,
		c.peerKey,
		&c.cv,
		kdfId*2,
		box,
	)
}
