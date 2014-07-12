package pipe

import "github.com/stouset/go.noise/box"
import "github.com/stouset/go.noise/ciphersuite"

type clientHandshake struct {
	context box.Context
}

func NewClientHandshake(
	suite ciphersuite.Ciphersuite,
	clientKey *ciphersuite.Keypair,
) (
	handshake *clientHandshake,
) {
	return &clientHandshake{
		context: *box.NewContext(suite, clientKey, 1),
	}
}

func (h *clientHandshake) Eph() (eph []byte) {
	return []byte(h.context.EphemeralPublicKey())
}

func (h *clientHandshake) Syn(syn []byte) (data []byte, err error) {
	return h.context.Open(syn, 1)
}

func (h *clientHandshake) Ack(data []byte, padLen uint32) (ack []byte) {
	return h.context.Shut(data, 2, padLen)
}

func (h *clientHandshake) Terminate() {
	h.context.Terminate()
}
