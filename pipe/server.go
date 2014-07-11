package pipe

import "github.com/stouset/go.noise/box"
import "github.com/stouset/go.noise/ciphersuite"

type serverHandshake struct {
	context box.Context
}

func NewServerHandshake(
	suite ciphersuite.Ciphersuite,
	serverKey *ciphersuite.Keypair,
) (
	handshake *serverHandshake,
) {
	return &serverHandshake{
		context: *box.NewContext(suite, serverKey, 1),
	}
}

func (h *serverHandshake) Eph(eph []byte) {
	h.context.Init(ciphersuite.PublicKey(eph))
}

func (h *serverHandshake) Syn(data []byte, padLen uint32) (syn []byte, err error) {
	return h.context.Shut(data, 1, padLen)
}

func (h *serverHandshake) Ack(ack []byte) (data []byte, err error) {
	return h.context.Open(ack, 2)
}

func (h *serverHandshake) Terminate() {
	h.context.Terminate()
}
