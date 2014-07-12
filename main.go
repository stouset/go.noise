package main

// TODO: sodium_init

import "github.com/stouset/go.noise/ciphersuite"
import "github.com/stouset/go.noise/pipe"

import "fmt"

func main() {
	suite := ciphersuite.Noise255
	serverKey := suite.NewKeypair()
	clientKey := suite.NewKeypair()

	clientHandshake := pipe.NewClientHandshake(suite, clientKey)
	serverHandshake := pipe.NewServerHandshake(suite, serverKey)
	defer clientHandshake.Terminate()
	defer serverHandshake.Terminate()

	clientEphemeralKey := clientHandshake.Eph()
	serverHandshake.Eph(clientEphemeralKey)

	var syn1, syn2, ack1, ack2 []byte
	var err error

	syn1 = serverHandshake.Syn([]byte("hoy!"), 0)

	if err != nil {
		goto err
	}

	syn2, err = clientHandshake.Syn(syn1)

	if err != nil {
		goto err
	}

	fmt.Printf("Syn: %x\n", syn1)
	fmt.Printf("Syn Contents: %s\n", syn2)

	ack1 = clientHandshake.Ack([]byte("hoy hoy!"), 0)

	if err != nil {
		goto err
	}

	ack2, err = serverHandshake.Ack(ack1)

	if err != nil {
		goto err
	}

	fmt.Printf("Ack :%x\n", ack1)
	fmt.Printf("Ack Contents: %s\n", ack2)

	return

err:

	fmt.Printf("Error: %s\n", err)
}
