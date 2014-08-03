package box

// #cgo pkg-config: libsodium
// #include <sodium/core.h>
// #include <sodium/randombytes.h>
import "C"
import "unsafe"

import "github.com/stouset/go.noise/ciphersuite"

import "encoding/binary"

func shutBox(
	suite ciphersuite.Ciphersuite,
	selfEphemeralKey *ciphersuite.Keypair,
	selfKey *ciphersuite.Keypair,
	peerEphemeralKey *ciphersuite.PublicKey,
	peerKey *ciphersuite.PublicKey,
	cv *ciphersuite.ChainVariable,
	kdfNum int8,
	padLen uint32,
	data []byte,
) (
	box []byte,
) {
	var cc1, cc2 ciphersuite.CipherContext

	dh1, _ := suite.DH(selfEphemeralKey.Private, *peerEphemeralKey)
	*cv, cc1 = suite.DeriveCVCC(*cv, dh1, kdfNum)

	dh2, _ := suite.DH(selfKey.Private, *peerEphemeralKey)
	*cv, cc2 = suite.DeriveCVCC(*cv, dh2, kdfNum+1)

	header := shutBoxHeader(suite, cc1, selfEphemeralKey.Public, selfKey.Public)
	body := shutBoxBody(suite, cc2, selfEphemeralKey.Public, header, data, padLen)

	box = make(
		[]byte,
		len(selfEphemeralKey.Public)+len(header)+len(body),
	)

	copy(box[0:], selfEphemeralKey.Public)
	copy(box[len(selfEphemeralKey.Public):], header)
	copy(box[len(selfEphemeralKey.Public)+len(header):], body)

	return
}

func shutBoxHeader(
	suite ciphersuite.Ciphersuite,
	cc []byte,
	selfEphemeralPublicKey ciphersuite.PublicKey,
	selfPublicKey ciphersuite.PublicKey,
) (
	header []byte,
) {
	return suite.Encrypt(cc, selfPublicKey, selfEphemeralPublicKey)
}

func shutBoxBody(
	suite ciphersuite.Ciphersuite,
	cc []byte,
	selfEphemeralPublicKey ciphersuite.PublicKey,
	header []byte,
	data []byte,
	padLen uint32,
) (
	body []byte,
) {
	random := make([]byte, padLen)

	if padLen > 0 {
		randomPtr := (*C.uchar)(unsafe.Pointer(&random[0]))
		randomLen := C.ulonglong(padLen)

		C.randombytes(randomPtr, randomLen)
	}

	plaintext := make([]byte, len(data)+int(padLen)+4)
	copy(plaintext, data)
	copy(plaintext[len(data):], random)
	binary.LittleEndian.PutUint32(plaintext[len(data)+len(random):], padLen)

	return suite.Encrypt(
		cc,
		plaintext,
		append(selfEphemeralPublicKey, header...),
	)
}

func openBox(
	suite ciphersuite.Ciphersuite,
	selfEphemeralKey *ciphersuite.Keypair,
	selfKey *ciphersuite.Keypair,
	peerEphemeralKey *ciphersuite.PublicKey,
	peerKey *ciphersuite.PublicKey,
	cv *ciphersuite.ChainVariable,
	kdfNum int8,
	box []byte,
) (
	data []byte,
	err error,
) {
	var cc1, cc2 ciphersuite.CipherContext

	*peerEphemeralKey = box[:suite.DHLen()]
	header := box[suite.DHLen() : suite.DHLen()+suite.DHLen()+suite.MACLen()]
	body := box[suite.DHLen()+suite.DHLen()+suite.MACLen():]

	dh1, _ := suite.DH(selfEphemeralKey.Private, *peerEphemeralKey)
	*cv, cc1 = suite.DeriveCVCC(*cv, dh1, kdfNum)

	*peerKey, err = openBoxHeader(suite, cc1, *peerEphemeralKey, header)

	if err != nil {
		return nil, err
	}

	dh2, _ := suite.DH(selfEphemeralKey.Private, *peerKey)
	*cv, cc2 = suite.DeriveCVCC(*cv, dh2, kdfNum+1)

	data, err = openBoxBody(suite, cc2, peerEphemeralKey, header, body)

	if err != nil {
		return nil, err
	}

	return
}

func openBoxHeader(
	suite ciphersuite.Ciphersuite,
	cc []byte,
	peerEphemeralKey ciphersuite.PublicKey,
	header []byte,
) (
	peerKey ciphersuite.PublicKey,
	err error,
) {
	return suite.Decrypt(cc, header, peerEphemeralKey)
}

func openBoxBody(
	suite ciphersuite.Ciphersuite,
	cc []byte,
	peerEphemeralKey *ciphersuite.PublicKey,
	header []byte,
	body []byte,
) (
	data []byte,
	err error,
) {
	plaintext, err := suite.Decrypt(
		cc,
		body,
		append(*peerEphemeralKey, header...),
	)

	if err != nil {
		return nil, err
	}

	padLen := binary.LittleEndian.Uint32(plaintext[len(plaintext)-4:])

	return plaintext[:len(plaintext)-int(padLen)-4], nil
}
