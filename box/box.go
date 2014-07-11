package box

// #cgo pkg-config: libsodium
// #include <sodium/core.h>
// #include <sodium/randombytes.h>
import "C"
import "unsafe"

import "github.com/stouset/go.noise/ciphersuite"
import "github.com/stouset/go.noise/kdf"

import "encoding/binary"
import "fmt"

func deriveBoxKey(
	suite ciphersuite.Ciphersuite,
	dhKey ciphersuite.SymmetricKey,
	cv *[]byte,
	kdfNum *int8,
) (
	cc []byte,
) {
	name := suite.Name()
	info := append(name[:], byte(*kdfNum))

	key := kdf.Derive(
		dhKey,
		*cv,
		info,
		suite.CVLen()+suite.CCLen(),
	)

	*kdfNum += 1
	*cv = key[:suite.CVLen()]
	cc = key[suite.CVLen():]

	return
}

func shutBox(
	suite ciphersuite.Ciphersuite,
	selfEphemeralKey *ciphersuite.Keypair,
	selfKey *ciphersuite.Keypair,
	peerEphemeralKey *ciphersuite.PublicKey,
	peerKey *ciphersuite.PublicKey,
	cv *[]byte,
	kdfNum *int8,
	padLen uint32,
	data []byte,
) (
	box []byte,
) {
	dh1 := suite.DH(selfEphemeralKey.Private, *peerEphemeralKey)
	cc1 := deriveBoxKey(suite, dh1, cv, kdfNum)

	dh2 := suite.DH(selfKey.Private, *peerEphemeralKey)
	cc2 := deriveBoxKey(suite, dh2, cv, kdfNum)

	fmt.Println(dh1, cc1)
	fmt.Println(dh2, cc2)

	header := shutBoxHeader(suite, cc1, selfEphemeralKey.Public, selfKey.Public)
	body := shutBoxBody(suite, cc2, header, data, padLen)

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
	return suite.Encrypt(cc, selfEphemeralPublicKey, selfPublicKey)
}

func shutBoxBody(
	suite ciphersuite.Ciphersuite,
	cc []byte,
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
	binary.BigEndian.PutUint32(plaintext[len(data)+len(random):], padLen)

	return suite.Encrypt(cc, header, plaintext)
}

func openBox(
	suite ciphersuite.Ciphersuite,
	selfEphemeralKey *ciphersuite.Keypair,
	selfKey *ciphersuite.Keypair,
	peerEphemeralKey *ciphersuite.PublicKey,
	peerKey *ciphersuite.PublicKey,
	cv *[]byte,
	kdfNum *int8,
	box []byte,
) (
	data []byte,
	err error,
) {
	*peerEphemeralKey = box[:suite.DHLen()]
	header := box[suite.DHLen() : suite.DHLen()+suite.DHLen()+suite.MACLen()]
	body := box[suite.DHLen()+suite.DHLen()+suite.MACLen():]

	dh1 := suite.DH(selfEphemeralKey.Private, *peerEphemeralKey)
	cc1 := deriveBoxKey(suite, dh1, cv, kdfNum)

	fmt.Println(dh1, cc1)

	*peerKey, err = openBoxHeader(suite, cc1, *peerEphemeralKey, header)

	if err != nil {
		return nil, err
	}

	dh2 := suite.DH(selfEphemeralKey.Private, *peerKey)
	cc2 := deriveBoxKey(suite, dh2, cv, kdfNum)

	fmt.Println(dh2, cc2)

	data, err = openBoxBody(suite, cc2, body, header)

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
	return suite.Decrypt(cc, peerEphemeralKey, header)
}

func openBoxBody(
	suite ciphersuite.Ciphersuite,
	cc []byte,
	body []byte,
	header []byte,
) (
	data []byte,
	err error,
) {
	plaintext, err := suite.Decrypt(cc, header, body)

	if err != nil {
		return nil, err
	}

	padLen := binary.BigEndian.Uint32(plaintext[len(plaintext)-4:])

	return plaintext[:len(plaintext)-int(padLen)-4], nil
}
