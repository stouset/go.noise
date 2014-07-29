package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/core.h>
// #include <sodium/crypto_onetimeauth_poly1305.h>
// #include <sodium/crypto_scalarmult_curve25519.h>
// #include <sodium/crypto_stream_chacha20.h>
// #include <sodium/randombytes.h>
// #include <sodium/utils.h>
import "C"
import "unsafe"

import "encoding/binary"
import "errors"

// TODO: check return value
var sodiumInitialized = int(C.sodium_init())

var Noise255 *noise255 = &noise255{
	name:   [24]byte{'N', 'o', 'i', 's', 'e', '2', '5', '5'},
	dhLen:  32,
	keyLen: 32,
	ivLen:  8,
	cvLen:  48,
	macLen: 16,

	macKeyLen:  32,
	pubKeyLen:  int(C.crypto_scalarmult_curve25519_scalarbytes()),
	privKeyLen: int(C.crypto_scalarmult_curve25519_bytes()),
}

type noise255 struct {
	name   [24]byte
	dhLen  int
	keyLen int
	ivLen  int
	cvLen  int
	macLen int

	macKeyLen  int
	pubKeyLen  int
	privKeyLen int
}

func (n *noise255) Name() (name [24]byte) { return n.name }
func (n *noise255) DHLen() int            { return n.dhLen }
func (n *noise255) CCLen() int            { return n.keyLen + n.ivLen }
func (n *noise255) CVLen() int            { return n.cvLen }
func (n *noise255) MACLen() int           { return n.macLen }

func (n *noise255) NewKeypair() (pair *Keypair) {
	pair = &Keypair{
		Public:  make([]byte, n.pubKeyLen),
		Private: make([]byte, n.privKeyLen),
	}

	pubPtr := (*C.uchar)(unsafe.Pointer(&pair.Public[0]))
	privPtr := (*C.uchar)(unsafe.Pointer(&pair.Private[0]))
	privLen := C.ulonglong(n.privKeyLen)

	C.randombytes(privPtr, privLen)
	C.crypto_scalarmult_curve25519_base(pubPtr, privPtr)

	return
}

func (n *noise255) DH(privKey PrivateKey, pubKey PublicKey) (dhKey SymmetricKey) {
	dhKey = make([]byte, n.dhLen)

	dhPtr := (*C.uchar)(unsafe.Pointer(&dhKey[0]))
	pubPtr := (*C.uchar)(unsafe.Pointer(&pubKey[0]))
	privPtr := (*C.uchar)(unsafe.Pointer(&privKey[0]))

	C.crypto_scalarmult_curve25519(dhPtr, privPtr, pubPtr)

	return
}

func (n *noise255) Encrypt(
	cc []byte,
	authtext []byte,
	plaintext []byte,
) (
	ciphertext []byte,
) {
	key := cc[:n.keyLen]
	iv := cc[n.keyLen:]

	keystream := n.encrypt(key, iv, make([]byte, 64), 0)
	ciphertext = n.encrypt(key, iv, plaintext, 1)

	macKey := keystream[:n.macKeyLen]
	copy(cc, n.encrypt(key, flip(iv), make([]byte, 64), 1)[:n.CCLen()])

	mac := n.mac(macKey, authtext, ciphertext)

	ciphertext = append(ciphertext, mac...)

	return
}

func (n *noise255) Decrypt(
	cc []byte,
	authtext []byte,
	ciphertext []byte,
) (
	plaintext []byte,
	err error,
) {
	key := cc[:n.keyLen]
	iv := cc[n.keyLen:]

	keystream := n.encrypt(key, iv, make([]byte, 64), 0)
	macKey := keystream[:n.macKeyLen]

	mac := ciphertext[len(ciphertext)-n.macLen:]
	ciphertext = ciphertext[:len(ciphertext)-n.macLen]

	if !equal(mac, n.mac(macKey, authtext, ciphertext)) {
		return nil, errors.New("noise255: ciphertext MAC indicates tampering")
	}

	plaintext = n.encrypt(key, iv, ciphertext, 1)

	copy(cc, n.encrypt(key, flip(iv), make([]byte, 64), 1)[:n.CCLen()])

	return
}

func (n *noise255) encrypt(
	key []byte,
	iv []byte,
	plaintext []byte,
	counter int,
) (
	ciphertext []byte,
) {
	// nothing to do if the plaintext is empty; this will cause the
	// ciphertext to be empty, too
	if len(plaintext) == 0 {
		return
	}

	ciphertext = make([]byte, len(plaintext))

	ciphertextPtr := (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	keyPtr := (*C.uchar)(unsafe.Pointer(&key[0]))
	ivPtr := (*C.uchar)(unsafe.Pointer(&iv[0]))
	plaintextPtr := (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	plaintextLen := C.ulonglong(len(plaintext))

	C.crypto_stream_chacha20_xor_ic(ciphertextPtr, plaintextPtr,
		plaintextLen, ivPtr, C.uint64_t(counter), keyPtr)

	return
}

func (n *noise255) mac(
	key []byte,
	authtext []byte,
	ciphertext []byte,
) (
	mac []byte,
) {
	authtextOffset := 0
	ciphertextOffset := pad16len(authtext)
	authLenOffset := pad16len(ciphertext) + ciphertextOffset
	cipherLenOffset := 8 + authLenOffset
	inLen := 8 + cipherLenOffset

	mac = make([]byte, n.macLen)
	in := make([]byte, inLen)

	copy(in[authtextOffset:], authtext)
	copy(in[ciphertextOffset:], ciphertext)
	binary.LittleEndian.PutUint64(in[authLenOffset:], uint64(len(authtext)))
	binary.LittleEndian.PutUint64(in[cipherLenOffset:], uint64(len(ciphertext)))

	macPtr := (*C.uchar)(unsafe.Pointer(&mac[0]))
	keyPtr := (*C.uchar)(unsafe.Pointer(&key[0]))
	inPtr := (*C.uchar)(unsafe.Pointer(&in[0]))

	C.crypto_onetimeauth_poly1305(macPtr, inPtr, C.ulonglong(inLen), keyPtr)

	return
}

func equal(
	b1 []byte,
	b2 []byte,
) bool {
	b1Ptr := unsafe.Pointer(&b1[0])
	b2Ptr := unsafe.Pointer(&b2[0])
	b1Len := C.size_t(len(b1))

	if len(b1) != len(b2) {
		return false
	}

	return int(C.sodium_memcmp(b1Ptr, b2Ptr, b1Len)) == 0
}

func pad16len(in []byte) int {
	return len(in) + (16 - (len(in) % 16) % 16)
}

func flip(in []byte) (out []byte) {
	n  := len(in)
	out = make([]byte, n)

	for i := 0; i < n; i++ {
		out[i] = ^in[i]
	}

	return
}
