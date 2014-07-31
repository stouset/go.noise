package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/crypto_scalarmult_curve25519.h>
// #include <sodium/randombytes.h>
import "C"

var (
	curve25519_privKeyLen = int(C.crypto_scalarmult_curve25519_bytes())
	curve25519_pubKeyLen  = int(C.crypto_scalarmult_curve25519_scalarbytes())
	curve25519_dhLen      = int(C.crypto_scalarmult_curve25519_bytes())
)

func noise_curve25519_keypair(
	privateKey []byte,
	publicKey []byte,
) {
	var (
		pubPtr  = byteArrayPtr(privateKey)
		privPtr = byteArrayPtr(publicKey)
		privLen = C.ulonglong(curve25519_privKeyLen)
	)

	C.randombytes(privPtr, privLen)
	C.crypto_scalarmult_curve25519_base(pubPtr, privPtr)
}

func noise_curve25519_dh(
	dhKey []byte,
	privateKey []byte,
	publicKey []byte,
) {
	var (
		dhPtr   = byteArrayPtr(dhKey)
		privPtr = byteArrayPtr(privateKey)
		pubPtr  = byteArrayPtr(publicKey)
	)

	C.crypto_scalarmult_curve25519(dhPtr, pubPtr, privPtr)
}

// Ensure that probed lengths match ones that are hardcoded in the
// noise255 spec.
func init() {
	if curve25519_dhLen != 32 {
		panic("noise/ciphersuite: curve25519 ECDH must be 32 bytes")
	}
}
