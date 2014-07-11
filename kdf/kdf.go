package kdf

// #cgo pkg-config: libsodium
// #include <sodium/crypto_auth_hmacsha512.h>
import "C"
import "unsafe"

const hashLen = 64

func Derive(
	secret []byte,
	extra []byte,
	info []byte,
	outLen int,
) (
	out []byte,
) {
	var state C.struct_crypto_auth_hmacsha512_state

	sLen := C.size_t(len(secret))
	sPtr := (*C.uchar)(unsafe.Pointer(&secret[0]))

	t := make([]byte, hashLen)
	tPtr := (*C.uchar)(unsafe.Pointer(&t[0]))

	m := append(info, byte(0))
	m = append(m, t[:32]...)
	m = append(m, extra...)
	mPtr := (*C.uchar)(unsafe.Pointer(&m[0]))
	mLen := C.ulonglong(len(m))

	iterations := byte((outLen + hashLen - 1) / hashLen)
	c := byte(0)
	cOffset := len(info)

	for ; c < iterations; c++ {
		m[cOffset] = c

		C.crypto_auth_hmacsha512_init(&state, sPtr, sLen)
		C.crypto_auth_hmacsha512_update(&state, mPtr, mLen)
		C.crypto_auth_hmacsha512_final(&state, tPtr)

		out = append(out, t...)
	}

	return out[:outLen]
}
