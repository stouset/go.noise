package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/crypto_auth_hmacsha512.h>
import "C"

// Derives a key from a secret, a chaining variable (as extra), and an
// info parameter used to ensure uniqueness of the inputs as a whole.
func kdf(
	secret []byte,
	extra []byte,
	info []byte,
	outLen int,
) []byte {
	const hashLen = 64

	var (
		// the number of blocks we need to generate, plus a
		// counter to track our progress through them
		blocks = byte((outLen + hashLen - 1) / hashLen)
		c      = byte(0)

		// preallocate memory for the entire output
		out []byte = make([]byte, blocks*hashLen)

		// offsets for the different fields that comprise the
		// message that gets hashed
		iOffset = 0
		cOffset = iOffset + len(info)
		tOffset = cOffset + 1  // c is 1 byte long
		eOffset = tOffset + 32 // we only use 32 bytes of t
		mLength = eOffset + len(extra)

		// C types for the secret and its size
		sSize = byteArraySize(secret)
		sPtr  = byteArrayPtr(secret)

		// C types for the hashed message and its length
		m    = make([]byte, mLength)
		mLen = byteArrayLen(m)
		mPtr = byteArrayPtr(m)

		// C pointer to the current block being computed
		t    = out
		tPtr = byteArrayPtr(t)

		// the HMAC internal state
		state C.struct_crypto_auth_hmacsha512_state
	)

	// copy the static components of m into place
	copy(m[iOffset:], info)
	copy(m[eOffset:], extra)

	// iteratively hash the message into each block of the output
	for ; c < blocks; c++ {
		copy(m[cOffset:], []byte{c})

		C.crypto_auth_hmacsha512_init(&state, sPtr, sSize)
		C.crypto_auth_hmacsha512_update(&state, mPtr, mLen)
		C.crypto_auth_hmacsha512_final(&state, tPtr)

		// mix in some of the output from the previous block
		// into the next iteration
		copy(m[tOffset:], t[:32])

		// advance the pointer by one block
		t = t[hashLen:]
		tPtr = byteArrayPtr(t)
	}

	// trim output to match the requested length
	return out[:outLen]
}
