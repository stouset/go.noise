package ciphersuite

// #cgo pkg-config: libsodium
// #include <string.h>
// #include <sodium/crypto_auth_hmacsha512.h>
import "C"

import (
	"github.com/stouset/go.secrets"
	"unsafe"
)

// Derives a key from a secret, a chaining variable (as extra), and an
// info parameter used to ensure uniqueness of the inputs as a whole.
func kdf(
	secret secrets.Secret,
	extra secrets.Secret,
	info []byte,
	keyLen int,
) (
	key *secrets.Secret,
	err error,
) {
	const (
		hashLen   = 64
		stateSize = int(unsafe.Sizeof(C.struct_crypto_auth_hmacsha512_state{}))
	)

	var (
		// the number of blocks we need to generate, plus a
		// counter to track our progress through them
		blocks = (keyLen + hashLen - 1) / hashLen
		c      = 0

		// offsets for the different fields that comprise the
		// message that gets hashed
		iOffset = 0
		cOffset = iOffset + len(info)
		tOffset = cOffset + 1  // c is 1 byte long
		eOffset = tOffset + 32 // we only use 32 bytes of t
		mLength = eOffset + extra.Len()

		state   *secrets.Secret
		message *secrets.Secret
	)

	// allocate the HMAC internal state
	state, err = secrets.NewSecret(stateSize)

	if err != nil {
		return nil, err
	}

	// allocate memory for the entire output
	key, err = secrets.NewSecret(blocks * hashLen)

	if err != nil {
		return nil, err
	}

	// allocate memory for the message to be hashed
	message, err = secrets.NewSecret(mLength)

	if err != nil {
		return nil, err
	}

	state.ReadWrite()
	defer state.Wipe()

	key.ReadWrite()
	defer key.Lock()

	message.ReadWrite()
	defer message.Wipe()

	secret.Read()
	defer secret.Lock()

	extra.Read()
	defer extra.Lock()

	var (
		statePtr = (*C.struct_crypto_auth_hmacsha512_state)(state.Pointer())

		secretPtr  = (*C.uchar)(secret.Pointer())
		secretSize = C.size_t(secret.Len())

		extraSlice = extra.Slice()

		messagePtr   = (*C.uchar)(message.Pointer())
		messageLen   = C.ulonglong(message.Len())
		messageSlice = message.Slice()

		tAddr = uintptr(key.Pointer())

		messageAddr  = uintptr(unsafe.Pointer(messagePtr))
		messageAddrC = messageAddr + uintptr(cOffset)
		messageAddrT = messageAddr + uintptr(tOffset)
	)

	// copy in the static components of the hashed message
	copy(messageSlice[iOffset:], info)
	copy(messageSlice[eOffset:], extraSlice)

	// finished with extra, so explicitly re-lock it
	extra.Lock()

	for ; c < blocks; c++ {
		C.memset(unsafe.Pointer(messageAddrC), C.int(c), 1)

		C.crypto_auth_hmacsha512_init(statePtr, secretPtr, secretSize)
		C.crypto_auth_hmacsha512_update(statePtr, messagePtr, messageLen)
		C.crypto_auth_hmacsha512_final(statePtr, (*C.uchar)(unsafe.Pointer(tAddr)))

		C.memcpy(unsafe.Pointer(messageAddrT), unsafe.Pointer(tAddr), 32)

		// advance the pointer into the key by one block
		tAddr += uintptr(hashLen)
	}

	// trim output to match the requested length
	err = key.Trim(keyLen)

	if err != nil {
		return nil, err
	}

	return key, nil
}
