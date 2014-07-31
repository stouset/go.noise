package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/crypto_onetimeauth_poly1305.h>
// #include <sodium/crypto_stream_chacha20.h>
// #include <sodium/utils.h>
import "C"

import (
	"encoding/binary"
	"errors"
)

var (
	poly1305_keyLen   = int(C.crypto_onetimeauth_poly1305_keybytes())
	poly1305_macLen   = int(C.crypto_onetimeauth_poly1305_bytes())
	chacha20_keyLen   = int(C.crypto_stream_chacha20_keybytes())
	chacha20_ivLen    = 8 // hardcoded by Noise spec
	chacha20_blockLen = 64
)

func noise_chacha20poly1305_encrypt(
	cc CipherContext,
	plaintext []byte,
	authtext []byte,
) []byte {
	var (
		key        = cc[:chacha20_keyLen]
		iv         = cc[chacha20_keyLen : chacha20_keyLen+chacha20_ivLen]
		zeroes     = make([]byte, chacha20_blockLen)
		macKey     = make([]byte, poly1305_keyLen, chacha20_blockLen)
		out        = make([]byte, len(plaintext)+poly1305_macLen)
		ciphertext = out[:len(plaintext)]
		mac        = out[len(plaintext):]
	)

	chacha20(macKey, key, iv, zeroes, 0)
	chacha20(ciphertext, key, iv, plaintext, 1)
	noise_poly1305_hmac(mac, macKey, ciphertext, authtext)

	noise_chacha20_rekey(cc)

	return out
}

func noise_chacha20poly1305_decrypt(
	cc CipherContext,
	ciphertext []byte,
	authtext []byte,
) ([]byte, error) {
	var (
		key       = cc[:chacha20_keyLen]
		iv        = cc[chacha20_keyLen : chacha20_keyLen+chacha20_ivLen]
		zeroes    = make([]byte, chacha20_blockLen)
		macKey    = make([]byte, poly1305_keyLen, chacha20_blockLen)
		plaintext = make([]byte, len(ciphertext)-poly1305_macLen)
		mac       = ciphertext[len(plaintext):]

		err error
	)

	ciphertext = ciphertext[:len(plaintext)]

	chacha20(macKey, key, iv, zeroes, 0)

	err = noise_poly1305_auth(mac, macKey, ciphertext, authtext)

	if err != nil {
		return nil, err
	}

	chacha20(plaintext, key, iv, ciphertext, 1)

	noise_chacha20_rekey(cc)

	return plaintext, nil
}

func noise_chacha20_rekey(
	cc CipherContext,
) {
	var (
		key    = cc[:chacha20_keyLen]
		iv     = make([]byte, chacha20_ivLen)
		zeroes = make([]byte, len(cc))
	)

	for i := 0; i < len(iv); i++ {
		iv[i] = ^cc[chacha20_keyLen+i]
	}

	chacha20(cc, key, iv, zeroes, 1)
}

func noise_poly1305_hmac(
	dst []byte,
	macKey []byte,
	ciphertext []byte,
	authtext []byte,
) {
	var (
		atPadLen = noise_pad16_len(authtext)
		ctPadLen = noise_pad16_len(ciphertext)

		atOffset    = 0
		ctOffset    = atOffset + atPadLen
		atLenOffset = ctOffset + ctPadLen
		ctLenOffset = atLenOffset + 8

		in = make([]byte, atPadLen+ctPadLen+8+8)
	)

	copy(in[atOffset:], authtext)
	copy(in[ctOffset:], ciphertext)

	binary.LittleEndian.PutUint64(in[atLenOffset:], uint64(len(authtext)))
	binary.LittleEndian.PutUint64(in[ctLenOffset:], uint64(len(ciphertext)))

	poly1305(dst, macKey, in)
}

func noise_poly1305_auth(
	target []byte,
	macKey []byte,
	ciphertext []byte,
	authtext []byte,
) error {
	mac := make([]byte, poly1305_macLen)

	noise_poly1305_hmac(mac, macKey, ciphertext, authtext)

	if !byteArrayEqual(target, mac) {
		return errors.New("noise/ciphersuite: ciphertext MAC indicates tampering")
	}

	return nil
}

func noise_pad16_len(in []byte) int {
	return len(in) + (16 - (len(in)%16)%16)
}

func chacha20(
	dst []byte,
	key []byte,
	iv []byte,
	msg []byte,
	ic int64,
) {
	var (
		dstPtr = byteArrayPtr(dst)
		keyPtr = byteArrayPtr(key)
		ivPtr  = byteArrayPtr(iv)
		msgPtr = byteArrayPtr(msg)
		msgLen = byteArrayLen(msg)
	)

	C.crypto_stream_chacha20_xor_ic(
		dstPtr,
		msgPtr,
		msgLen,
		ivPtr,
		C.uint64_t(ic),
		keyPtr,
	)
}

func poly1305(
	dst []byte,
	key []byte,
	in []byte,
) {
	var (
		keyPtr = byteArrayPtr(key)
		dstPtr = byteArrayPtr(dst)
		inPtr  = byteArrayPtr(in)
		inLen  = byteArrayLen(in)
	)

	C.crypto_onetimeauth_poly1305(dstPtr, inPtr, inLen, keyPtr)
}

// Ensure that probed lengths match ones that are hardcoded in the
// noise255 spec.
func init() {
	if poly1305_keyLen != 32 {
		panic("noise/ciphersuite: poly1305 keys must be 32 bytes")
	}

	if poly1305_macLen != 16 {
		panic("noise/ciphersuite: poly1305 macs must be 16 bytes")
	}

	if chacha20_keyLen != 32 {
		panic("noise/ciphersuite: chacha20 keys must be 32 bytes")
	}
}
