package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/crypto_onetimeauth_poly1305.h>
// #include <sodium/crypto_stream_chacha20.h>
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
	cc []byte,
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
	cc []byte,
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

	err = noise_poly1305_hmac_verify(mac, macKey, ciphertext, authtext)

	if err != nil {
		return nil, err
	}

	chacha20(plaintext, key, iv, ciphertext, 1)

	noise_chacha20_rekey(cc)

	return plaintext, nil
}

func noise_chacha20_rekey(
	cc []byte,
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
	poly1305(
		dst,
		macKey,
		noise_poly1305_hmac_format(ciphertext, authtext),
	)
}

func noise_poly1305_hmac_verify(
	target []byte,
	macKey []byte,
	ciphertext []byte,
	authtext []byte,
) error {
	if !poly1305_verify(
		macKey,
		target,
		noise_poly1305_hmac_format(ciphertext, authtext),
	) {
		return errors.New("noise/ciphersuite: ciphertext MAC indicates tampering")
	}

	return nil
}

func noise_poly1305_hmac_format(
	ciphertext []byte,
	authtext []byte,
) []byte {
	var (
		atPadLen = noise_pad16_len(authtext)
		ctPadLen = noise_pad16_len(ciphertext)

		atOffset    = 0
		ctOffset    = atOffset + atPadLen
		atLenOffset = ctOffset + ctPadLen
		ctLenOffset = atLenOffset + 8

		out = make([]byte, atPadLen+ctPadLen+8+8)
	)

	copy(out[atOffset:], authtext)
	copy(out[ctOffset:], ciphertext)

	binary.LittleEndian.PutUint64(out[atLenOffset:], uint64(len(authtext)))
	binary.LittleEndian.PutUint64(out[ctLenOffset:], uint64(len(ciphertext)))

	return out
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

	C.crypto_onetimeauth_poly1305(
		dstPtr,
		inPtr,
		inLen,
		keyPtr,
	)
}

func poly1305_verify(
	key []byte,
	target []byte,
	in []byte,
) bool {
	var (
		keyPtr    = byteArrayPtr(key)
		targetPtr = byteArrayPtr(target)
		inPtr     = byteArrayPtr(in)
		inLen     = byteArrayLen(in)
	)

	ret := C.crypto_onetimeauth_poly1305_verify(
		targetPtr,
		inPtr,
		inLen,
		keyPtr,
	)

	return ret == 0
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
