package ciphersuite

// #cgo pkg-config: libsodium
// #include <sodium/utils.h>
import "C"
import "unsafe"

func byteArrayLen(slice []byte) C.ulonglong {
	return C.ulonglong(len(slice))
}

func byteArraySize(slice []byte) C.size_t {
	return C.size_t(len(slice))
}

func byteArrayCap(slice []byte) C.size_t {
	return C.size_t(cap(slice))
}

func byteArrayPtr(slice []byte) *C.uchar {
	if len(slice) == 0 {
		return nil
	}

	return (*C.uchar)(unsafe.Pointer(&slice[0]))
}

func byteArrayVoidPtr(slice []byte) unsafe.Pointer {
	return unsafe.Pointer(&slice[0])
}

func byteArrayEqual(
	b1 []byte,
	b2 []byte,
) bool {
	if len(b1) != len(b2) {
		return false
	}

	var (
		b1Ptr  = byteArrayVoidPtr(b1)
		b2Ptr  = byteArrayVoidPtr(b2)
		b1Size = byteArraySize(b1)
	)

	return int(C.sodium_memcmp(b1Ptr, b2Ptr, b1Size)) == 0
}
