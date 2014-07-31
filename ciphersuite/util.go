package ciphersuite

import (
	"C"
	"unsafe"
)

func byteArrayLen(slice []byte) C.ulonglong {
	return C.ulonglong(len(slice))
}

func byteArraySize(slice []byte) C.size_t {
	return C.size_t(len(slice))
}

func byteArrayPtr(slice []byte) *C.uchar {
	if len(slice) == 0 {
		return nil
	}
	
	return (*C.uchar)(unsafe.Pointer(&slice[0]))
}
