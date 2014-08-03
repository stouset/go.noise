package ciphersuite

import (
	"C"
	"reflect"
	"unsafe"
)

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
	return (*C.uchar)(
		unsafe.Pointer(
			(*reflect.SliceHeader)(
				unsafe.Pointer(&slice),
			).Data,
		),
	)
}
