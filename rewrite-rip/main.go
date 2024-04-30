package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"unsafe"
)

var (
	uncalledPtr = reflect.ValueOf(Uncalled).Pointer()
)

//go:noinline
func main() {
	log.Println("pid:", os.Getpid())

	switch runtime.GOARCH {
	case "arm64":
		junk_arm()
	case "amd64":
		junk_x86()
	default:
		log.Fatalf("unsupported arch: %q", runtime.GOARCH)
	}

	log.Println("nope")
}

//go:noinline
func junk_arm() {
	var b uint32 = 0x41424344

	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		log.Panicln("nope")
	}

	_localVarPtr := unsafe.Pointer(&b)
	localVarPtrBack := unsafe.Pointer(uintptr(_localVarPtr) - 512)

	log.Printf("pc: 0x%x | pc line: %d | main: 0x%x | uncalled: 0x%x",
		pc, line, reflect.ValueOf(main).Pointer(), uncalledPtr)

	// func Float32bits(f float32) uint32 { return *(*uint32)(unsafe.Pointer(&f)) }
	stackMemory := *(*[1024]byte)(localVarPtrBack)

	memoryPtr := uintptr(localVarPtrBack)

	for i := 0; i < len(stackMemory); i += 4 {
		value := stackMemory[i : i+4]

		valueLittle := uintptr(binary.LittleEndian.Uint32(value))

		fmt.Fprintf(os.Stdout, "0x%x: 0x%x - 0x%x\n",
			memoryPtr, value, valueLittle)

		if isAddressNear(valueLittle, pc) {
			binary.LittleEndian.PutUint32(stackMemory[i:], uint32(uncalledPtr))

			log.Printf("found possible saved rip 0x%x at 0x%x | new value is: 0x%x",
				valueLittle, memoryPtr, stackMemory[i:i+4])

			//return
		}

		memoryPtr += 4
	}

	fmt.Scanln()
}

//go:noinline
func junk_x86() {
	var b uint64 = 0x4142434445464748

	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		log.Panicln("nope")
	}

	_localVarPtr := unsafe.Pointer(&b)

	log.Printf("main: 0x%x | pc line: %d | main: 0x%x | uncalled: 0x%x",
		pc, line, reflect.ValueOf(main).Pointer(), uncalledPtr)

	localVarPtrBack := unsafe.Pointer(uintptr(_localVarPtr) - 1024)

	// func Float32bits(f float32) uint32 { return *(*uint32)(unsafe.Pointer(&f)) }
	stackMemory := *(*[2048]byte)(localVarPtrBack)

	memoryPtr := uintptr(localVarPtrBack)

	for i := 0; i < 2048; i += 8 {
		value := stackMemory[i : i+8]

		valueLittle := uintptr(binary.LittleEndian.Uint64(value))

		fmt.Fprintf(os.Stdout, "0x%x: 0x%x - 0x%x\n",
			memoryPtr, value, valueLittle)

		//if valueLittle == 0x4142434445464748 {
		//	log.Println("TODO")
		//	binary.LittleEndian.PutUint64(stackMemory[i:], uint64(uncalledPtr))
		//}

		if isAddressNear(valueLittle, pc) {
			binary.LittleEndian.PutUint64(stackMemory[i:], uint64(uncalledPtr))

			log.Printf("found possible saved rip 0x%x at 0x%x | new value is: 0x%x",
				valueLittle, memoryPtr, stackMemory[i:i+8])
		}

		memoryPtr += 8
	}

	//log.Printf("b: 0x%x", b)

	fmt.Scanln()
}

func isAddressNear(addr uintptr, target uintptr) bool {
	return addr > target && addr < target+1024
}

//go:noinline
func Uncalled() {
	log.Println("win")
	os.Exit(1)
}
