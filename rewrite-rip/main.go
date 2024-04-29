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

//go:noinline
func main() {
	log.Println("pid:", os.Getpid())

	junk_x86()

	log.Println("nope")
}

//go:noinline
func junk_arm() {
	var b uint32 = 0x41424344

	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		log.Fatalln("nope")
	}

	for pc%4 != 0 {
		pc++
	}

	_localVarPtr := unsafe.Pointer(&b)
	localVarPtrBack := unsafe.Pointer(uintptr(_localVarPtr) - 512)

	uncalledPtr := reflect.ValueOf(Uncalled).Pointer()

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

		if valueLittle == pc {
			binary.LittleEndian.PutUint32(stackMemory[i:], uint32(uncalledPtr))

			log.Printf("found pc 0x%x at 0x%x | new value is: 0x%x",
				pc, memoryPtr, stackMemory[i:i+4])

			return
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
		log.Fatalln("nope")
	}

	for pc%4 != 0 {
		log.Printf("add (pc was: 0x%x", pc)
		pc++
	}

	_localVarPtr := unsafe.Pointer(&b)
	localVarPtrBack := unsafe.Pointer(uintptr(_localVarPtr) - 64)

	uncalledPtr := reflect.ValueOf(Uncalled).Pointer()

	log.Printf("pc: 0x%x | pc line: %d | main: 0x%x | uncalled: 0x%x",
		pc, line, reflect.ValueOf(main).Pointer(), uncalledPtr)

	// func Float32bits(f float32) uint32 { return *(*uint32)(unsafe.Pointer(&f)) }
	stackMemory := *(*[1024]byte)(localVarPtrBack)

	memoryPtr := uintptr(localVarPtrBack)

	for i := 0; i < len(stackMemory); i += 8 {
		//log.Printf("i: %d | 0x%x(memPtr) + 0x%x(i) = 0x%x",
		//	i, memoryPtr, i, memoryPtr+8)

		value := stackMemory[i : i+8]

		valueLittle := uintptr(binary.LittleEndian.Uint64(value))

		fmt.Fprintf(os.Stdout, "0x%x: 0x%x - 0x%x\n",
			memoryPtr, value, valueLittle)

		if valueLittle == pc {
			binary.LittleEndian.PutUint64(stackMemory[i:], uint64(uncalledPtr))

			log.Printf("found pc 0x%x at 0x%x | new value is: 0x%x",
				pc, memoryPtr, stackMemory[i:i+8])

			return
		}

		memoryPtr += 8
	}

	fmt.Scanln()
}

//go:noinline
func Uncalled() {
	log.Println("win")
	os.Exit(1)
}
