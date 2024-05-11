package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"unsafe"
)

//go:noinline
func main() {
	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}

	log.Println("nope :c")
}

func mainWithError() error {
	flag.Parse()
	ropChainPath := flag.Arg(0)
	if ropChainPath == "" {
		return errors.New("the first argument must be the path to the ROP chain")
	}

	ropChain, err := os.ReadFile(ropChainPath)
	if err != nil {
		return err
	}

	if len(ropChain) > 1024 {
		return errors.New("rop chain too lorge")
	}

	var b [1024]byte
	for i := 0; i < len(ropChain); i++ {
		b[i] = ropChain[i]
	}

	junk_x86(b)
	return nil
}

//go:noinline
func junk_x86(ropChain [1024]byte) {
	ropChainPointer := reflect.ValueOf(ropChain).Pointer()
	var b uint64 = 0x4142434445464748

	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		log.Panicln("nope")
	}

	log.Printf("pc: 0x%x | pc line: %d | main: 0x%x | uncalled: 0x%x",
		pc, line, reflect.ValueOf(main).Pointer(), ropChainPointer)

	currentAddress := uintptr(unsafe.Pointer(&b))
	for i := 0; i < 1069; i += 8 {
		chunk := *(*uintptr)(unsafe.Pointer(currentAddress))

		fmt.Fprintf(os.Stdout, "0x%x: 0x%x\n", currentAddress, chunk)

		if isAddressNear(chunk, pc) {
			*(*uintptr)(unsafe.Pointer(currentAddress)) = ropChainPointer

			log.Printf("found possible saved rip 0x%x at 0x%x | new value is: 0x%x",
				chunk, currentAddress, ropChainPointer)
		}

		currentAddress += 8
	}

	fmt.Scanln()
}

func isAddressNear(addr uintptr, target uintptr) bool {
	return addr > target && addr < target+1024
}

//go:noinline
func RopRegion() {
	log.Println("mweh")
	os.Exit(1)
}

//go:noinline
func RopRegion2() [1024]byte {
	x := [1024]byte{}
	return x
}
