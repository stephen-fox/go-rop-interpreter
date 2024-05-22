package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"syscall"
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
	forkProcess := flag.Bool(
		"fork",
		false,
		"Create a child process that is a duplicate of current process"+
			"with a single thread. This is to avoid weird stack behavior seen"+
			"in multi threaded processes. We think this is due to go's garbage"+
			"collector.")

	flag.Parse()
	ropChainPath := flag.Arg(0)
	if ropChainPath == "" {
		return errors.New("the first argument must be the path to the ROP chain")
	}

	if *forkProcess {
		id, _, _ := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
		switch id {
		//case -1:
		//	return errors.New("failed to invoke fork syscall")
		case 0:
			// keep going
		default:
			return nil
		}
	}

	unresolvedRopChain, err := os.ReadFile(ropChainPath)
	if err != nil {
		return err
	}

	ropChain, err := parseROPChain(unresolvedRopChain)
	if err != nil {
		return err
	}

	junk_x86(ropChain)
	return nil
}

//go:noinline
func junk_x86(ropChain [1024]byte) {
	firstRetPointer := reflect.ValueOf(RopRegion).Pointer()
	var stackVariable uint64 = 0x4142434445464748

	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		log.Panicln("nope")
	}

	log.Printf("pc: 0x%x | pc line: %d | main: 0x%x | uncalled: 0x%x",
		pc, line, reflect.ValueOf(main).Pointer(), firstRetPointer)

	currentAddress := uintptr(unsafe.Pointer(&stackVariable))
	for i := 0; i < 2048; i += 8 {
		chunk := *(*uintptr)(unsafe.Pointer(currentAddress))

		fmt.Fprintf(os.Stdout, "0x%x: 0x%x\n", currentAddress, chunk)

		if isAddressNear(chunk, pc) {
			*(*uintptr)(unsafe.Pointer(currentAddress)) = firstRetPointer

			log.Printf("found possible saved rip 0x%x at 0x%x | new value is: 0x%x",
				chunk, currentAddress, firstRetPointer)
		}

		currentAddress += 8
	}

	// runtime.KeepAlive(ropChain)
}

func isAddressNear(addr uintptr, target uintptr) bool {
	return addr > target && addr < target+12
}

//go:noinline
func RopRegion() {
	log.Println("mweh")
	os.Exit(1)
}

//go:noinline
func parseROPChain(unresolvedROPChain []byte) ([1024]byte, error) {
	var ropChain [1024]byte
	firstRetPointer := reflect.ValueOf(RopRegion).Pointer()

	for i := 0; i < len(unresolvedROPChain); i += 8 {
		chunk := unresolvedROPChain[i : i+8]
		if bytes.HasPrefix(chunk, []byte{0xba, 0x68, 0x65, 0x77, 0x6d, 0xbe}) {
			gadgetAddr := uint64(binary.BigEndian.Uint16(chunk[6:8])) + uint64(firstRetPointer)
			binary.LittleEndian.PutUint64(ropChain[i:i+8], gadgetAddr)
			continue
		}

		copy(ropChain[i:i+8], chunk)
	}

	return ropChain, nil
}
