// runner executes an "unresolved ROP chain" produced by the compiler program,
// effectively acting as an interpreter.
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

	log.Fatalln("fatal: this code should never be reached")
}

func mainWithError() error {
	forkProcess := flag.Bool(
		"fork",
		false,
		"Create a child process that is a duplicate of current process\n"+
			"with a single thread. This avoids weird stack behavior seen in\n"+
			"multi-threaded Go processes. We think this behavior is due to\n"+
			"Go's garbage collector. Try specifying this flag if your ROP\n"+
			"chain is resulting in a segfault")

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
			// We are the single-threaded child.
		default:
			// We are the multi-threaded parent - exit.
			return nil
		}
	}

	// Read an offset-based ("unresolved") ROP chain from a file.
	// For more information on the structure of this data, refer
	// to parseROPChain.
	//
	// Note: In the real world, we would read this data over
	// the network from a client. Here, we are reading from
	// a file for simplicity and security reasons.
	unresolvedRopChain, err := os.ReadFile(ropChainPath)
	if err != nil {
		return err
	}

	// Turn the unresolved ROP chain into a real ROP chain.
	ropChain, err := parseROPChain(unresolvedRopChain)
	if err != nil {
		return err
	}

	// Pass execution to the ROP chain by rewriting the saved RIP
	// to point at the first ROP gadget.
	pointSavedRipToRopChain_x86_64(ropChain)

	// We never reach here because we passed execution to the ROP
	// chain in the previous function call.
	return nil
}

//go:noinline
func pointSavedRipToRopChain_x86_64(ropChain [1024]byte) {
	// We assume that the first address of the ROP chain
	// begins with a pointer to a "ret" gadget.
	firstRetPointer := reflect.ValueOf(RopRegion).Pointer()

	// This local variable is used to locate the stack and
	// adjacent memeory.
	var stackCandle uint64 = 0x4142434445464748

	pc, _, line, ok := runtime.Caller(1)
	if !ok {
		log.Panicln("runtime.Caller failed")
	}

	log.Printf("pc: 0x%x | pc line: %d | main: 0x%x | uncalled: 0x%x",
		pc, line, reflect.ValueOf(main).Pointer(), firstRetPointer)

	currentAddress := uintptr(unsafe.Pointer(&stackCandle))

	// Starting from the stack candle, search the stack in 8 bytes
	// chunks for chunks that look like the saved return instruction
	// pointer. If a chunk looks like the saved RIP, then overwrite it.
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
	// This function is overwritten with ROP gadget addresses.
	// Since this function is part of the executable's code
	// segment, passing execution to an instruction in this
	// region should not look too out of the ordinary to
	// antivirus or other malwa- I mean EDR.
	log.Println("")
	os.Exit(1)
}

//go:noinline
func parseROPChain(unresolvedROPChain []byte) ([1024]byte, error) {
	// We assume that unresolvedROPChain consists of 8-byte chunks
	// of data that are either offsets to ROP gadgets found in
	// the RopRegion, or arbitray data.
	//
	// We assume that the first chunk in the RopRegion is
	// a "ret" instruction offset.
	var ropChain [1024]byte

	firstRetPointer := reflect.ValueOf(RopRegion).Pointer()

	for i := 0; i < len(unresolvedROPChain); i += 8 {
		chunk := unresolvedROPChain[i : i+8]

		if bytes.HasPrefix(chunk, []byte{0xba, 0x68, 0x65, 0x77, 0x6d, 0xbe}) {
			// Here, chunk is the offset of a ROP gadget
			// found in RopRegion.
			gadgetAddr := uint64(binary.BigEndian.Uint16(chunk[6:8])) + uint64(firstRetPointer)

			binary.LittleEndian.PutUint64(ropChain[i:i+8], gadgetAddr)
		} else {
			// Otherwise, we just copy the chunk "as is"
			// into the ROP chain.
			copy(ropChain[i:i+8], chunk)
		}
	}

	return ropChain, nil
}
