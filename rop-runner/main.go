package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
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

	unresolvedRopChain, err := os.ReadFile(ropChainPath)
	if err != nil {
		return err
	}

	ropChain, err := parseROPChain(unresolvedRopChain)
	if err != nil {
		return err
	}

	_, err = os.Stdout.WriteString(hex.Dump(ropChain))
	if err != nil {
		return fmt.Errorf("failed to write hex dump string to stdout - %w", err)
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
func parseROPChain(unresolvedROPChain []byte) ([]byte, error) {
	var ropChain []byte
	firstRetPointer := reflect.ValueOf(RopRegion).Pointer()
	scanner := bufio.NewScanner(bytes.NewReader(unresolvedROPChain))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		ropType, value, found := strings.Cut(line, ": ")
		if !found {
			return nil, fmt.Errorf("separator ':' not found on line: %d", lineNum)
		}

		value = strings.TrimPrefix(value, "0x")
		switch ropType {
		case "g":
			offset, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse gadget on line: %d - %w", lineNum, err)
			}

			ropAddress := uint64(firstRetPointer) + offset
			ropChain = binary.LittleEndian.AppendUint64(ropChain, ropAddress)
		case "d":
			data, err := hex.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode data on line: %d - %w", lineNum, err)
			}

			decodedLen := len(data)
			temp := make([]byte, decodedLen)
			for i := range data {
				temp[decodedLen-1-i] = data[i]
			}
			data = temp

			ropChain = append(ropChain, data...)
		}
	}

	return ropChain, nil
}
