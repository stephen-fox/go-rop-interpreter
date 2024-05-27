// compiler reads the rop chain file and translates it into a slice of byte to
// input into rop-runner to execute a rop chain. If a rop gadget is written as
// string, it checks if this gadget is in the rop gadgets binary and overwrites
// the string with the address to the gadget.
package main

import (
	"bufio"
	"bytes"
	"compiler/asm"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"log"
	"os"
	"sort"
	"strings"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalf("fatal: %s", err)
	}
}

func mainWithError() error {
	ropChainPath := flag.String(
		"rop-chain",
		"",
		"Path to the rop chain file")

	ropGadgetsPath := flag.String(
		"rop-gadgets",
		"",
		"Path to the rop gadgets binary file (the nasm output file)")

	writeROPGadgets := flag.Bool(
		"write-gadgets",
		false,
		"Write gadgets to standard out")

	flag.Usage = func() {}
	flag.Parse()

	binaryRopGadgets, err := os.ReadFile(*ropGadgetsPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %s - %w", *ropGadgetsPath, err)
	}

	ropGadgetsMap := make(map[string]ropGadget)
	var parentGadget ropGadget
	var nextOffset uint64

	err = asm.DecodeX86(binaryRopGadgets, 64, func(inst x86asm.Inst, index int) {
		nextOffset += uint64(inst.Len)
		parentGadget.instructions = append(parentGadget.instructions, inst)

		if inst.Op == x86asm.RET {
			var previousOffset uint64 = parentGadget.offset
			var previousInstSize uint64

			for i := 0; i < len(parentGadget.instructions); i++ {
				childGadget := ropGadget{
					instructions: parentGadget.instructions[i:],
					offset:       previousOffset + previousInstSize,
				}

				ropGadgetsMap[childGadget.String()] = childGadget

				previousOffset = childGadget.offset
				previousInstSize = uint64(parentGadget.instructions[i].Len)
			}

			parentGadget = ropGadget{
				// TODO: nextOffset can get replaced by previousOffset + previousInstSize
				offset: nextOffset,
			}

			return
		}
	})

	if err != nil {
		return fmt.Errorf("failed to decode binary rop gadgets - %w", err)
	}

	if *writeROPGadgets {
		var gadgetList []ropGadget
		for _, ropGadget := range ropGadgetsMap {
			gadgetList = append(gadgetList, ropGadget)
		}

		sort.SliceStable(gadgetList, func(i, j int) bool {
			return gadgetList[i].offset < gadgetList[j].offset
		})

		for _, gadget := range gadgetList {
			fmt.Printf("offset: %d, gadget: %s\n", gadget.offset, gadget.String())
		}

		return nil
	}

	unresolvedRopChain, err := os.ReadFile(*ropChainPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %s - %w", *ropChainPath, err)
	}

	ropChain, err := parseROPChainGadgets(unresolvedRopChain, ropGadgetsMap)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(ropChain)
	if err != nil {
		return err
	}

	return nil
}

type ropGadget struct {
	instructions []x86asm.Inst
	offset       uint64
}

func (o *ropGadget) String() string {
	var ropGadgetInstructions string
	for index, inst := range o.instructions {
		if index == 0 {
			ropGadgetInstructions = strings.ToLower(inst.String())
		} else {
			ropGadgetInstructions += "; " + strings.ToLower(inst.String())
		}
	}

	return ropGadgetInstructions
}

func parseROPChainGadgets(unresolvedROPChain []byte, ropGadgetsMap map[string]ropGadget) ([]byte, error) {
	var ropChain []byte
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
			return nil, fmt.Errorf("separator ':' not found")
		}

		value = strings.TrimPrefix(value, "0x")
		switch ropType {
		case "g":
			ropGadget, hasIt := ropGadgetsMap[value]
			if !hasIt {
				return nil, fmt.Errorf("line %d: failed to find rop gadget in rop gadget binary: %q", lineNum, value)
			}

			ropOffset := ropGadget.offset | 0xba6865776dbe0000
			ropChain = binary.BigEndian.AppendUint64(ropChain, ropOffset)
		case "d", "D":
			if ropType == "d" && len(value) < 16 {
				value = strings.Repeat("0", 16-len(value)) + value
			}

			data, err := hex.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: failed to decode data - %w", lineNum, err)
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
