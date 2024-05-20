package main

import (
	"compiler/asm"
	"flag"
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"log"
	"os"
)

// rop chain file
// binary rop gadgets
func main() {
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

	flag.Parse()

	ropChain, err := os.ReadFile(*ropChainPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %s - %w", *ropChainPath, err)
	}
	_ = ropChain

	binaryRopGadgets, err := os.ReadFile(*ropGadgetsPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %s - %w", *ropGadgetsPath, err)
	}

	var ropGadgets []ropGadget
	var currentRopGadget ropGadget
	var nextOffset uint64

	err = asm.DecodeX86(binaryRopGadgets, 64, func(inst x86asm.Inst, index int) {
		nextOffset += uint64(inst.Len)
		currentRopGadget.instructions = append(currentRopGadget.instructions, inst)

		if inst.Op == x86asm.RET {
			ropGadgets = append(ropGadgets, currentRopGadget)

			currentRopGadget = ropGadget{
				offset: nextOffset,
			}

			return
		}
	})

	if err != nil {
		return fmt.Errorf("failed to decode binary rop gadgets - %w", err)
	}

	for _, gadget := range ropGadgets {
		log.Printf("%d - %v", gadget.offset, gadget.instructions)
	}

	return nil
}

type ropGadget struct {
	instructions []x86asm.Inst
	offset       uint64
}
