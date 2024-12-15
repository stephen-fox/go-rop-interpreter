// compiler attempts to ease the difficulty of writing ROP chains by
// compiling a human readable "source" format into a binary ROP chain.
// compiler writes the resulting "unresolved ROP chain" to stdout.
//
// # How it works
//
// Compilation is accomplished by first parsing two pieces of data:
//
//   - A ROP chain source file
//   - A binary file containing ROP gadgets. This must be injected
//     into the runner program using the injector program (this file
//     can be generated using the "nasm" assembler, refer to the
//     examples directory)
//
// ROP gadgets referenced in the source file are looked-up in the specified
// ROP chain binary file. The "chain" file should match the data that was
// written to the runner program using the injector program.
//
// The compiler translates the source file into a payload known as the
// "unsresolved ROP chain" which is interpreted by the runner program
// at runtime.
//
// While we assume the runner program is written in Go, there is (theoretically)
// nothing stopping us from writing the the runner in a different programming
// language. There is no contract between the compiler and the runner beyond
// resolving gadget offsets into addresses.
//
// # Source file format
//
// The ROP chain source file consists of newline delimited strings. Each line
// starts with an identifier string followed by arguments in the format of:
//
//	<identifier-string> <argument>
//
// Possible identifier strings consists of the following:
//
//   - g: ROP gadget in human-readable assembly format
//   - d: A blob of arbitrary, hex-encoded data (automatically
//     left-padded with zeros)
//   - D: Same as "d", but no zero padding is performed
//
// # Output file format
//
// The compiler produces a blob of binary data that we refer to as the
// "unresolved ROP chain". It is "unresolved" because each gadget is
// represented by its offset within the ROP gadget file. We use offsets
// because gadgets' memory addresses cannot be known ahead of time due
// to PIE and ASLR. Thus, the runner program must resolve these offsets
// into memory addresses when it parses the unresolved ROP chain.
//
// The runner program assumes that the first instruction in the chain
// is a "ret" instruction. This begins execution of the ROP chain.
//
// # Future work
//
// We can potentially make this less error-prone by reading the available
// ROP gadgets from the runner program. We did not pursue this because
// we were unsure how Go programs may be structured in the future.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"rop-interpreter/internal/asm"

	"golang.org/x/arch/x86/x86asm"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalf("fatal: %s", err)
	}
}

func mainWithError() error {
	chainSrcPath := flag.String(
		"src",
		"",
		"Path to the ROP chain source file")

	availableGadgetsPath := flag.String(
		"gadgets",
		"",
		"Path to a binary file containing available ROP gadgets (the nasm output file)")

	writeGadgetsStdout := flag.Bool(
		"write-gadgets",
		false,
		"Write ROP gadgets found in the available gadgets file to stdout and exit")

	flag.Parse()

	binaryRopGadgets, err := os.ReadFile(*availableGadgetsPath)
	if err != nil {
		return fmt.Errorf("failed to read available gadgets file %q - %w",
			*availableGadgetsPath, err)
	}

	availableGadgets := make(map[string]ropGadget)
	var parentGadget ropGadget
	var nextOffset uint64

	// Populate the available gadgets map with gadgets found
	// in the binary gadgets blob.
	err = asm.DecodeX86(binaryRopGadgets, 64, func(inst x86asm.Inst, index int) {
		nextOffset += uint64(inst.Len)
		parentGadget.instructions = append(parentGadget.instructions, inst)

		if inst.Op == x86asm.RET {
			var parentOffset uint64 = parentGadget.offset
			var previousInstSize uint64

			// The following code creates multiple gadgets
			// for instruction sequences that contain more
			// than one instruction. For example, consider
			// the following gadget:
			//
			//   pop rdi
			//   pop rsi
			//   pop rdx
			//   ret
			//
			// While the above example is only one gadget,
			// it can be logically divided into four gadgets:
			//
			//   1. pop rdi; pop rsi; pop rdx; ret
			//   2. pop rsi; pop rdx; ret
			//   3. pop rdx; ret
			//   4. ret
			//
			// This allows the compiler to reuse existing ROP
			// gadgets if they contain a useful instruction.
			for i := 0; i < len(parentGadget.instructions); i++ {
				childGadget := ropGadget{
					instructions: parentGadget.instructions[i:],
					offset:       parentOffset + previousInstSize,
				}

				availableGadgets[childGadget.String()] = childGadget

				parentOffset = childGadget.offset
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

	if *writeGadgetsStdout {
		var gadgetList []ropGadget
		for _, ropGadget := range availableGadgets {
			gadgetList = append(gadgetList, ropGadget)
		}

		sort.SliceStable(gadgetList, func(i, j int) bool {
			return gadgetList[i].offset < gadgetList[j].offset
		})

		for _, gadget := range gadgetList {
			fmt.Printf("offset: %d, gadget: %s\n",
				gadget.offset, gadget.String())
		}

		return nil
	}

	chainSrc, err := os.ReadFile(*chainSrcPath)
	if err != nil {
		return fmt.Errorf("failed to read rop chain source file %q - %w",
			*chainSrcPath, err)
	}

	ropChain, err := compileRopChain(chainSrc, availableGadgets)
	if err != nil {
		return fmt.Errorf("failed to compile rop chain - %w", err)
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

// compileRopChain takes ROP chain source data, looks up its
// gadgets in the specified map and produces a binary ROP chain
// consisting of gadgets and their offsets.
//
// The ROP runner / interpreter must lookup the final addresses
// of the gadgets at runtime due to PIE and ASLR.
func compileRopChain(chainSrc []byte, availableGadgets map[string]ropGadget) ([]byte, error) {
	var ropChain []byte
	scanner := bufio.NewScanner(bytes.NewReader(chainSrc))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		ropType, value, found := strings.Cut(line, ": ")
		if !found {
			return nil, fmt.Errorf("line %d: separator ':' not found", lineNum)
		}

		value = strings.TrimPrefix(value, "0x")
		switch ropType {
		case "g":
			ropGadget, hasIt := availableGadgets[value]
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

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return ropChain, nil
}
