package main

import (
	"debug/elf"
	"debug/pe"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	exePathArg        = "f"
	exeTypeArg        = "t"
	symbolNameArg     = "n"
	ropGadgetsPathArg = "i"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	exePath := flag.String(
		exePathArg,
		"",
		"The executable to parse")

	exeType := flag.String(
		exeTypeArg,
		"",
		"The executable file type ('elf' or 'pe')")

	symbolName := flag.String(
		symbolNameArg,
		"",
		"The name of the dummy function to locate")

	ropGadgetsPath := flag.String(
		ropGadgetsPathArg,
		"",
		"Path to the rop gadgets file to overwrite the dymmy function with")

	flag.Parse()

	var err error
	flag.VisitAll(func(f *flag.Flag) {
		if err != nil {
			return
		}

		if f.Value.String() == "" {
			err = fmt.Errorf("please specify '-%s' - %s",
				f.Name, f.Usage)
		}
	})
	if err != nil {
		return err
	}

	out := os.Stdout

	ropGadgets, err := os.ReadFile(*ropGadgetsPath)
	if err != nil {
		return err
	}

	f, err := os.Open(*exePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var sym symbol
	switch *exeType {
	case "elf":
		sym, err = findElfSymbol(f, *symbolName)
	case "pe":
		sym, err = findPeSymbol(f, *symbolName)
	default:
		return fmt.Errorf("unsupported exe type: %q", *exeType)
	}
	if err != nil {
		return fmt.Errorf("failed to find symbol - %w", err)
	}

	log.Printf("size: %d | location: 0x%x", sym.Size, sym.Location)

	if len(ropGadgets) > int(sym.Size) {
		return fmt.Errorf("rop gadgets size must be %d bytes to overwrite function",
			sym.Size)
	}

	for len(ropGadgets) < int(sym.Size) {
		// pad the end with NOPs
		ropGadgets = append(ropGadgets, 0x90)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	_, err = io.CopyN(out, f, int64(sym.Location))
	if err != nil {
		return fmt.Errorf("failed to copy initial part of exe to output - %w", err)
	}

	_, err = out.Write(ropGadgets)
	if err != nil {
		return fmt.Errorf("failed to copy rop gadgets into %s - %w",
			*symbolName, err)
	}

	_, err = f.Seek(int64(sym.Size+sym.Location), io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to offset *after* dummy function - %w", err)
	}

	_, err = io.Copy(out, f)
	if err != nil {
		return fmt.Errorf("failed to copy remainder of file to output - %w", err)
	}

	return nil
}

func findElfSymbol(readerAt io.ReaderAt, symbolName string) (symbol, error) {
	elfFile, err := elf.NewFile(readerAt)
	if err != nil {
		return symbol{}, err
	}

	syms, err := elfFile.Symbols()
	if err != nil {
		return symbol{}, err
	}

	text := elfFile.Section(".text")
	if text == nil {
		return symbol{}, fmt.Errorf("elf is missing .text section")
	}

	for _, sym := range syms {
		if sym.Name != symbolName {
			continue
		}

		// https://stackoverflow.com/a/40249502
		// fn symbol VA - .text VA + .text offset
		return symbol{
			Name:     sym.Name,
			Location: sym.Value - text.Addr + text.Offset,
			Size:     sym.Size,
		}, nil
	}

	return symbol{}, fmt.Errorf("failed to find symbol: %q", symbolName)
}

func findPeSymbol(readerAt io.ReaderAt, symbolName string) (symbol, error) {
	peFile, err := pe.NewFile(readerAt)
	if err != nil {
		return symbol{}, err
	}

	for i, sym := range peFile.Symbols {
		if sym.Name != symbolName {
			continue
		}

		var end uint32
		if i < len(peFile.Symbols)-1 {
			end = peFile.Symbols[i+1].Value
		}

		// TODO: The location is probably wrong.
		return symbol{
			Name:     sym.Name,
			Location: uint64(sym.Value),
			Size:     uint64(end - sym.Value),
		}, nil
	}

	return symbol{}, fmt.Errorf("failed to find symbol: %q", symbolName)
}

type symbol struct {
	Name     string
	Location uint64
	Size     uint64
}
