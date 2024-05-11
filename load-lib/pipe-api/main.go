package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/ebitengine/purego"
)

// We apparently need binutils / something it relies on for this to work.
// New packages to be INSTALLED:
//        binutils: 2.40_5,1
//        liblz4: 1.9.4_1,1
//        zstd: 1.5.6
//
// pkg install binutils

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	flag.Parse()

	libraryPathTmp := flag.Arg(0)
	if libraryPathTmp == "" {
		return fmt.Errorf("please specify the library to load as the first non-flag argument")
	}

	libraryPath, err := filepath.Abs(libraryPathTmp)
	if err != nil {
		return err
	}

	funcName := flag.Arg(1)
	if funcName == "" {
		return fmt.Errorf("please specify the functon name to execute as the second non-flag argument")
	}

	log.Println("our pid is:", os.Getpid())

	for {
		err := loadAndUnload(libraryPath, funcName)
		if err != nil {
			return err
		}
	}
}

func loadAndUnload(libraryPath string, funcName string) error {
	log.Printf("> press enter to load '%s' and execute '%s()'",
		libraryPath, funcName)
	fmt.Scanln()

	p, err := newPipe()
	if err != nil {
		return err
	}
	defer p.Close()

	log.Printf("fds: ToLib: %d | FromLib: %d | ToUs: %d | FromUs: %d",
		p.ToLib.Fd(), p.FromLib.Fd(), p.ToUsFd, p.FromUsFd)

	go func() {
		scanner := bufio.NewScanner(p.FromLib)
		scanner.Scan()

		log.Printf("read: %q", scanner.Text())
		if scanner.Err() != nil {
			log.Printf("scanner failed - %s", scanner.Err())
			return
		}
	}()

	go func() {
		_, err := p.ToLib.Write([]byte("hello world\n"))
		if err != nil {
			log.Printf("write failed - %s", err)
			return
		}
	}()

	lib, err := purego.Dlopen(libraryPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}

	log.Println(".so mappings after load:")
	procstat()

	log.Printf("executing %s::%s()...\n--- begin fn execution", libraryPath, funcName)

	var fn func(readfd int32, writefd int32) uint8
	//var fn func()
	purego.RegisterLibFunc(&fn, lib, funcName)

	r := fn(p.FromUsFd, p.ToUsFd)
	if r != 0 {
		log.Printf("fn failed with status: %d", r)
	}

	log.Println("--- end fn execution")

	log.Printf("> press enter to *unload* the library")
	fmt.Scanln()
	purego.Dlclose(lib)

	log.Println(".so mappings after unload:")
	procstat()

	return nil
}

type pipe struct {
	ToLib    *os.File
	FromLib  *os.File
	FromUsFd int32
	ToUsFd   int32
}

func (o *pipe) Close() error {
	o.ToLib.Close()
	o.FromLib.Close()
	return nil
}

func newPipe() (*pipe, error) {
	usRead, libWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	libRead, usWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	return &pipe{
		ToLib:    usWrite,
		FromLib:  usRead,
		FromUsFd: int32(libRead.Fd()),
		ToUsFd:   int32(libWrite.Fd()),
	}, nil
}

func mustProcstat(libraryName string) {
	switch runtime.GOOS {
	case "freebsd":
		err := procstat()
		if err != nil {
			panic(err)
		}
	default:
		log.Printf("[warn] cannot get process address space mappings")
	}
}

func procstat() error {
	out, err := exec.Command(
		"doas",
		"procstat",
		"vm",
		fmt.Sprintf("%d", os.Getpid())).
		CombinedOutput()
	if err != nil {
		return err
	}

	w := os.Stderr

	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if !bytes.HasSuffix(scanner.Bytes(), []byte(".so")) {
			continue
		}

		i := bytes.Index(scanner.Bytes(), []byte("0x"))
		if i <= 0 {
			fmt.Errorf("expected mapping line to contain at least one 0x: %q",
				scanner.Text())
		}

		b := scanner.Bytes()[i:]

		fmt.Fprintf(w, "    %s\n", b)
		count++
	}

	if count == 0 {
		w.Write([]byte("    (buh, no .so mappings found)\n"))
	}

	return scanner.Err()
}
