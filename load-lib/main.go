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
		log.Printf("> press enter to load '%s' and execute '%s()'",
			libraryPath, funcName)
		fmt.Scanln()

		lib, err := purego.Dlopen(libraryPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			return err
		}

		log.Println(".so mappings after load:")
		procstat()

		log.Printf("executing %s::%s()...\n--- begin fn execution", libraryPath, funcName)

		var fn func()
		purego.RegisterLibFunc(&fn, lib, funcName)
		fn()

		log.Println("--- end fn execution")

		log.Printf("> press enter to *unload* the library")
		fmt.Scanln()
		purego.Dlclose(lib)

		log.Println(".so mappings after unload:")
		procstat()
	}
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
