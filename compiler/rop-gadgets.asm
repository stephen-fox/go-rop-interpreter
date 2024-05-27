section .text

GLOBAL _start

_start:
[BITS 64]
ret

; pointer gadgets
mov rdi, rsp
pop r10
ret

; push gadgets
push rax
ret

push rbx
ret

push rcx
ret

push rdx
ret

push rsi
ret

push rdi
ret

push rsp
ret

; pop gadgets
pop rax
ret

pop rbx
ret

pop rcx
ret

pop rdx
ret

pop rsi
ret

pop rdi
ret

pop rsp
ret

pop r10
ret

pop r8
ret

pop r9
ret

; zero gadgets
xor rax, rax
ret

xor rbx, rbx
ret

xor rcx, rcx
ret

xor rdx, rdx
ret

xor rsi, rsi
ret

xor rdi, rdi
ret

xor rdx, rdx
ret

xor rsp, rsp
ret

; mov gadgets
mov rax, [rdx]
ret

; syscall gadget
int 0x80
ret

syscall
ret
