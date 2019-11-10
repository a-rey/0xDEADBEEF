; non-NULL shellcode
section .text
global _start

_start:
  xor  rax, rax
  inc  eax          ; rax = syscall number for sys_write 
  xor  rdi, rdi
  inc  edi          ; rdi = stdout file descriptor
  jmp  get_msg_addr
write:
  pop  rsi          ; rsi = address of message string
  xor  rdx, rdx
  mov  dl, msg.len  ; rdx = length of message string
  syscall           ; write(stdout, message, strlen(message))
  xor  rax, rax
  mov  al, 0x3c     ; rax = syscall number for sys_exit
  xor  rdi, rdi     ; rdi = 0
  syscall           ; exit(0)
get_msg_addr:
  call write
msg:
  db "hello world!", 0xA
.len: equ $ - msg