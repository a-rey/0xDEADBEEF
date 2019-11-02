; non-NULL shellcode
section .text
global _start

_start:
  xor  eax, eax
  mov  al, 0x4      ; eax = syscall number for sys_write 
  xor  ebx, ebx
  inc  ebx          ; ebx = stdout file descriptor
  jmp  get_msg_addr
write:
  pop  ecx          ; ecx = address of message string
  xor  edx, edx
  mov  dl, msg.len  ; edx = length of message string
  int  0x80         ; write(stdout, message, strlen(message))
  xor  eax, eax
  inc  al           ; eax = syscall number for sys_exit
  xor  ebx, ebx     ; ebx = 0
  int  0x80         ; exit(0)
get_msg_addr:
  call write
msg:
  db "hello world!", 0xA
.len: equ $ - msg