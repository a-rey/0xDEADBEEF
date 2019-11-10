; non-NULL shellcode
global start
section .text

start:
  xor  rax, rax
  mov  al, 0x2
  shl  eax, 0x18
  push rax          ; save syscall base (0x2000000) on stack
  add  al, 0x4      ; rax = syscall number for write (0x2000004)
  xor  rdi, rdi
  inc  edi          ; rdi = stdout
  jmp  get_msg_addr
write:
  pop  rsi          ; rsi = address of message string
  xor  rdx, rdx
  mov  dl, msg.len  ; rdx = length of message string
  syscall           ; write(stdout, message, strlen(message))
  pop  rax
  inc  al           ; rax = syscall number for exit (0x2000001)
  xor  rdi, rdi     ; rdi = 0
  syscall           ; exit(0)
get_msg_addr:
  call write
msg:
  db "hello world!", 0xA
.len: equ $ - msg