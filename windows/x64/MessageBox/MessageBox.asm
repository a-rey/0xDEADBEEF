; position independent non-NULL shellcode
BITS 64
section .text
global _start

_start:
  jmp start                        ; jump to program start (keeps PIC offsets from having NULLs)
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; get_address(1, 2, 3)
;   rcx = (1) DLL base address
;   rdx = (2) pointer to function string to look for
;   r8  = (3) strlen(function string)
;   - returns in rax the virtual address of the function from the DLL provided
;   - clobbers rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11
;   - does not modify the stack
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
get_address:
  xor  r9, r9                      ; zero register
  mov  r9d, [rcx + 0x3C]           ; get RVA of PE header (4 byte value)
  add  r9, rcx                     ; get virtual address of PE header
  xor  r11, r11                    ; zero register
  mov  r11d, [r9 + 0x88]           ; get RVA of export table in PE header
  add  r11, rcx                    ; get virtual address of export table
  xor  r9, r9                      ; zero register
  mov  r9d, [r11 + 0x20]           ; get RVA of name pointer table in export table
  add  r9, rcx                     ; get virtual address of name pointer table
  xor  rax, rax                    ; zero register
  mov  eax, [r11 + 0x18]           ; get number of exported *named* functions from export table
  xchg rcx, r10                    ; save dll base in r10
.loop:                             ; loop through name pointer table backwards
  dec  eax                         ; go to the next name pointer
  mov  rcx, r8                     ; get length of target string
  mov  rdi, rdx                    ; get pointer to target string
  xor  rsi, rsi                    ; zero register
  mov  esi, [r9 + (rax * 0x4)]     ; get RVA of next pointer from name table (entries are 4 bytes long)
  add  rsi, r10                    ; get virtual address of next pointer from name table 
  repe cmpsb                       ; compare till rcx = 0 or hit a NULL byte
  jnz  get_address.loop            ; if rcx != 0, then keep looping
  xor  rsi, rsi                    ; zero register
  mov  esi, [r11 + 0x24]           ; get the RVA of the ordinal table in export table
  add  rsi, r10                    ; get the virtual address of the ordinal table
  xor  rdx, rdx                    ; zero register
  mov  dx, [rsi + (rax * 0x2)]     ; get the ordinal number of the target function from the ordinal table (entries are 2 bytes long)
  xor  rsi, rsi                    ; zero register
  mov  esi, [r11 + 0x1C]           ; get RVA of address table in export table
  add  rsi, r10                    ; get the virtual address of the address table
  mov  edx, [rsi + (rdx * 0x4)]    ; get the RVA of the target function
  add  rdx, r10                    ; get the virtual address of the target function
  xchg rdx, rax                    ; set return value
  ret
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; main routine:
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
start:
  and  rsp, 0xFFFFFFFFFFFFFFF0     ; align stack to 16 bytes
  xor  rbp, rbp                    ; keep rbp as constant NULL for program
  mov  rbx, [gs:ebp + 0x60]        ; get address of PEB from TEB
  mov  rbx, [rbx + 0x18]           ; get pointer to PEB_LDR_DATA in PEB
  mov  rbx, [rbx + 0x20]           ; get pointer to LDR_MODULE[0] from Flink of InMemoryOrderModuleList in PEB_LDR_DATA
  mov  rbx, [rbx]                  ; get pointer to ntdll.dll
  mov  rbx, [rbx]                  ; get pointer to kernel32.dll
  mov  rbx, [rbx + 0x20]           ; get pointer to BaseAddress of kernel32.dll
;   push LoadLibraryA.len
;   jmp  LoadLibraryA 
; _LoadLibraryA:
;   push ebx 
;   call get_address                 ; get_address(kernel32.dll, 'LoadLibraryA', strlen('LoadLibraryA'))
;   jmp  User32
; _User32:
;   mov  esi, [esp]
;   mov  word [esi + User32.len], bp ; get dll pointer and add NULL termination to string
;   call eax                         ; LoadLibraryA('user32')
;   push MessageBoxA.len 
;   jmp  MessageBoxA
; _MessageBoxA:
;   push eax 
;   call get_address                 ; get_address(user32.dll, 'MessageBoxA', strlen('MessageBoxA'))
;   push ebp
;   push ebp
;   jmp  msg
; _msg:
;   mov  esi, [esp] 
;   mov  word [esi + msg.len], bp    ; get message pointer and add NULL termination to string
;   push ebp
;   call eax                         ; MessageBox(NULL, message, NULL, NULL)
;   push ExitProcess.len
;   jmp  ExitProcess
; _ExitProcess:
;   mov  ebx, [esp + 0x24]           ; load kernel32.dll address off of stack from call to 1st get_address()
;   push ebx
;   call get_address                 ; get_address(kernel32.dll, "ExitProcess", strlen("ExitProcess"))
;   push ebp
;   call eax                         ; ExitProcess(0)

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; position independent code (PIC) data:
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; LoadLibraryA:
;   call  _LoadLibraryA
; .string:
;   db "LoadLibraryA"
; .len: equ $ - LoadLibraryA.string

; User32:
;   call  _User32
; .string:
;   db "user32", 0x30, 0x30          ; NULL byte set at runtime (with a store WORD not BYTE)
; .len: equ $ - User32.string - 0x2  ; 2 byte offset to point to first temp 0x30 byte
 
; MessageBoxA:
;   call _MessageBoxA
; .string:
;   db "MessageBoxA"
; .len: equ $ - MessageBoxA.string

; msg:
;   call _msg
; .string:
;   db "Hello World!", 0x30, 0x30    ; NULL byte set at runtime (with a store WORD not BYTE)
; .len: equ $ - msg.string - 0x2     ; 2 byte offset to point to first temp 0x30 byte

; ExitProcess:
;   call _ExitProcess
; .string:
;   db "ExitProcess"
; .len: equ $ - ExitProcess.string
