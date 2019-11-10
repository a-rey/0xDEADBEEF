; position independent non-NULL shellcode
BITS 32
section .text
global _start

_start:
  jmp start                        ; jump to program start (keeps PIC offsets from having NULLs)
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; get_address(1, 2, 3)
;   [esp + 0xC] = (3) strlen(function string)
;   [esp + 0x8] = (2) pointer to function string to look for
;   [esp + 0x4] = (1) DLL base address
;   [esp + 0x0] = return address from call
;   - returns in eax the virtual address of the function from the DLL provided
;   - all registers are caller saved except for ebp/esp
;   - caller responsible for stack cleanup
;   - does not modify arguments passed in on the stack
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
get_address:
  mov  eax, [esp + 0x4]            ; get DLL base address
  mov  ebx, [eax + 0x3C]           ; get RVA of PE header
  add  ebx, eax                    ; get virtual address of PE header
  mov  ebx, [ebx + 0x78]           ; get RVA of export table in PE header
  add  ebx, eax                    ; get virtual address of export table
  mov  edx, [ebx + 0x20]           ; get RVA of name pointer table in export table
  add  edx, eax                    ; get virtual address of name pointer table
  mov  eax, [ebx + 0x18]           ; get number of exported *named* functions from export table
.loop:                             ; loop through name pointer table backwards
  dec  eax                         ; go to the next name pointer
  mov  ecx, [esp + 0xC]            ; get length of target string
  mov  edi, [esp + 0x8]            ; get pointer to target string
  mov  esi, [edx + (eax * 0x4)]    ; get RVA of next pointer from name table (entries are 4 bytes long)
  add  esi, [esp + 0x4]            ; get virtual address of next pointer from name table 
  repe cmpsb                       ; compare till ecx = 0 or hit a NULL byte
  jnz  get_address.loop            ; if ecx != 0, then keep looping
  mov  esi, [ebx + 0x24]           ; get the RVA of the ordinal table in export table
  add  esi, [esp + 0x4]            ; get the virtual address of the ordinal table
  mov  ax,  [esi + (eax * 0x2)]    ; get the ordinal number of the target function from the ordinal table (entries are 2 bytes long)
  mov  esi, [ebx + 0x1C]           ; get RVA of address table in export table
  add  esi, [esp + 0x4]            ; get the virtual address of the address table
  mov  eax, [esi + (eax * 0x4)]    ; get the RVA of the target function
  add  eax, [esp + 0x4]            ; get the virtual address of the target function
  ret
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; main routine:
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
start:
  xor  ebp, ebp                    ; keep ebp as constant NULL for program
  mov  ebx, [fs:ebp + 0x30]        ; get address of PEB from TEB
  mov  ebx, [ebx + 0xC]            ; get pointer to PEB_LDR_DATA in PEB
  mov  ebx, [ebx + 0x14]           ; get pointer to LDR_MODULE[0] from Flink of InMemoryOrderModuleList in PEB_LDR_DATA
  mov  ebx, [ebx]                  ; get pointer to ntdll.dll
  mov  ebx, [ebx]                  ; get pointer to kernel32.dll
  mov  ebx, [ebx + 0x10]           ; get pointer to BaseAddress of kernel32.dll
  push LoadLibraryA.len
  jmp  LoadLibraryA 
_LoadLibraryA:
  push ebx 
  call get_address                 ; get_address(kernel32.dll, 'LoadLibraryA', strlen('LoadLibraryA'))
  jmp  User32
_User32:
  mov  esi, [esp]
  mov  word [esi + User32.len], bp ; get dll pointer and add NULL termination to string
  call eax                         ; LoadLibraryA('user32')
  push MessageBoxA.len 
  jmp  MessageBoxA
_MessageBoxA:
  push eax 
  call get_address                 ; get_address(user32.dll, 'MessageBoxA', strlen('MessageBoxA'))
  push ebp
  push ebp
  jmp  msg
_msg:
  mov  esi, [esp] 
  mov  word [esi + msg.len], bp    ; get message pointer and add NULL termination to string
  push ebp
  call eax                         ; MessageBox(NULL, message, NULL, NULL)
  push ExitProcess.len
  jmp  ExitProcess
_ExitProcess:
  mov  ebx, [esp + 0x24]           ; load kernel32.dll address off of stack from call to 1st get_address()
  push ebx
  call get_address                 ; get_address(kernel32.dll, "ExitProcess", strlen("ExitProcess"))
  push ebp
  call eax                         ; ExitProcess(0)

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; position independent code (PIC) data:
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

LoadLibraryA:
  call  _LoadLibraryA
.string:
  db "LoadLibraryA"
.len: equ $ - LoadLibraryA.string

User32:
  call  _User32
.string:
  db "user32", 0x30, 0x30          ; NULL byte set at runtime (with a store WORD not BYTE)
.len: equ $ - User32.string - 0x2  ; 2 byte offset to point to first temp 0x30 byte
 
MessageBoxA:
  call _MessageBoxA
.string:
  db "MessageBoxA"
.len: equ $ - MessageBoxA.string

msg:
  call _msg
.string:
  db "Hello World!", 0x30, 0x30    ; NULL byte set at runtime (with a store WORD not BYTE)
.len: equ $ - msg.string - 0x2     ; 2 byte offset to point to first temp 0x30 byte

ExitProcess:
  call _ExitProcess
.string:
  db "ExitProcess"
.len: equ $ - ExitProcess.string
