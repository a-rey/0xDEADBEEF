import sys
import mmap
import ctypes

# get user supplied shell code
print('[*] reading input ...')
shellcode = bytes.fromhex(input())
print('[*] shell code raw: {0}'.format(shellcode))
print('[*] shell code length: {0}'.format(len(shellcode)))

# map shell code into memory
page = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE | mmap.PROT_READ | mmap.PROT_EXEC)
page.write(shellcode)
addr = ctypes.addressof(ctypes.c_int.from_buffer(page))
print('[*] shell code mapped at {0}'.format(hex(addr)))

# get a function pointer to shell code and execute it
f = ctypes.CFUNCTYPE(None)(addr)
print('[*] running ...')
f()