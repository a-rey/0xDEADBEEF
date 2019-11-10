import sys
import mmap
import ctypes

shellcode = (b'\x48\x31\xc0\xb0\x02\xc1\xe0\x18\x50\x04\x04\x48\x31'
             b'\xff\xff\xc7\xeb\x10\x5e\x48\x31\xd2\xb2\x0d\x0f\x05'
             b'\x58\xfe\xc0\x48\x31\xff\x0f\x05\xe8\xeb\xff\xff\xff'
             b'\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21\x0a')

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