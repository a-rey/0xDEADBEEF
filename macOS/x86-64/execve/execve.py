import sys
import mmap
import ctypes

shellcode = (b'\x48\x31\xd2\x52\x48\xbf\x2f\x2f\x62\x69\x6e'
             b'\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xf6\x48'
             b'\x31\xc0\xb0\x02\xc1\xe0\x18\xb0\x3b\x0f\x05')

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