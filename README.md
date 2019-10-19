# 0xDEADBEEF
My collection of shellcode/assembly

## Contents

Each shell code payload directory has a `.bin` file containing the hex representation of the assembled shell code. Test payloads in Python with the following code:

```python
import mmap
import ctypes

shellcode = "<copy and paste from .bin file>"
page = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE | mmap.PROT_READ | mmap.PROT_EXEC)
page.write(shellcode)
addr = ctypes.addressof(ctypes.c_int.from_buffer(page))
f = ctypes.CFUNCTYPE(None)(addr)
f()
```

or compile and test the payload in C:

```c
char shellcode[] = "<copy and paste from .bin file>";

int main() {
  void(*f)() = (void *)shellcode;
  f();
  return 0;
}
```

## References

- macOS:
  - [System call table](https://opensource.apple.com/source/xnu/xnu-2782.20.48/bsd/kern/syscalls.master)
- linux
  - [System call table](https://syscalls.kernelgrok.com/)
