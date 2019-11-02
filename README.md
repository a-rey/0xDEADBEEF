# 0xDEADBEEF
My collection of shellcode/assembly

## Contents

Each shell code payload directory has an `.asm` file with the shellcode and a test file. Execute the test file with `make test` or see a disassembly of the shellcode with `make print`.

## References

- macOS:
  - [System call table](https://opensource.apple.com/source/xnu/xnu-2782.20.48/bsd/kern/syscalls.master)
- linux
  - [System call table](https://syscalls.kernelgrok.com/)
