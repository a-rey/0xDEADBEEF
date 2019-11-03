# 0xDEADBEEF
My collection of shellcode/assembly

## Contents

Each shellcode payload directory has a `.asm` file with the shellcode and a test file. Execute the test file with `make test` or see a disassembly of the shellcode with `make print`.

## References

- macOS:
  - [System Call Table](https://opensource.apple.com/source/xnu/xnu-2782.20.48/bsd/kern/syscalls.master)
- linux
  - [System Call Arguments](https://syscalls.kernelgrok.com/)
  - [x86/64 System Call Calling Conventions](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-on-i386-and-x86-6)
  - [x86 System Call Table](https://elixir.free-electrons.com/linux/latest/source/arch/x86/entry/syscalls/syscall_32.tbl)
  - [x64 System Call Table](https://elixir.free-electrons.com/linux/latest/source/arch/x86/entry/syscalls/syscall_64.tbl)
