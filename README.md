# `0xDEADBEEF`

My collection of assembly

## Contents:

Each directory has an `.asm` file with the assembly and a corresponding test file. Execute the test file with `make test` or see a disassembly with `make print`.

## Platform Notes:

- macOS:
  - [System Call Table](https://opensource.apple.com/source/xnu/xnu-2782.20.48/bsd/kern/syscalls.master)
- Linux:
  - [System Call Arguments](https://syscalls.kernelgrok.com/)
  - [x86/64 System Call Calling Conventions](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-on-i386-and-x86-6)
  - [x86 System Call Table](https://elixir.free-electrons.com/linux/latest/source/arch/x86/entry/syscalls/syscall_32.tbl)
  - [x64 System Call Table](https://elixir.free-electrons.com/linux/latest/source/arch/x86/entry/syscalls/syscall_64.tbl)
- Windows:
  - [x86 Calling Conventions](https://en.wikipedia.org/wiki/X86_calling_conventions#cdecl)
  - [x64 Calling Conventions](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention)
  - [Windows TEB](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm)
  - [x86 TEB to kernel32.dll Translation](https://idafchev.github.io/images/windows_shellcode/locate_dll1.gif)
  - Environment Setup on Windows 10:
    - Enable Windows Subsystem for Linux (WSL):

    ```powershell
    # run in an Administrator window
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    ```
    - Reboot machine
    - Install Ubuntu WSL version from Microsoft Store
    - Enable OpenSSH Server:

    ```powershell
    # run in an Administrator window
    Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    ```
    - SSH into Windows Box and start Bash shell from the `cmd.exe` prompt by running `powershell` then `bash`
    - Environment setup after installing Windows subsystem for linux (Ubuntu flavor):

    ```bash
    # installs mingw cross-compiler into linux subsystem for compiling shellcode
    sudo apt update
    sudo apt upgrade
    sudo apt install nasm make mingw-w64
    ```
    - For testing/debugging, install [MinGW32](http://www.mingw.org/wiki/Getting_Started). Allows for debugging of shellcode (on a default install of MinGW32, gdb will be at `/mnt/c/MinGW/bin/`):

    ```
    /mnt/c/MinGW/bin/gdb.exe MessageBox.exe
    GNU gdb (GDB) 7.6.1
    ...
    (gdb) p/x &shellcode
    $1 = 0x403020
    (gdb) b *0x403020
    Breakpoint 1 at 0x403020
    (gdb) r
    Starting program: MessageBox.exe
    [New Thread 4004.0x1514]
    [New Thread 4004.0x1dc4]
    
    Breakpoint 1, 0x00403020 in shellcode ()
    (gdb)
    ```
  - Fixing `Operation did not complete successfully because the file contains a virus` Windows error for testing shellcode:
    - Open the _Settings app_ and go to the **Update & Security** section. In the left pane navigate to **Windows Defender** and in the right pane disable **Real-time protection**.