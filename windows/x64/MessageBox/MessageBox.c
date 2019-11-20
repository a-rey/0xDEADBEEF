#include <stdio.h>
#include <string.h>
#include <windows.h>

unsigned char shellcode[] = {
  0x00
};

int main(void) {
  DWORD flag = 0;
  int len = strlen(shellcode);
  printf("[*] shellcode length: %d\n", len);
  VirtualProtect(shellcode, len, PAGE_EXECUTE_READWRITE, &flag);
  (*(void (*)())shellcode)();
  return 0;
}