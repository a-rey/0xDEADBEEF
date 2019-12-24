#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x48\x31\xc0\xff\xc0\x48\x31\xff"
                            "\xff\xc7\xeb\x12\x5e\x48\x31\xd2"
                            "\xb2\x0d\x0f\x05\x48\x31\xc0\xb0"
                            "\x3c\x48\x31\xff\x0f\x05\xe8\xe9"
                            "\xff\xff\xff\x68\x65\x6c\x6c\x6f"
                            "\x20\x77\x6f\x72\x6c\x64\x21\x0a";

int main(void) {
  printf("[*] shellcode length: %d\n", strlen(shellcode));
  (*(void (*)())shellcode)();
  return 0;
}

