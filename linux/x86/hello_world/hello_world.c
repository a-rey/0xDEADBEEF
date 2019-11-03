#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x31\xc0\xb0\x04\x31\xdb\x43"
                            "\xeb\x0f\x59\x31\xd2\xb2\x0d"
                            "\xcd\x80\x31\xc0\xfe\xc0\x31"
                            "\xdb\xcd\x80\xe8\xec\xff\xff"
                            "\xff\x68\x65\x6c\x6c\x6f\x20"
                            "\x77\x6f\x72\x6c\x64\x21\x0a";

int main(void) {
  printf("[*] shellcode length: %d\n", strlen(shellcode));
  (*(void (*)())shellcode)();
  return 0;
}

