//gcc -m32 -fno-stack-protector vuln2.c -o vuln2

#include <string.h>

void overflow (char* inbuf)
{
  char buf[4];
  strcpy(buf, inbuf);
}

int main (int argc, char** argv)
{
  overflow(argv[1]);
  return 0;
}
