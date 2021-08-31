//gcc -m32 -fno-stack-protector -no-pie vuln.c -o vuln

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
