//gcc -m32 -fno-stack-protector vuln.c -o vuln
#include <stdio.h>
#include <string.h>
#include <unistd.h>


void overflow (char* inbuf)
{
  char buf[4];
  char str1[] = "A";
  strcpy(buf, inbuf);
  if (strcmp(str1,inbuf)==0){
    printf("I am option A\n");
  }  
  else {
  printf("invalid option!!!! Please Enter using capitals\n");
  }
  return;
}



int main (void)
{
  char strInput[64];
  
  printf("Enter option between A-B\n");
  scanf("%s", strInput);
  printf("You entered: %s\n",strInput);
  overflow(strInput);
  
  

  return 0;
}