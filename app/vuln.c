//gcc -m32 -fno-stack-protector vuln.c -o vuln
#include <stdio.h>
#include <string.h>
#include <unistd.h>


void overflow (char* inbuf, char* argsInput)
{
  char buf[4];
  char str1[] = "A";
  int ret=0;
  strcpy(buf, inbuf);
  printf("Inputs + argument:  %s %s \n",inbuf, argsInput);
  if (strcmp(str1,inbuf)==0){
    char *binaryPath = "/usr/bin/ls";
    char *args[] = {binaryPath, argsInput, NULL};
    printf("I am option A\n");
    printf("I will execute...ls -l");
    ret=execv(binaryPath,args);
    printf("done");
  }  
  else {
  printf("invalid option!!!! Please Enter using capitals\n");
  }
  return;
}


int main (void)
{
  char strInput[64];
  char strInput2[64];
  
  printf("Enter option between A-B\n");
  scanf("%s %s", strInput, strInput2);
  printf("You entered: %s %s\n",strInput, strInput2);
  overflow(strInput, strInput2);
  
  

  return 0;
}