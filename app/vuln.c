//gcc -m32 -fno-stack-protector -no-pie vuln.c -o vuln
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void execWhoami ()
{
  
  int ret=0;
  char *binaryPath = "/usr/bin/whoami";
  char *args[] = {binaryPath, NULL};
  printf("I will execute...whoami\n");
  printf("\n");
  ret=execv(binaryPath,args);  
  return;
}

void execNmap (char* argsInput1, char* argsInput2)
{
  
  int ret=0;
  char *binaryPath = "/usr/bin/nmap";
  char *args[] = {binaryPath, "-sS", "-p", argsInput1, argsInput2, "-T5",NULL};
  printf("I am option A\n");
  printf("I will execute...nmap\n");
  ret=execv(binaryPath,args);
  return;
}

void helpCommand (char* inputArgs)
{
  printf("I will execute...DOOM!!!!!!!%s\n", inputArgs);
  exit(0);
}



int main (int argc, char** argv)
{
  char strInput[64];
  char strInput2[64];
  char optionA[64] = "A", optionB[64] = "B", optionQ[64] = "Q", help[16] = "h";
  char buf[64];
  
  if (argv[1]){
  strcpy(buf, argv[1]);
  }

  if (strcmp(buf, help)==0){
  printf("gotHIM!!!!");
  helpCommand(buf);
  }

  
   printf(R"EOF(
||====================================================================||
||//$\\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\//$\\||
||(100)==================|    DAMN VULNERABLE   |================(100)||
||\\$//                  '------========--------'                \\$//||
||<<|                                                              |>>||
||>>|								   |<<||
||<<|       █▀▄▀█ ▄▀█ █▄▀ █▀▀   █ ▀█▀   █▀█ ▄▀█ █ █▄░█	    |>>||
||>>|       █░▀░█ █▀█ █░█ ██▄   █ ░█░   █▀▄ █▀█ █ █░▀█      |<<||
||<<|								   |>>||
||>>|			       __________                          |<<||
||<<\      $$$$$$$$$     _____/          \________    $$$$$$$$$    />>||
||//$\                 ~|       ZEIT 8042        |~               /$\\||
||(100)===================     PASS 4 SURE      =================(100)||
||\\$//\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\\$//||
||====================================================================||
)EOF");
  printf("Select option to run as root: \n");
  printf("[A] Run Whoami\n");
  printf("[B] Run nmap\n");
  printf("[Q] Quit \n");
  scanf("%s", strInput);
  printf("You entered: %s\n",strInput);
  
  
  if (strcmp(strInput, optionA)==0){
  execWhoami();
  }
  if (strcmp(strInput, optionB)==0){
  printf("Please enter a port number!!\n");
  scanf("%s", strInput);
  printf("Please enter an IP address!!\n");
  scanf("%s", strInput2);
  execNmap(strInput, strInput2);
  }
  if (strcmp(strInput, optionQ)==0){
  printf("Okay.....exiting....\n");
  }
  else {
    printf("invalid option!!!! Please Enter using capitals\n");
  }
  printf("done....\n");
  
  return 0;
}