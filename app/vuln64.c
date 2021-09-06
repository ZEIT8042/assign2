//Author: z5332187 Phillip McCullough
//University of New South Wales: Masters of Cyber Security
//Course: ZEIT8042
//Compile usiing: gcc -fno-stack-protector -no-pie vuln64.c -o vuln64
//System used: Linux 5.10.0-kali9-amd64 SMP Debian 5.10.46-1kali1 (2021-06-25) x86_64 GNU/Linux

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void execWhoami ()	//execute whoami commd and print result result to terminal
{
  
  int ret=0;
  char *binaryPath = "/usr/bin/whoami";
  char *args[] = {binaryPath, NULL};
  printf("I will execute...whoami\n");
  printf("\n");
  ret=execv(binaryPath,args);  
  return;
}

void execNmap (char* argsInput1, char* argsInput2)	//execute nmap command and print results to terminal
{
  
  int ret=0;
  char *binaryPath = "/usr/bin/nmap";
  char *args[] = {binaryPath, "-sS", "-p", argsInput1, argsInput2, "-T5",NULL};	// args for port and IP address
  printf("I am option A\n");
  printf("I will execute...nmap\n");
  ret=execv(binaryPath,args);
  return;
}

void helpCommand (char* inputArgs)	//vulnerable function
{
  char buffer[48];
  puts("This is an admin tools to run programs with elevated privileges");
  puts("Press Enter to return...");
  gets(buffer);				//BoF input occurs here
  return;
}



int main (int argc, char** argv)
{
  char strInput[64];					//initialize string variables
  char strInput2[64];
  char optionA[64] = "A", optionB[64] = "B", optionQ[64] = "Q", help[16] = "h";
  
  
  if (argc > 1){		//if an argument is passed, execute helpCommand vulnerable function
  helpCommand(argv[1]);
  }
  else{
  printf("For help use: ./vuln64 h \n");
  }

  
   printf(R"EOF(
░█████╗░██████╗░███╗░░░███╗██╗███╗░░██╗  ████████╗░█████╗░░█████╗░██╗░░░░░░██████╗
██╔══██╗██╔══██╗████╗░████║██║████╗░██║  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░██╔════╝
███████║██║░░██║██╔████╔██║██║██╔██╗██║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░╚█████╗░
██╔══██║██║░░██║██║╚██╔╝██║██║██║╚████║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░░╚═══██╗
██║░░██║██████╔╝██║░╚═╝░██║██║██║░╚███║  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗██████╔╝
╚═╝░░╚═╝╚═════╝░╚═╝░░░░░╚═╝╚═╝╚═╝░░╚══╝  ░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝╚═════╝░
||=================================================================================||
)EOF");
  printf("Select option to run as root: \n");		//prompt series of options to execute
  printf("[A] Run Whoami\n");
  printf("[B] Run nmap\n");
  printf("[Q] Quit \n");
  scanf("%s", strInput);
  printf("You entered: %s\n",strInput);
  
  
  if (strcmp(strInput, optionA)==0){			//series of if statements which execute functions 
  execWhoami();						//based on user selection above
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
    printf("invalid option!!!! Please Enter using capitals\n");		//if condiitons not met exit
  }
  printf("done....\n");
  
  return 0;
}