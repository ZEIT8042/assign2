output: vuln64.c
	gcc -fno-stack-protector -no-pie vuln64.c -o vuln64
	chown root:root vuln64
	chmod u+s vuln64