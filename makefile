output: app/vuln64.c
	gcc -fno-stack-protector -no-pie app/vuln64.c -o app/vuln64
	chown root:root app/vuln64
	chmod u+s app/vuln64