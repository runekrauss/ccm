CCM
============

# Description
There is a C program `ccm` which can be used for
encryption according to [RFC 3610](http://tools.ietf.org/html/rfc3610) and performs a cryptographic integrity check during decryption.

Counter with CBC-MAC (CCM) is a generic authenticated encryption block cipher mode.  CCM is only defined for use with 128-bit block ciphers, such as AES [AES].  The CCM design principles can easily be applied to other block sizes, but these modes will require their own specifications. For the generic CCM mode there are two parameter choices. 

The first choice is *M*, the size of the authentication field. The choice of the value for *M* involves a trade-off between message expansion and the probability that an attacker can undetectably modify a message. Valid values are 4, 6, 8, 10, 12, 14, and 16 octets.  The second choice is *L*, the size of the length field.  This value requires a trade-off between the maximum message size and the size of the Nonce. Different applications require different trade-offs, so *L* is a parameter. Valid values of *L* range between 2 octets and 8 octets (the value *L=1* is reserved).

## Prerequisites
+ C99
+ Doxygen for reading the documentation
+ OpenSSL for encryption and decryption features

## Installation
At first, clone or download this project. Afterwards, go to the terminal and type `make` to compile and link this application.

Furthermore, it is possible to use the debug mode using `make debug` (for additional output such as the S-blocks) or to delete the object files and so on using `make clean`.

## Usage
The CLI is compatible with the following format:

```
$ ./ccm -d|-e [-h] <key> <nonce> <plaintext> secret text
```

This is explained below:

* `-d` for encryption
* `-e` for decryption
* `-h` (optional) for entering hexadecimal numbers
* `<key>` for the used key
* `nonce` for the random number
* `secret text` for the ciphertext as file

The respective file is read in as input stream (stdin) and the parameters are parsed via `getopt`. For example, either encryption or decryption is allowed, but not both at the same time.

The test vector *testdata.txt* is used as an example. The settings regarding the password are:

```
Cipher: AES-128 M=8 L=5 K_LEN=16 N_LEN=10 K=0x001234567890abcdefdcaffeed3921ee N=0x00112233445566778899
```

These are now applied as follows:

```
$ ./ccm -e -h 001234567890abcdefdcaffeed3921ee 00112233445566778899 < testdata.txt > encrypted
``` 

Afterwards, the following output is available:

```
key:00:12:34:56:78:90:ab:cd:ef:dc:af:fe:ed:39:21:ee
nonce:00:11:22:33:44:55:66:77:88:99
length:38
content:Ein kleiner Text
zum Testen von CCM.

b-blocks:
1c:00:11:22:33:44:55:66:77:88:99:00:00:00:00:25
45:69:6e:20:6b:6c:65:69:6e:65:72:20:54:65:78:74
0a:7a:75:6d:20:54:65:73:74:65:6e:20:76:6f:6e:20
43:43:4d:2e:0a:00:00:00:00:00:00:00:00:00:00:00
mac:bb:78:19:d3:01:cf:c8:ab
a-blocks:
04:00:11:22:33:44:55:66:77:88:99:00:00:00:00:00:
04:00:11:22:33:44:55:66:77:88:99:00:00:00:00:01:
04:00:11:22:33:44:55:66:77:88:99:00:00:00:00:02:
04:00:11:22:33:44:55:66:77:88:99:00:00:00:00:03:
04:00:11:22:33:44:55:66:77:88:99:00:00:00:00:04:
s-blocks:
6a:0c:4a:ff:a2:7f:07:12:8e:47:9d:56:8e:6f:8a:f3:
01:13:ec:50:76:bc:50:12:06:92:47:6d:eb:bc:6e:61:
9d:3b:48:73:a9:95:40:94:a2:c2:b0:b0:68:9e:07:49:
dc:8d:0d:f2:fa:0d:95:7e:70:84:1f:41:71:c5:a7:50:
79:06:4d:38:1c:11:83:29:7a:76:77:df:43:0b:6a:6a:
DzÇp–5{h˜5MøŸóA=â¡%Á÷ßﬁêÒiiüŒ@‹—tS,£∞œπ
```

The respective block types, keys and random number are displayed. Also the length, which is *38* (increased by 1 due to zero byte), is displayed. The ciphertext is at the bottom.

## More information
Generate the documentation regarding the special comments with a command in your terminal, for example:

```
$ cd ccm
$ doxygen doxygen.config
```

Afterwards, you will get a website with helpful information about the code.