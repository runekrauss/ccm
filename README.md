# CCM

**CCM** is an algorithm that extends the block cipher AES with **authentication**, so that it ensures both confidentiality and integrity.

## :dart: Features

* Authenticated AES encryption
* Decryption using 128-bit block ciphers

## :rocket: Getting Started

### :wrench: Installation

As a prerequisite, the library [OpenSSL](https://github.com/openssl/openssl) must be installed, since this algorithm accesses functions of this toolkit.

To compile and link CCM just type `make` or `make debug` for debugging purposes.

**Note**: Object files and other intermediate files can be removed using the command `make clean`.

### :computer: Usage

The CLI can be used according to the following scheme:

```console
$ ./ccm -d|-e [-h] <key> <nonce> <file>
```

* `-d`: decryption
* `-e`: encryption
* `-h`: hexadecimal format
* `<key>`: cipher key
* `<nonce>`: random number
* `<file>`: ciphertext or plaintext

The file is read in as an input stream and either encrypted or decrypted depending on the parameters.

## :white_check_mark: Tests

In the following, the test vector [testdata.txt](testdata.txt) is to be encrypted. The password settings according to [RFC 3610](http://tools.ietf.org/html/rfc3610) are as follows:

```
Cipher: AES-128 M=8 L=5 K_LEN=16 N_LEN=10 K=0x001234567890abcdefdcaffeed3921ee N=0x00112233445566778899
```

Now the file will be encrypted applying the aforementioned settings:

```console
$ ./ccm -e -h 001234567890abcdefdcaffeed3921ee 00112233445566778899 < testdata.txt > encrypted

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

The respective block types, keys, and random number are displayed. The ciphertext is at the bottom. The decryption works analogously.

## :book: Documentation

The CCM documentation becomes available by typing the following commands in the terminal:

```console
$ cd ccm
$ doxygen doxygen.config
```

## :warning: License

CCM is licensed under the terms of the [MIT license](LICENSE.txt).
