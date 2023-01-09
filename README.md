# CtfChal_SaltyFile

Repo is part of a CTF challenge

# Building

You will need a C++ compiler and libsodium to compile.  On Ubuntu, you can
install them by executing the following:

```
sudo apt install build-essential libsodium-dev
```

To compile the application

```
g++ saltyfile.cpp -lsodium -osalty
```

# Running the application

Running the application:

```
$ ./salty -h
Libsodium initialized
File encrypt and decrypt
Usage: ./salty mode filename
       ./salty -d ciphertext plaintext
       ./salty -e plaintext ciphertext
```

An example:

$ ./salty -e README.md README.enc
Libsodium initialized
Encryption mode, plaintext = README.md
Password Salt:
a2 d1 95 b0 75 bb 31 0d  4a 13 71 dc a5 81 65 4b  |....u.1.J.q...eK|

Opened plaintext README.md and cipertext file README.enc
Key:
4e dd 25 57 be 33 da 27  c2 8a 27 1e 7c 4e ab a2  |N.%W.3.'..'.|N..|
b3 9d 30 8a 3c 1d 55 c0  0e 76 c9 48 b8 6e 2d ab  |..0.<.U..v.H.n-.|

Nonce:
8e ed 39 91 af 8d 26 3b  1e e5 76 2e              |..9...&;..v.    |

Plaintext file size is 52
Read in a chunk of size 52
Ciphertext length = 68
Ciphertext:
da c6 cf 03 32 64 59 bf  69 07 f6 8a 52 41 e7 f6  |....2dY.i...RA..|
07 60 08 4d 18 82 77 8c  25 d3 16 d9 24 8b 64 86  |.`.M..w.%...$.d.|
fc 4d 9a 62 61 d8 9e ab  32 c5 d6 21 88 65 3e ee  |.M.ba...2..!.e>.|
48 7c a6 ab 08 32 dc 6a  cd f3 e8 eb 48 e3 ea de  |H|...2.j....H...|
5c 3f b7 84                                       |\?..            |

Encryption complete. 52 encrypted into 68 bytes
$ hexdump -C README.enc 
00000000  a2 d1 95 b0 75 bb 31 0d  4a 13 71 dc a5 81 65 4b  |....u.1.J.q...eK|
00000010  8e ed 39 91 af 8d 26 3b  1e e5 76 2e 34 00 00 00  |..9...&;..v.4...|
00000020  44 00 00 00 00 00 00 00  da c6 cf 03 32 64 59 bf  |D...........2dY.|
00000030  69 07 f6 8a 52 41 e7 f6  07 60 08 4d 18 82 77 8c  |i...RA...`.M..w.|
00000040  25 d3 16 d9 24 8b 64 86  fc 4d 9a 62 61 d8 9e ab  |%...$.d..M.ba...|
00000050  32 c5 d6 21 88 65 3e ee  48 7c a6 ab 08 32 dc 6a  |2..!.e>.H|...2.j|
00000060  cd f3 e8 eb 48 e3 ea de  5c 3f b7 84              |....H...\?..|
0000006c
$ ./salty -d README.enc README.verify
Libsodium initialized
Decryption mode, ciphertext = README.enc to README.verify
Opened ciphertext README.enc and plaintext file README.verify
Password Salt:
a2 d1 95 b0 75 bb 31 0d  4a 13 71 dc a5 81 65 4b  |....u.1.J.q...eK|

Key:
4e dd 25 57 be 33 da 27  c2 8a 27 1e 7c 4e ab a2  |N.%W.3.'..'.|N..|
b3 9d 30 8a 3c 1d 55 c0  0e 76 c9 48 b8 6e 2d ab  |..0.<.U..v.H.n-.|

Nonce:
8e ed 39 91 af 8d 26 3b  1e e5 76 2e              |..9...&;..v.    |

  totalPtLen=0, ptLen=52, ctLen=68
  Read in a chunk of size 68
  Ciphertext:
  da c6 cf 03 32 64 59 bf  69 07 f6 8a 52 41 e7 f6  |....2dY.i...RA..|
  07 60 08 4d 18 82 77 8c  25 d3 16 d9 24 8b 64 86  |.`.M..w.%...$.d.|
  fc 4d 9a 62 61 d8 9e ab  32 c5 d6 21 88 65 3e ee  |.M.ba...2..!.e>.|
  48 7c a6 ab 08 32 dc 6a  cd f3 e8 eb 48 e3 ea de  |H|...2.j....H...|
  5c 3f b7 84                                       |\?..            |

  Plaintext length = 52
  We must have reached the end of the cipher text
    cps=0, and ccs=0
Decryption complete. 52 decrypted bytes
$ md5sum README.*
8679c2a22a3d5cf033646c2782753534  README.enc
7b9beab5a500a9aa0950b169d01948cd  README.md
7b9beab5a500a9aa0950b169d01948cd  README.verify
```
