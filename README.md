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

```
$ ./salty -h
Libsodium initialized                                                          
File encrypt and decrypt                                                       
Usage: ./salty mode filename                                                   
        ./salty -d ciphertext plaintext                                        
        ./salty -e plaintext ciphertext
$
$  
$ ./salty -e README.md README.enc
Libsodium initialized                                                          
Enter password:                                                                
                                                                               
Encryption mode, plaintext = README.md
Opened plaintext README.md and cipertext file README.enc                       
Plaintext file size is 3290                                                    
Read in a chunk of size 2048                                                   
Ciphertext length = 2064                                                       
Read in a chunk of size 1242                                                   
Ciphertext length = 1258                                                       
Encryption complete. 3290 encrypted into 3322 bytes
$
$
$                            
$ hexdump -C README.enc | head -n 10                                                                              
00000000  69 3d ec fd 21 21 32 a6  8d 37 6f 80 c3 a1 93 23  |i=..!!2..7o....#| 
00000010  95 a0 51 f9 f7 51 83 05  9c 4e 42 7c 00 08 00 00  |..Q..Q...NB|....|
00000020  10 08 00 00 00 00 00 00  64 f7 4c 14 70 7d c0 33  |........d.L.p}.3| 
00000030  36 da 2d ce db f3 72 26  38 9f 1f ce 20 ae 7c 32  |6.-...r&8... .|2|
00000040  2d d7 6a f7 87 aa d0 a0  20 51 64 32 9d a8 55 bb  |-.j..... Qd2..U.|
00000050  a3 c7 9d 48 fc c4 fa 3b  c9 bd a0 2a a1 78 05 7b  |...H...;...*.x.{|
00000060  9f e4 34 90 15 09 9e 1d  44 c0 4a 34 35 b3 5b 25  |..4.....D.J45.[%|
00000070  4a bd dd d7 9e 7e 8e d6  c4 78 57 c9 74 a0 74 09  |J....~...xW.t.t.|
00000080  41 d9 1a 57 00 9b e8 50  63 af 95 33 30 0e 8d b1  |A..W...Pc..30...|
00000090  2f d6 f4 fb fa 54 4f e1  a0 44 04 67 70 e1 3f 99  |/....TO..D.gp.?.|
$
$
$
$ ./salty -d README.enc README.verify
Libsodium initialized                                                          
Enter password:                                                                
                                                                               
Decryption mode, ciphertext = README.enc to README.verify  
Opened ciphertext README.enc and plaintext file README.verify
  totalPtLen=0, ptLen=2048, ctLen=2064                                         
Read in a chunk of size 2064                                                   
Plaintext length = 2048                                                        
  totalPtLen=2048, ptLen=1242, ctLen=1258
Read in a chunk of size 1258                                                   
Plaintext length = 1242                                                        
We must have reached the end of the cipher text
  cps=0, and ccs=0                                                             
Decryption complete. 3290 decrypted bytes
$
$
$
$ md5sum README.*
a931a0ff7bf4cf34adfef1db47975d8c  README.enc
9160ca5d6830e50d11b0bb5eaa08b1e6  README.md
9160ca5d6830e50d11b0bb5eaa08b1e6  README.verify
```
