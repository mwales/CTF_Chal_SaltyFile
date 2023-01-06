#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>

#include "hexdump.h"

#define PASSWORD "wildcat{git_history_is_forever}"
#define KEY_LEN crypto_aead_aes256gcm_KEYBYTES

#define DECRYPT_MODE "-d"
#define ENCRYPT_MODE "-e"


void printHelp(char* programName)
{
	std::cout << "File encrypt and decrypt" << std::endl;
	std::cout << "Usage: " << programName << " mode filename" << std::endl;
	std::cout << "\t" << programName << " " DECRYPT_MODE " ciphertext plaintext" << std::endl;
	std::cout << "\t" << programName << " " ENCRYPT_MODE " plaintext ciphertext" << std::endl;
}

void incrementNonce(unsigned char* value, int sizeOfValueBytes)
{
	int place = sizeOfValueBytes - 1;
	while(place >= 0)
	{
		if (value[place] == 0xff)
		{
			value[place] = 0;
		}
		else
		{
			value[place] += 1;
			return;
		}

		place--;
	}
}


void encryptMode(std::string inputPt, std::string outputCt)
{
	std::cerr << "Encryption mode, plaintext = " << inputPt << std::endl;

	unsigned char pwsalt[crypto_pwhash_SALTBYTES];
	unsigned char key[KEY_LEN];
	randombytes_buf(pwsalt, sizeof pwsalt);

	std::cout << "Password Salt:" << std::endl;
	hexDump(pwsalt, sizeof pwsalt);
	std::cout << std::endl;

	int fdIn = open(inputPt.c_str(), O_RDONLY);
	int fdOut = open(outputCt.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if ( (fdIn <= 0) || (fdOut <= 0) )
	{
		std::cerr << "Error opening one of the files" << std::endl;
		return;
	}

	std::cout << "Opened plaintext " << inputPt << " and cipertext file " << outputCt << std::endl;

	int saltWritten = write(fdOut, pwsalt, sizeof pwsalt);
	if (saltWritten != sizeof pwsalt)
	{
		std::cerr << "Error writing the salt bytes to the file" << std::endl;
		close(fdIn);
		close(fdOut);
		return;
	}

	// Derive a key from the password
	int hashSuccess = crypto_pwhash(key, KEY_LEN,
	                                PASSWORD, strlen(PASSWORD),
	                                pwsalt, crypto_pwhash_OPSLIMIT_MODERATE,
	                                crypto_pwhash_MEMLIMIT_MODERATE,
	                                crypto_pwhash_ALG_DEFAULT);

	if (hashSuccess)
	{
		std::cerr << "Error converting password to key" << std::endl;
		close(fdIn);
		close(fdOut);
		return;
	}

	std::cout << "Key:" << std::endl;
	hexDump(key, sizeof key);
	std::cout << std::endl;

	// Create a nonce
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	randombytes_buf(nonce, sizeof nonce);
	int nonceWritten = write(fdOut, nonce, sizeof nonce);
	if (nonceWritten != sizeof nonce)
	{
		std::cerr << "Error writing the nonce to the ct file" << std::endl;
		close(fdIn);
		close(fdOut);
		return;
	}

	std::cout << "Nonce:" << std::endl;
	hexDump(nonce, sizeof nonce);
	std::cout << std::endl;

	unsigned int const BUF_LEN = 2048;
	unsigned char ptBuf[BUF_LEN];
	unsigned char ctBuf[BUF_LEN + crypto_aead_aes256gcm_ABYTES];

	uint32_t ptSize = lseek(fdIn, 0, SEEK_END);
	std::cout << "Plaintext file size is " << ptSize << std::endl;
	lseek(fdIn, 0, SEEK_SET);

	uint32_t progress = 0;
	uint32_t totalCtLen = 0;
	while(progress < ptSize)
	{
		int chunkSize = ptSize - progress;
		if (chunkSize > BUF_LEN)
		{
			chunkSize = BUF_LEN;
		}

		uint32_t br = read(fdIn, ptBuf, chunkSize);
		if (br != chunkSize)
		{
			std::cerr << "Error reading chunk of size " << chunkSize << " at " << progress << std::endl;
			close(fdIn);
			close(fdOut);
			return;
		}

		std::cout << "Read in a chunk of size " << br << std::endl;
		
		unsigned long long ctLen = 0;
		crypto_aead_aes256gcm_encrypt(ctBuf, &ctLen,
		                              ptBuf, br,
		                              NULL, 0,
		                              NULL, nonce, key);

		std::cout << "Ciphertext length = " << ctLen << std::endl;

		std::cout << "Ciphertext:" << std::endl;
		hexDump(ctBuf, ctLen);
		std::cout << std::endl;

		write(fdOut, &br, sizeof(uint32_t));
		write(fdOut, &ctLen, sizeof(unsigned long long));

		unsigned long long bw = write(fdOut, ctBuf, ctLen);
		if (bw != ctLen)
		{
			std::cerr << "Error writing the ciphertext of size " << ctLen << " at " << progress << std::endl;
			close(fdIn);
			close(fdOut);
			return;
		}

		progress += chunkSize;
		totalCtLen += ctLen;
		incrementNonce( (unsigned char*) &nonce, crypto_aead_aes256gcm_NPUBBYTES);
	}

	std::cout << "Encryption complete. " << progress << " encrypted into " << totalCtLen << " bytes" << std::endl;

	close(fdIn);
	close(fdOut);
}

void decryptMode(std::string inputCt, std::string outputPt)
{
	std::cerr << "Decryption mode, ciphertext = " << inputCt << " to " << outputPt << std::endl;

	unsigned char pwsalt[crypto_pwhash_SALTBYTES];
	unsigned char key[KEY_LEN];

	int fdIn = open(inputCt.c_str(), O_RDONLY);
	int fdOut = open(outputPt.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if ( (fdIn <= 0) || (fdOut <= 0) )
	{
		std::cerr << "Error opening one of the files" << std::endl;
		return;
	}

	std::cout << "Opened ciphertext " << inputCt << " and plaintext file " << outputPt << std::endl;

	int saltRead = read(fdIn, &pwsalt, sizeof pwsalt);
	if (saltRead != sizeof pwsalt)
	{
		std::cerr << "Error reading the salt bytes from the file" << std::endl;
		close(fdIn);
		close(fdOut);
		return;
	}

	std::cout << "Password Salt:" << std::endl;
	hexDump(pwsalt, sizeof(pwsalt));
	std::cout << std::endl;

	// Derive a key from the password
	int hashSuccess = crypto_pwhash(key, KEY_LEN,
	                                PASSWORD, strlen(PASSWORD),
	                                pwsalt, crypto_pwhash_OPSLIMIT_MODERATE,
	                                crypto_pwhash_MEMLIMIT_MODERATE,
	                                crypto_pwhash_ALG_DEFAULT);

	if (hashSuccess)
	{
		std::cerr << "Error converting password to key" << std::endl;
		close(fdIn);
		close(fdOut);
		return;
	}

	std::cout << "Key:" << std::endl;
	hexDump(key, KEY_LEN);
	std::cout << std::endl;

	// Create a nonce
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	int nonceRead = read(fdIn, &nonce, sizeof nonce);
	if (nonceRead != sizeof nonce)
	{
		std::cerr << "Error reading the nonce from the ct file" << std::endl;
		close(fdIn);
		close(fdOut);
		return;
	}

	std::cout << "Nonce:" << std::endl;
	hexDump(nonce, sizeof nonce);
	std::cout << std::endl;

	unsigned int const BUF_LEN = 2048;
	unsigned char ptBuf[BUF_LEN];
	unsigned char ctBuf[BUF_LEN + crypto_aead_aes256gcm_ABYTES];

	uint32_t totalPtLen = 0;
	while(1)
	{
		
		uint32_t chunkPtSize = -1;
		unsigned long long chunkCtSize = 0;

		int cps = read(fdIn, &chunkPtSize, sizeof(uint32_t));
		int ccs = read(fdIn, &chunkCtSize, sizeof(unsigned long long));

		if ( (cps != sizeof(uint32_t)) || (ccs != sizeof(unsigned long long)) )
		{
			std::cout << "We must have reached the end of the cipher text" << std::endl;
			std::cout << "  cps=" << cps << ", and ccs=" << ccs << std::endl;
			break;
		}

		std::cerr << "  totalPtLen=" << totalPtLen << ", ptLen=" << chunkPtSize << ", ctLen=" << chunkCtSize << std::endl;
		
		uint32_t br = read(fdIn, ctBuf, chunkCtSize);
		if (br != chunkCtSize)
		{
			std::cerr << "Error reading chunk of size " << chunkCtSize << " at " << totalPtLen << std::endl;
			close(fdIn);
			close(fdOut);
			return;
		}

		std::cout << "Read in a chunk of size " << br << std::endl;
		
		std::cout << "Ciphertext:" << std::endl;
		hexDump(ctBuf, chunkCtSize);
		std::cout << std::endl;

		unsigned long long ptLen = 0;
		int decryptSuccess = crypto_aead_aes256gcm_decrypt(ptBuf, &ptLen,
		                                                   NULL,
		                                                   ctBuf, chunkCtSize,
		                                                   NULL, 0,
		                                                   nonce, key);

		std::cout << "Plaintext length = " << ptLen << std::endl;
		
		if (decryptSuccess == -1)
		{
			std::cerr << "Decryption call failed.  MAC?" << std::endl;
			close(fdIn);
			close(fdOut);
			return;
		}

		unsigned long long bw = write(fdOut, ptBuf, ptLen);
		if (bw != ptLen)
		{
			std::cerr << "Error writing the plaintext of size " << ptLen << " at " << totalPtLen << std::endl;
			close(fdIn);
			close(fdOut);
			return;
		}

		totalPtLen += ptLen;
		incrementNonce( (unsigned char*) &nonce, crypto_aead_aes256gcm_NPUBBYTES);
	}

	std::cout << "Decryption complete. " << totalPtLen << " decrypted bytes" << std::endl;

	close(fdIn);
	close(fdOut);
}



int main(int argc, char** argv)
{
	if (sodium_init() < 0)
	{
		std::cerr << "Error initializing libsodium" << std::endl;
		return 1;
	}

	std::cout << "Libsodium initialized" << std::endl;

	if (argc != 4)
	{
		printHelp(argv[0]);
		return 0;
	}

	std::string mode = argv[1];
	std::string inFile = argv[2];
	std::string outFile = argv[3];

	if (mode == ENCRYPT_MODE)
	{
		encryptMode(inFile, outFile);
	}
	else if (mode == DECRYPT_MODE)
	{
		decryptMode(inFile, outFile);
	}
	else
	{
		std::cerr << "Invalid mode: " << mode << std::endl;
	}

	return 0;
}

