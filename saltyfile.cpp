#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>



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

	crypto_aead_aes256gcm_keygen(key);

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
		                              (unsigned char*) &br, sizeof(uint32_t),
		                              NULL, nonce, key);

		std::cout << "Ciphertext length = " << ctLen << std::endl;

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

