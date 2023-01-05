#include <iostream>
#include <cstdlib>
#include <cstdio>

#include <sodium.h>

#define PASSWORD "wildcat{git_history_is_forever}"
#define KEY_LEN crypto_aead_aes256gcm_KEYBYTES

#define DECRYPT_MODE "-d"
#define ENCRYPT_MODE "-e"


void printHelp(char* programName)
{
	std::cout << "File encrypt and decrypt" << std::endl;
	std::cout << "Usage: " << programName << " mode filename" << std::endl;
	std::cout << "\t" << programName << " " DECRYPT_MODE " ciphertext" << std::endl;
	std::cout << "\t" << programName << " " ENCRYPT_MODE " plaintext" << std::endl;
}

void encryptMode(std::string filename)
{
	std::cerr << "Encryption mode, plaintext = " << filename << std::endl;
}

void decryptMode(std::string filename)
{
	std::cerr << "Decryption mode, ciphertext = " << filename << std::endl;
}

int main(int argc, char** argv)
{
	if (sodium_init() < 0)
	{
		std::cerr << "Error initializing libsodium" << std::endl;
		return 1;
	}

	std::cout << "Libsodium initialized" << std::endl;

	if (argc != 3)
	{
		printHelp(argv[0]);
		return 0;
	}

	std::string mode = argv[1];
	std::string filename = argv[2];

	if (mode == ENCRYPT_MODE)
	{
		encryptMode(filename);
	}
	else if (mode == DECRYPT_MODE)
	{
		decryptMode(filename);
	}
	else
	{
		std::cerr << "Invalid mode: " << mode << std::endl;
	}

	return 0;
}

