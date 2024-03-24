#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	if (entropy != null){
		unsigned char* outBuf_64;
		outBuf_64 = malloc(64);
		HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, outBuf_64, NULL);

		for(int i=0; i<32; i++) {
			K->hmacKey[i] = outBuf_64[i];
			K->aesKey[i]  = outBuf_64[i+32];
		}
		free(outBuf_64);
	} else{
		unsigned char* outBuf_32_hmac;
		unsigned char* outBuf_32_aes;
		outBuf_32_hmac = malloc(32);
		outBuf_32_aes  = malloc(32);
		randBytes(outBuf_32_hmac, 32);
		randBytes(outBuf_32_aes , 32);

		for(int i=0; i<32; i++) {
			K->hmacKey[i] = outBuf_32_hmac[i];
			K->aesKey[i]  = outBuf_32_aes[i] ;
		}

		free(outBuf_32_hmac);
		free(outBuf_32_aes );
	}
	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	if(IV == NULL) {
		IV = malloc(16);
		randBytes(IV, 16);
	}
	memcpy(outBuf, IV, 16);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV)) {
		ERR_print_errors_fp(stderr);
	}
	int nWritten;
	if(1 != EVP_EncryptUpdate(ctx, outBuf+16, &nWritten, inBuf, len)) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	int totalLen = nWritten + 16 + HM_LEN;
	unsigned char newBuf[nWritten];
	memcpy(newBuf, &outBuf[16], nWritten);

	unsigned char* HMAC_Buf = malloc(HM_LEN);
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nWritten+16, HMAC_Buf, NULL);
	memcpy(&outBuf[nWritten+16], HMAC_Buf, HM_LEN);

	return totalLen; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	int fdin  = open(fnin, O_RDONLY)									 ;
	int fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin == -1 || fdout == -1) { 
		printf("Failed to open files\n");
		return -1; 
	}

	struct stat statBuf;
	if(fstat(fdin, &statBuf) == -1 || statBuf.st_size == 0) { return -1; }

	char *pa;
	pa = mmap(NULL, statBuf.st_size, PROT_READ, MAP_PRIVATE, fdin, 0); // mmap() establish a mapping between a process address space and a file
	if(pa == MAP_FAILED) { return -1; }

	size_t fdinLen = strlen(pa) + 1;
	size_t ciphertextLen = ske_getOutputLen(fdinLen);

	unsigned char* ciphertext = malloc(ciphertextLen+1);
	
	char freeIV = 0;
	if(IV == NULL) { 
		IV = malloc(16);
		randBytes(IV, 16); 
		freeIV = 1;
	}
	ssize_t encryptLen = ske_encrypt(ciphertext, (unsigned char*)pa, fdinLen, K, IV);

	if(encryptLen == -1){
		printf("Failed to encrypt\n");
	}	

	lseek(fdout, offset_out, SEEK_SET);
	ssize_t written = write(fdout, ciphertext, encryptLen);
	if(written == -1){
		printf("Failed to write to file\n");
	}
	

	munmap(pa, statBuf.st_size);
	free(ciphertext);
	if(freeIV > 0){
		free(IV);
	}
	close(fdin);
	close(fdout);

	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	unsigned char hmac[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len-HM_LEN, hmac, NULL);

	for(int i=0; i<HM_LEN; i++) {
		if(hmac[i] != inBuf[len-HM_LEN+i]) { return -1; }
	}

	unsigned char IV[16];
	memcpy(IV, inBuf, 16);

	int adjustLen = len - HM_LEN - 16;
	unsigned char ciphertext[adjustLen];
	for(int i=0; i<adjustLen; i++) {
		ciphertext[i] = inBuf[i+16];
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV)) {
		ERR_print_errors_fp(stderr);
	}

	size_t ciphertextLen = adjustLen;

	int nWritten = 0;
	if(1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, ciphertext, ciphertextLen)) {
		ERR_print_errors_fp(stderr);
	}
	
	return nWritten;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	int fdin  = open(fnin, O_RDONLY)									 ;
	int fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin == -1 || fdout == -1) { return -1; }

	struct stat statBuf;
	if(fstat(fdin, &statBuf) == -1 || statBuf.st_size == 0) { return -1; }

	unsigned char *pa;
	pa = mmap(NULL, statBuf.st_size, PROT_READ, MAP_PRIVATE, fdin, offset_in);
	if(pa == MAP_FAILED) { return -1; }

	char* plaintext = malloc(statBuf.st_size-16-HM_LEN-offset_in);
	ske_decrypt((unsigned char*)plaintext, pa, statBuf.st_size-offset_in, K);
	FILE *pFile = fopen(fnout, "w");
	if(pFile == NULL) { return -1; }
	else {
		fputs(plaintext, pFile);
		fclose(pFile);
	}
	return 0;
}
