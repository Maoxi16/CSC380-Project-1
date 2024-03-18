/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */
	// Get the length of the RSA modulus N in bytes.
	size_t keyLength = rsa_numBytesN(K);
    unsigned char* randomBytes = (unsigned char*)malloc(keyLength);
    if (!randomBytes) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    printf("Key size: %zu bytes\n", keyLength);

    // Generate a random symmetric key (SK).
    randBytes(randomBytes, keyLength);
    SKE_KEY SK;
    ske_keyGen(&SK, randomBytes, keyLength);

    // Calculate encapsulation length: RSA encrypted key length + hash length.
    size_t encapLen = keyLength + HASHLEN;
    unsigned char* encapsulation = (unsigned char*)malloc(encapLen);
    if (!encapsulation) {
        fprintf(stderr, "Memory allocation failed\n");
        free(randomBytes);
        return -1;
    }

    // RSA encrypt the random bytes and store in the encapsulation buffer.
    if (keyLength != rsa_encrypt(encapsulation, randomBytes, keyLength, K)) {
        fprintf(stderr, "RSA encryption failed\n");
        free(randomBytes);
        free(encapsulation);
        return -1;
    }

    // Hash the random bytes and append the hash to the end of the encapsulation buffer.
    unsigned char* hashOutput = (unsigned char*)malloc(HASHLEN);
    if (!hashOutput) {
        fprintf(stderr, "Memory allocation failed\n");
        free(randomBytes);
        free(encapsulation);
        return -1;
    }
    SHA256(randomBytes, keyLength, hashOutput);
    memcpy(encapsulation + keyLength, hashOutput, HASHLEN);

    // Open the output file for writing.
    int fdOut = open(fnOut, O_CREAT | O_RDWR, S_IRWXU);
    if (fdOut == -1) {
        fprintf(stderr, "Failed to open output file\n");
        free(randomBytes);
        free(encapsulation);
        free(hashOutput);
        return -1;
    }

    // Write the encapsulation to the file.
    write(fdOut, encapsulation, encapLen);
    close(fdOut);

    // Encrypt the input file with the symmetric key and append the ciphertext after the encapsulation.
    if (ske_encrypt_file(fnOut, fnIn, &SK, NULL, encapLen) != 0) {
        fprintf(stderr, "Symmetric encryption failed\n");
        // In a real scenario, consider removing the partially written output file.
    }

    // Free allocated memory.
    free(randomBytes);
    free(encapsulation);
    free(hashOutput);

	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */
	// Calculate RSA modulus length and encapsulation length.
    size_t rsaLen = rsa_numBytesN(K);
    size_t encapLen = rsaLen + HASHLEN;
    printf("RSA Key size: %zu bytes\n", rsaLen);

    FILE* encrypted = fopen(fnIn, "rb");
    if (!encrypted) {
        fprintf(stderr, "Failed to open input file\n");
        return -1;
    }

    // Allocate memory and read the encapsulated data (RSA(X)|H(X)).
    unsigned char* encap = (unsigned char*)malloc(encapLen);
    if (!encap) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(encrypted);
        return -1;
    }

    size_t read = fread(encap, 1, encapLen, encrypted);
    fclose(encrypted); // Close the file as soon as we're done reading the necessary part.

    if (read != encapLen) {
        fprintf(stderr, "Failed to read encapsulated key\n");
        free(encap);
        return -1;
    }

    // Decrypt the encapsulated key to recover X.
    unsigned char* x = (unsigned char*)malloc(rsaLen);
    if (!x) {
        fprintf(stderr, "Memory allocation failed\n");
        free(encap);
        return -1;
    }

    if (rsaLen != rsa_decrypt(x, encap, rsaLen, K)) {
        fprintf(stderr, "Failed to decrypt RSA(X)\n");
        free(x);
        free(encap);
        return -1;
    }

    // Calculate H(X) from the decrypted X.
    unsigned char* hComputed = (unsigned char*)malloc(HASHLEN);
    if (!hComputed) {
        fprintf(stderr, "Memory allocation failed\n");
        free(x);
        free(encap);
        return -1;
    }
    SHA256(x, rsaLen, hComputed);

    // Compare computed H(X) with the encapsulated H(X).
    if (memcmp(hComputed, encap + rsaLen, HASHLEN) != 0) {
        fprintf(stderr, "Hash comparison failed\n");
        free(hComputed);
        free(x);
        free(encap);
        return -1;
    }

    // Generate the symmetric key from X and decrypt the file.
    SKE_KEY SK;
    ske_keyGen(&SK, x, rsaLen);
    if (ske_decrypt_file(fnOut, fnIn, &SK, encapLen) != 0) {
        fprintf(stderr, "Symmetric decryption failed\n");
        // Handle decryption failure as needed.
    }

    // Clean up allocated memory.
    free(hComputed);
    free(x);
    free(encap);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	int generate(char* fnOut, size_t nBits) {
    RSA_KEY K;

    // Append ".pub" to the filename for the public key file.
    size_t fnOutLen = strlen(fnOut);
    char* fPub = malloc(fnOutLen + 5); // Additional space for ".pub" and null terminator
    if (!fPub) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    snprintf(fPub, fnOutLen + 5, "%s.pub", fnOut);

    FILE* outPrivate = fopen(fnOut, "w");
    if (!outPrivate) {
        fprintf(stderr, "Failed to open private key file for writing\n");
        free(fPub);
        return -1;
    }

    FILE* outPublic = fopen(fPub, "w");
    if (!outPublic) {
        fprintf(stderr, "Failed to open public key file for writing\n");
        fclose(outPrivate);
        free(fPub);
        return -1;
    }

    rsa_keyGen(nBits, &K);
    rsa_writePrivate(outPrivate, &K);
    rsa_writePublic(outPublic, &K);

    fclose(outPrivate);
    fclose(outPublic);
    rsa_shredKey(&K);
    free(fPub);

    return 0;
}

/**
 * Encrypts a file using a public RSA key.
 *
 * @param fnOut The output filename for the encrypted content.
 * @param fnIn The input filename of the content to encrypt.
 * @param fnKey The filename of the public key to use for encryption.
 * @return 0 on success, -1 on failure.
 */
int encrypt(char* fnOut, char* fnIn, char* fnKey) {
    FILE* keyFile = fopen(fnKey, "r");
    if (!keyFile) {
        fprintf(stderr, "Key file does not exist: %s\n", fnKey);
        return -1;
    }

    RSA_KEY K;
    if (rsa_readPublic(keyFile, &K) != 0) {
        fprintf(stderr, "Failed to read public key\n");
        fclose(keyFile);
        return -1;
    }
    fclose(keyFile);

    if (kem_encrypt(fnOut, fnIn, &K) != 0) {
        rsa_shredKey(&K);
        return -1;
    }

    rsa_shredKey(&K);
    return 0;
}

/**
 * Decrypts a file using a private RSA key.
 *
 * @param fnOut The output filename for the decrypted content.
 * @param fnIn The input filename of the encrypted content.
 * @param fnKey The filename of the private key to use for decryption.
 * @return 0 on success, -1 on failure.
 */
int decrypt(char* fnOut, char* fnIn, char* fnKey) {
    FILE* privateKey = fopen(fnKey, "r");
    if (!privateKey) {
        fprintf(stderr, "Key file does not exist: %s\n", fnKey);
        return -1;
    }

    RSA_KEY K;
    if (rsa_readPrivate(privateKey, &K) != 0) {
        fprintf(stderr, "Failed to read private key\n");
        fclose(privateKey);
        return -1;
    }
    fclose(privateKey);

    if (kem_decrypt(fnOut, fnIn, &K) != 0) {
        rsa_shredKey(&K);
        return -1;
    }

    rsa_shredKey(&K);
    return 0;
}
	switch (mode) {
		case ENC:
		case DEC:
		case GEN:
		default:
			return 1;
	}

	return 0;
}
