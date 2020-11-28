#define _CRT_SECURE_NO_WARNINGS
// xcm-validator.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#define MAX_LINE_SIZE  1024
#define SIGNATURE_LENGTH 128

const char pub_pem[] =
"-----BEGIN PUBLIC KEY-----\r\n"
///*
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxFcKg7r6kBHH+JFnuR71sGaHS\r\n"
"J0LssA4s539OmgY2oZOuNV2cnV0wAfhVR1S1YAair4n4CFEUWEvwOej6RydeDZni\r\n"
"yKBQv8opnjA2S5kTqpfVMQFlmMUecQwCLnh5qWJOwohfewJrd34F37okTAeUs4Mi\r\n"
"h9okA+Jtqx+OlMOPowIDAQAB\r\n"
"-----END PUBLIC KEY-----\r\n";

void printUsage() {
	printf("Usage: xcm-validator <igc filename>\n");
}

RSA* readPubKey() {
	RSA* key;
	BIO* bp;

	bp = BIO_new_mem_buf((void*)pub_pem, sizeof(pub_pem));
	key = (RSA*)PEM_read_bio_RSA_PUBKEY(bp, NULL, NULL, NULL);
	BIO_free(bp);

	return key;
}

void exit_invalid() {
	printf("check FAILED\n");
	exit(1);
}

int from_hex(int c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else {
		exit_invalid();
		return 0;		// make compiler happy
	}
}


int main(int arg, char* argv[]) {
	FILE* filep;
	char line[MAX_LINE_SIZE];
	unsigned char sha[SHA_DIGEST_LENGTH];
	unsigned char signature[SIGNATURE_LENGTH];
	SHA_CTX sha_ctx;
	int sigPos = 0;

	if (arg != 2) {
		printUsage();
		exit(1);
	}

	filep = fopen(argv[1], "rt");
	if (filep == NULL) {
		printf("File does not exist.\n");
		exit(1);
	}

	SHA1_Init(&sha_ctx);

	//read the igc File
	while (fgets(line, MAX_LINE_SIZE, filep) != NULL) {		
		int len = strlen(line);

		while (len >= 1 && (line[len - 1] == '\r' || line[len - 1] == '\n')) len--;

		if (len > 0) {
			if (line[0] == 'G') {
				int i;
				for (i = 1; i + 1 < len && sigPos < SIGNATURE_LENGTH; i += 2)
					signature[sigPos++] = from_hex(line[i]) * 16 + from_hex(line[i + 1]);
				if (i != len)
					exit_invalid();
			}
			else if (line[0] != 'L' ) {
				SHA1_Update(&sha_ctx, line, len);
			}
		}
	}
	fclose(filep);

	if (sigPos != SIGNATURE_LENGTH) {
		exit_invalid();
	}

	SHA1_Final(sha, &sha_ctx);

	int ret = RSA_verify(NID_sha1, sha, SHA_DIGEST_LENGTH, signature, SIGNATURE_LENGTH, readPubKey());

	if(ret == 1)
		printf("VALID\n");
	else
		exit_invalid();

	return 0;
}
