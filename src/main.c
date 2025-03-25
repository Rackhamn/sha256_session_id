#include <stdio.h>
#include <stdlib.h> // exit
#include "sha256.c"

int main(int argc, char ** argv) {
	const char *msg = "hello world";
	
	if(argc > 1) {
		msg = (const char *)argv[1];
	} else {
		printf("No text given. using \"hello world\"\n");
		printf("Usage: $PROGRAM <text>\n");
	}

	uint8_t hash[32];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, (const uint8_t *)msg, strlen(msg));
	sha256_final(&ctx, hash);

	printf("sha256:\n");
	for (int i = 0; i < 32; i++)
		printf("%02x", hash[i]);
	printf("\n");

	// "hello world" should become this
	// printf("sha256 correct:\n");
	// printf("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9\n");

	return 0;
}

