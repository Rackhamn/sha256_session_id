#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.c"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#else
// linux
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#endif

void read_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
	HCRYPTPROV hProvider = 0;
	if(!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		return;
	}
	if(!CrpytGenRandom(hProvider, (DWORD)len, buf)) {
		CryptReleaseContext(hProvider, 0);
		return;
	}
	CryptReleaseContext(hProvider, 0);
#else
// linux
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0) { 
		return;
	}
	ssize_t r = read(fd, buf, len);
	close(fd);
	return;
#endif
}

uint64_t get_unix_timestamp() {
#ifdef _WIN32
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	// convert to 64-bit value
	uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

	// convert to seconds since unix epoch
	const uint64_t epoch_diff = 116444736000000000ULL;
	return ((ticks - epoch_diff) / 10000000ULL);
#else
// linux
	return (uint64_t)time(NULL);
#endif
}

int main() {
	printf("Generate a session ID\n");

	SHA256_CTX ctx;
	uint8_t hash[32] = { 0 };
	sha256_init(&ctx);

	uint32_t user_id = 0;
	uint8_t rnd_buf[8] = { 0 };
	uint64_t timestamp = 0;
	char token_data[64] = { 0 };

	// session id = sha256(random_bytes + timestamp + user_id)
	
	// get input data
	user_id = 123;
	read_random_bytes(rnd_buf, 8);
	timestamp = get_unix_timestamp();

	// display input data
	printf("Session ID input:\n");
	printf("user_id: %u\n", user_id);
	printf("random: ");
	for(int i = 0; i < 8; i++) {
		printf("%02x", rnd_buf[i]);
	}
	printf("\n");
	printf("timestamp: %lu\n", timestamp);
	printf("\n");

	// build token buffer
	memcpy(token_data, &user_id, sizeof(user_id));
	memcpy(token_data + sizeof(user_id), rnd_buf, sizeof(rnd_buf[0]) * 8);
	memcpy(token_data + sizeof(user_id) + (sizeof(rnd_buf[0]) * 8), &timestamp, sizeof(timestamp));
	// compute hash
	size_t token_len = sizeof(user_id) + (sizeof(rnd_buf[0]) * 8) + sizeof(timestamp);
	sha256_update(&ctx, (const uint8_t *)token_data, token_len);
        sha256_final(&ctx, hash);

	// display hash
	printf("sha256:\n");
	for (int i = 0; i < 32; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");

	return 0;
}
