# sha256_session_id
Test implementation of SHA-256 to generate a website session_id

## SHA-256 Usage example
```c
const char *msg = "hello world";
const size_t msg_len = strlen(msg);
uint8_t hash[32];
SHA256_CTX ctx;

sha256_init(&ctx);
sha256_update(&ctx, (const uint8_t *)msg, msg_len);
sha256_final(&ctx, hash);

printf("sha256:\n");
for (int i = 0; i < 32; i++)
    printf("%02x", hash[i]);
printf("\n");
```
## Session_ID Usage example
```c
// the input data 
uint32_t user_id = 0;
uint8_t rnd_buf[8] = { 0 };
uint64_t timestamp = 0;
char token_data[64] = { 0 };

// get input data
user_id = 123;
read_random_bytes(rnd_buf, 8);
timestamp = get_unix_timestamp();

// use SHA-256 on the token_data buffer
```
