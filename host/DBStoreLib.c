#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
// #include <hello_world_ta.h>
#include <dbstore_ta.h>
#include <openssl/pem.h>
#include <DBStoreLib.h>

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

char public_key_app[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NhVkTM+cICoPiQFnZ3j\n"
"Med/vRzJjClYzd0UlOqp1qWxJcOe7bG9rZOFNkkTpWqxOfKZQzHKqGmZZauXxPq5\n"
"IfG72ig9f9hLyv3Npb6X5bFfdCGFBA7t8Y6DQMB5K2Qz5+1HQlaH5R4xJ/hwUloU\n"
"BzSwmljnMvacBErT4CqcKnYa+QBsFyBy+adGElRoo/vFksZ39BlmhjMRI6jYwCjK\n"
"RhY/N+rrkGOAim1hVSl/gpAtQVNTPXKVfwDFadQTkgCOyz2Wj1dSvZ/Ugarq3Byj\n"
"XYcG34OZFYOYgixNqBVvHdjLkXmjTQz3bc2XdsKYGlNl2UCiI8oOYxm17+kG3nVS\n"
"fQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

uint8_t modulus_app[] =
"\xd0\xd8\x55\x91\x33\x3e\x70\x80\xa8\x3e\x24\x05\x9d\x9d"
"\xe3\x31\xe7\x7f\xbd\x1c\xc9\x8c\x29\x58\xcd\xdd\x14\x94\xea"
"\xa9\xd6\xa5\xb1\x25\xc3\x9e\xed\xb1\xbd\xad\x93\x85\x36\x49"
"\x13\xa5\x6a\xb1\x39\xf2\x99\x43\x31\xca\xa8\x69\x99\x65\xab"
"\x97\xc4\xfa\xb9\x21\xf1\xbb\xda\x28\x3d\x7f\xd8\x4b\xca\xfd"
"\xcd\xa5\xbe\x97\xe5\xb1\x5f\x74\x21\x85\x04\x0e\xed\xf1\x8e"
"\x83\x40\xc0\x79\x2b\x64\x33\xe7\xed\x47\x42\x56\x87\xe5\x1e"
"\x31\x27\xf8\x70\x52\x5a\x14\x07\x34\xb0\x9a\x58\xe7\x32\xf6"
"\x9c\x04\x4a\xd3\xe0\x2a\x9c\x2a\x76\x1a\xf9\x00\x6c\x17\x20"
"\x72\xf9\xa7\x46\x12\x54\x68\xa3\xfb\xc5\x92\xc6\x77\xf4\x19"
"\x66\x86\x33\x11\x23\xa8\xd8\xc0\x28\xca\x46\x16\x3f\x37\xea"
"\xeb\x90\x63\x80\x8a\x6d\x61\x55\x29\x7f\x82\x90\x2d\x41\x53"
"\x53\x3d\x72\x95\x7f\x00\xc5\x69\xd4\x13\x92\x00\x8e\xcb\x3d"
"\x96\x8f\x57\x52\xbd\x9f\xd4\x81\xaa\xea\xdc\x1c\xa3\x5d\x87"
"\x06\xdf\x83\x99\x15\x83\x98\x82\x2c\x4d\xa8\x15\x6f\x1d\xd8"
"\xcb\x91\x79\xa3\x4d\x0c\xf7\x6d\xcd\x97\x76\xc2\x98\x1a\x53"
"\x65\xd9\x40\xa2\x23\xca\x0e\x63\x19\xb5\xef\xe9\x06\xde\x75"
"\x52\x7d";

uint8_t public_key_app_int[] = 
"\x01\x00\x01";

char private_key_app[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAxvtUVCxzGNiUzYMSO/+4CRblzIkNn0ISenRzAkhFjZkwvhLt\n"
"JBAkLxt+0psDbEIgqJ7iTeoZFVgdYHwSHnh8iXOG06LE4jJwPh8bEq2KGgq22dP2\n"
"vlLEn6KdnMXPLvOpxFyhp/iwqYZZLURBd8TV/3KdryWDag4C4W+x6SWAt+3GJqFv\n"
"jHmqu6GYXWC3h8Y1FumFrjlFssUaThMXMqBR88E3zf/wRFlMo6pRJu8siOGjiNM4\n"
"6eu17HZDO1payD4vrCbYz/XKuZtrJ0UbNvCFUj+rLmLkznr51qyE0kWB/Xt0GZ9b\n"
"K4PRZMUnuJcWF+6TXcwBLdwBTYKACWd7OFB2dQIDAQABAoIBAEoZC6UwzEejV35U\n"
"YfTv3EOeQELzgpwcya7KMI3YBfad5lXRzHdSf3b/YTHiQdsNoQXJ7PIgy+hz4LSu\n"
"Xzzzl0TEPaAQDAtDxyKLCNTixPu/o6noUgk73zanItRfoTCV0lFqQVTAumDWw9yk\n"
"f1CvfxVaRDgV2yMiRpZWtsTgj1duTcnVuTHBLSDJORmo5IzJ4WeovMyQjesLnUMl\n"
"/8INL3l01BAO78VcVnZa6ZcmJhfraXQwkxfTAtx7zHjh5HxmaUFGmjpaLofnv7yt\n"
"v0bmpLjXL9SXQf5HKdDzoCUTH3v/Fos9dvSP1HSsTiPZZ6Sg/uz34GBFeapsVKC2\n"
"rj7MlGECgYEA/eXYSpU47M96F1ylKUZ8fEYKtzgfp1EK5j7QuGlvsEXnplpIamNg\n"
"eUHU4xzWJpJ0TmIsP+1f8W1kY7gAe6thuhPIjXEEk5JkEgbDN9HBEXZMvuGoevjp\n"
"dKbXure9hqN+9c+n1EH0xqKqjpXTQtsYqZuwH9xdEkopZWZUVEx3zO0CgYEAyKEV\n"
"+xYL8C3GHoGZHa7z6h9CDgaElkxldEeeD7GBQpALq/tGUgZ7Wa82QqoBOD/RYQeK\n"
"JOGrnhFMlYscDVkatWWEGAZE1xaI41Lc9bwf28EN7UcQFjcxqjFxJbEjiZxmmdow\n"
"ZlzXoVeoS10ntoRAwUIQU9Jk7jIp1k6T0Y0rJqkCgYEAnjULiqXjO8So2kfTbp3K\n"
"UhG++Z4SM0sPlJsNqeuhOeDFUOYu+4QDCGvaAM7mLlDSAkmwMwFx6Fl21aBBRM5s\n"
"7esH7ALBjEcK7iSinnSobn4dok+wkTfrGNIh2OpHQc88/GSxulSC9wdDaee4JY+q\n"
"lX06yQ+iOxRVKScTYxfnCp0CgYBxMSkEm0CrBjhD19x6Oc3VpkMPRLAjWADZZNqR\n"
"ghUqZ7ieFEttVcjcJZVYcS/0+1R3CNjwy/2WVa4+pNhz03TVKOwo3ciTDVy33HVb\n"
"kwLqafYgi7pQvl0f53stx84EAqCEZuxtpC3oEluaAXm5aM5b+pjZoddd6CFgjr6p\n"
"OJtC2QKBgCLcufK1ebPipI6D/odV3Pqv4aYZ7lkAhMkX1AtVPKaxv9wn3v3opSnB\n"
"iykMBXIqwjAkra3rZvYPQVNWIueuNJ7z8prI9jakOnA+p3XKBm4m32kQFiiSAK4X\n"
"THaSHg4J6+9INhl+Q2VjhWEZzL7J1YnBYXFRY7z5ffNK8IL8Ts6d\n"
"-----END RSA PRIVATE KEY-----\n";

char public_key_dbstore[] =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvtUVCxzGNiUzYMSO/+4\n"
"CRblzIkNn0ISenRzAkhFjZkwvhLtJBAkLxt+0psDbEIgqJ7iTeoZFVgdYHwSHnh8\n"
"iXOG06LE4jJwPh8bEq2KGgq22dP2vlLEn6KdnMXPLvOpxFyhp/iwqYZZLURBd8TV\n"
"/3KdryWDag4C4W+x6SWAt+3GJqFvjHmqu6GYXWC3h8Y1FumFrjlFssUaThMXMqBR\n"
"88E3zf/wRFlMo6pRJu8siOGjiNM46eu17HZDO1payD4vrCbYz/XKuZtrJ0UbNvCF\n"
"Uj+rLmLkznr51qyE0kWB/Xt0GZ9bK4PRZMUnuJcWF+6TXcwBLdwBTYKACWd7OFB2\n"
"dQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

// create RSA object
RSA *createRSA(unsigned char *key, int public) {
   RSA *rsa = NULL;
   BIO *keybio;
   keybio = BIO_new_mem_buf(key, -1);
   if (keybio == NULL) {
      printf("==> Error: Failed to create key BIO");
      return 0;
   }
   if (public) {
      rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
   } else {
      rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
   }
   if (rsa == NULL) {
      printf("==> Error: Failed to create RSA");
   }
   return rsa;
}

// encrypt in string using the private key
int encrypt_using_public_key (char * public_key, char * in, int in_len, char * out, int * out_len) {

   RSA * rsa;

   rsa = createRSA ((unsigned char *) public_key, 1);
   *out_len = RSA_public_encrypt (in_len, (unsigned char *)in, (unsigned char *)out, rsa, RSA_PKCS1_PADDING);

   if (*out_len == -1) {
      return -1;
   } else {
      return 1;
   }
}

// decrypt in string using the public key
int decrypt_using_private_key (char * private_key, char * in, int in_len, char * out, int * out_len) {

   RSA * rsa;

   rsa = createRSA ((unsigned char *) private_key, 0);
   *out_len = RSA_private_decrypt (in_len, (unsigned char *)in, (unsigned char *) out, rsa, RSA_PKCS1_PADDING);

   if (*out_len == -1)
      return -1;
   else {
      return 1;
   }
}

void call_ta_init(int call_type, const char *appid)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = {0};
	// TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	TEEC_UUID uuid = TA_DBSTORE_UUID; //will be DBStore code running on TZ!
	uint32_t err_origin;

	/* Shared buffers */
	TEEC_SharedMemory cryptoSM = {0};
	TEEC_SharedMemory signatureSM = {0};
	TEEC_SharedMemory modulusSM = {0};

	char nonce[NONCE_LEN] = {0};
	char *message = (char *) malloc((strlen(appid) + NONCE_LEN + 1) * sizeof(char));

	char crypto_req[CRYPTO_LEN] = {0};
	int crypto_req_len;

	//const char *input = "teste\n";
    //int req_len = strlen(req);

    //int certificate_len = 255;

    cryptoSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    cryptoSM.size  = CRYPTO_LEN;
	cryptoSM.buffer = calloc(CRYPTO_LEN, sizeof(char));

    signatureSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    signatureSM.size  = 256;
	signatureSM.buffer = calloc(256, sizeof(char));

	modulusSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    modulusSM.size  = 256;
	modulusSM.buffer = calloc(256, sizeof(char));

	printf("sizeof modulus - 1 %d\n", sizeof(modulus_app) - 1);

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE, TEEC_NONE);

	srand(time(NULL));
	rand_str(nonce, NONCE_LEN);
	strcat(message, appid);
	strcat(message, "_");
	strcat(message, nonce);

	if(encrypt_using_public_key(public_key_dbstore, message, strlen(message), crypto_req, &crypto_req_len) != 1)
		printf("Encryption gone wrong...\n");

	//printf("crypto: %s\n", crypto_req);

	op.params[0].memref.parent = &signatureSM;
    op.params[0].memref.size = 256;
    memcpy(signatureSM.buffer, "signature", 9);

    op.params[1].memref.parent = &modulusSM;
    op.params[1].memref.size = 256;
    memcpy(modulusSM.buffer, modulus_app, 256);

    op.params[2].memref.parent = &cryptoSM;
    op.params[2].memref.size = crypto_req_len;
    memcpy(cryptoSM.buffer, crypto_req, crypto_req_len);

	/* Use TEE Client API to allocate the underlying memory buffer. */
	res = TEEC_RegisterSharedMemory(&ctx, &signatureSM);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	res = TEEC_RegisterSharedMemory(&ctx, &modulusSM);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	res = TEEC_RegisterSharedMemory(&ctx, &cryptoSM);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*if (result != TEEC_SUCCESS)
	{
	goto cleanup3;
	}*/

	/* Clear the TEEC_Operation struct */
	// memset(&op, 0, sizeof(op));

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	printf("INIT: Invoking DBStore with request %s\n", (char *) signatureSM.buffer);
	res = TEEC_InvokeCommand(&sess, TA_DBSTORE_INIT, &op,
		 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("INIT: Received from DBStore values %s and %s\n", (char *) signatureSM.buffer,
		(char *) modulusSM.buffer);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	free(message);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
}

void call_ta_inv(int call_type, const char* nonce, const char *req, const char *hmac)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = {0};
	// TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	TEEC_UUID uuid = TA_DBSTORE_UUID; //will be DBStore code running on TZ!
	uint32_t err_origin;

	/* Shared buffers */
	TEEC_SharedMemory nonceSM = {0};
	TEEC_SharedMemory reqSM = {0};
	TEEC_SharedMemory hmacSM = {0};

	//char crypto_appid[32];
	//char crypto_nonce[32];

	//const char *input = "teste\n";
    int nonce_len = strlen(nonce);
    int req_len = strlen(req);
    int hmac_len = strlen(hmac);

    nonceSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    nonceSM.size  = nonce_len;
	nonceSM.buffer = calloc(nonce_len, sizeof(char));

	reqSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    reqSM.size  = req_len;
	reqSM.buffer = calloc(req_len, sizeof(char));

	hmacSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    hmacSM.size  = hmac_len;
	hmacSM.buffer = calloc(hmac_len, sizeof(char));

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE, TEEC_NONE);

	op.params[0].memref.parent = &nonceSM;
    op.params[0].memref.size = nonce_len;
    memcpy(nonceSM.buffer, nonce, nonce_len);

    op.params[1].memref.parent = &reqSM;
    op.params[1].memref.size = req_len;
    memcpy(reqSM.buffer, req, req_len);

    op.params[2].memref.parent = &hmacSM;
    op.params[2].memref.size = hmac_len;
    memcpy(hmacSM.buffer, hmac, hmac_len);

	/* Use TEE Client API to allocate the underlying memory buffer. */
	res = TEEC_RegisterSharedMemory(&ctx, &nonceSM);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	res = TEEC_RegisterSharedMemory(&ctx, &reqSM);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	res = TEEC_RegisterSharedMemory(&ctx, &hmacSM);
    if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*if (result != TEEC_SUCCESS)
	{
	goto cleanup3;
	}*/

	/* Clear the TEEC_Operation struct */
	// memset(&op, 0, sizeof(op));

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */
	printf("Invoking DBStore operation with values %s, %s and %s\n", (char *) nonceSM.buffer, 
		(char *) reqSM.buffer, (char *) hmacSM.buffer);
	res = TEEC_InvokeCommand(&sess, TA_DBSTORE_INV, &op,
		&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("DBStore answered with values %s, %s and %s\n", (char *) nonceSM.buffer,
		(char *) reqSM.buffer, (char *) hmacSM.buffer);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
}

int main(int argc, char *argv[])
{
	if(strcmp(argv[1], "init") == 0)
		call_ta_init(0, argv[2]);
	else if(strcmp(argv[1], "inv") == 0)
		call_ta_inv(1, argv[2], argv[3], argv[4]);
	else
		printf("ERROR: Unrecognized call to DBStore\n");

	return 0;
}
