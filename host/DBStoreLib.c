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
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
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
"MIIEowIBAAKCAQEA0NhVkTM+cICoPiQFnZ3jMed/vRzJjClYzd0UlOqp1qWxJcOe\n"
"7bG9rZOFNkkTpWqxOfKZQzHKqGmZZauXxPq5IfG72ig9f9hLyv3Npb6X5bFfdCGF\n"
"BA7t8Y6DQMB5K2Qz5+1HQlaH5R4xJ/hwUloUBzSwmljnMvacBErT4CqcKnYa+QBs\n"
"FyBy+adGElRoo/vFksZ39BlmhjMRI6jYwCjKRhY/N+rrkGOAim1hVSl/gpAtQVNT\n"
"PXKVfwDFadQTkgCOyz2Wj1dSvZ/Ugarq3ByjXYcG34OZFYOYgixNqBVvHdjLkXmj\n"
"TQz3bc2XdsKYGlNl2UCiI8oOYxm17+kG3nVSfQIDAQABAoIBABZ7Y2K5IHyd7P6b\n"
"hBs+lumVYTPreGrlPJEUvpV1WYko1xQYpfAylRetbMa2QS4qeR+i1QrdvlI44/GE\n"
"8labIvjbe/x1HoG3uBkHD29LQDDS0lK/FQGl1cmOLOT4k1Kve8L40RX8GK76fBIw\n"
"dW74EXXhHy3Oaj0bPRpdL8fO7nbHhDtIP7KaUQQ7/rsFi6yD4OTD+Ixu0d9SSDFU\n"
"PkTfFzSxiDTYpafJsfn7FOkQaY5HmlnOuRUQ6xYbjStueII4zc6zw1AX2euu8Imv\n"
"PnHNkNX1B1cYmucp46maHmevQCWNt0Dkd9Rbcq1k45IyclwsbIvxaLibhDFy0KA/\n"
"K/YNeqUCgYEA7oMKbInUP0MXz42zebNvDqnkUOer6JG8pobMSKhNhBQ0NBEcRxwT\n"
"Yq/Ke/uYx2RmSlbwuC5Ymx/SftWm4w/HqKbcCphgvVc5qKSIbmjfDawhpFLn3/eO\n"
"r5ZPXnOMwiuJAaGK8TbIDWWMhnpsR3NXeAFSPkh22zClBfLzckyRY0cCgYEA4Chv\n"
"mC13CJ8L49khJNvh+Pa2okMiVPuIZVQ8oJlsBHz4CWVoCvKKVBPblD6hD9VCNi2D\n"
"H0tDoRH6A2nX6zaEhMR97A5cqBFr7s68qXrS88z6gs2ip2GjYXujKpOnIDw7XdrA\n"
"VPJDWkWFbljnJlswlzb3eU0lhdKDtRDjSNUKVhsCgYAxI3I8VlESD4KSUkFNq3gP\n"
"71SIjpJOQeg57r+boIEH2xm+OGA5DkG4LTtsO7OIMNkaK7tAVtwOaYn2c5IEabXa\n"
"uzXOQQJ9P8EzS2KITLbXnET6E9KNw/Tzm+YSMYAoaMu7OErl00F38Rn4grRYLB0z\n"
"LiKBjnBeTDFTfnBFdhzl9QKBgQDIdyEl5TMZALPvdtVPU13J+0nl30gq3DBk/mqh\n"
"7dNOSDzCmm/rqnDPNFshPslnkX7/WMB1EihPOfZvaw7wifcFjXxXyZhPrhTqovTS\n"
"VMenxV8b769RJd6pZZrMjvPdvkARdXqf/XECoD3uK4+9G7xe34d+ceHmxheHrKy3\n"
"C9+MlQKBgCWBS9/lLwptf3abwuFsRxi6GknJMGFhsKoWbIt2F4BSPfl2n12XSb00\n"
"NRyvzQYhwTyCeW7R653kDq26iA+Y0z/x4rSwdAymA1UZ3OCy3hARMFSBjsA3T5cI\n"
"wQRtpvHJlhkM2+Ix/2O30kCMPiDoaBlDPJYEzs//Ftdb0M3+PsQx\n"
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

struct ctr_state {
	unsigned char *key;
	unsigned char *iv;
	unsigned int encrypt;
	const EVP_CIPHER *cipher_type;
};

void print_bytes(char * string, char * bytes, int len) {
	printf("%s ", string);
 
    for (int i = 0; i != len; i++)
        printf("%02x", (unsigned int)string[i]);
 
    printf("\n");
}

void transform_challenge(char * challenge) {
	int i = 0;

	while(i < strlen(challenge)) {
		challenge[i] += 2;
		i += 2;
	}
}

int verify_challenge(char * challenge, char * received) {

	transform_challenge(challenge);

	return strncmp(challenge, received, strlen(challenge));
}

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
   //BIO_free(keybio); //CAREFUL!!
   return rsa;
}

// encrypt in string using the private key
int encrypt_using_public_key (char * public_key, char * in, int in_len, char * out, int * out_len) {

   RSA * rsa;

   rsa = createRSA ((unsigned char *) public_key, 1);
   *out_len = RSA_public_encrypt (in_len, (unsigned char *)in, (unsigned char *)out, rsa, RSA_PKCS1_PADDING);

   //RSA_free(rsa);

   if (*out_len == -1) {
      return -1;
   } else {
      return 1;
   }
}

// decrypt in string using the public key
int decrypt_using_private_key (char * in, int in_len, char * out, int * out_len) {

   RSA * rsa;

   rsa = createRSA ((unsigned char *) private_key_app, 0);
   *out_len = RSA_private_decrypt (in_len, (unsigned char *)in, (unsigned char *) out, rsa, RSA_PKCS1_PADDING);

   //RSA_free(rsa);

   if (*out_len == -1)
      return -1;
   else {
      return 1;
   }
}

void ctr_encrypt_decrypt(struct ctr_state * params, unsigned char * in, int in_len, unsigned char * out, int * out_len, int message_len) {

	//int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
	EVP_CIPHER_CTX *ctx;
	int len;
	unsigned char result[256];
	unsigned char *received = (unsigned char *) malloc(sizeof(unsigned char) * in_len + 1);

	memcpy(received, in, in_len);

	ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, params->cipher_type, NULL, params->key, params->iv, params->encrypt);
	EVP_CipherUpdate(ctx, result, &len, received, in_len);
	EVP_CipherFinal_ex(ctx, result, &len);
	EVP_CIPHER_CTX_cleanup(ctx);

	*out_len = len;

	memcpy(out, result, message_len);
	free(received);
}

int aes_ctr(char * in, int in_len, char * out, int * out_len, unsigned char * key, unsigned char * iv, int message_len, int op) {

	struct ctr_state *params = (struct ctr_state *) malloc(sizeof(struct ctr_state));

	params->key = key;
	params->iv = iv;
	params->encrypt = op;
	params->cipher_type = EVP_aes_128_ctr();

	ctr_encrypt_decrypt(params, (unsigned char *) in, in_len, (unsigned char *) out, out_len, message_len);

	return 0;
}

void gen_hmac(char * in, int in_len, char * out, int * out_len, unsigned char * key) {

	unsigned char * result = (unsigned char *) malloc(sizeof(char) * 20);
	unsigned int len;

	HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
 
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(&ctx, key, 16, EVP_sha1(), NULL);
    HMAC_Update(&ctx, (unsigned char*) in, in_len);
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);

    *out_len = len;
    memcpy(out, result, 20);

    free(result);
}

int verify_hmac(char * in, int in_len, char * hmac, int * hmac_len, unsigned char * key) {
	char * generated_hmac = (char *) malloc(sizeof(char) * 20);
	int len;

	gen_hmac(in, in_len, generated_hmac, &len, key);
	*hmac_len = len;

	if(memcmp(generated_hmac, hmac, 20) == 0) {
		free(generated_hmac);
		return 1;
	}
	free(generated_hmac);
	return 0;
}

void call_ta_init(int call_type, const char *appid, char *session_key, char *iv)
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

	int message_len = strlen(appid) + NONCE_LEN + 1;

	char nonce[NONCE_LEN] = {0};
	char *message = (char *) malloc(message_len * sizeof(char));

	char crypto_req[CRYPTO_LEN] = {0};
	int crypto_req_len;
	static char decrypt_rsa[CRYPTO_LEN] = {0}; //will hold the session key
	int decrypt_rsa_len;
	char *decrypt_aes = (char *) malloc(message_len * sizeof(char)); //will hold the modified challenge
	int decrypt_aes_len;
	char r_iv[16];
	//char signature[256] = {0};

	//const char *input = "teste\n";
    //int req_len = strlen(req);

    //int certificate_len = 255;

    cryptoSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    cryptoSM.size  = CRYPTO_LEN;
	cryptoSM.buffer = calloc(CRYPTO_LEN, sizeof(char));

    signatureSM.flags = TEEC_MEM_OUTPUT;
    signatureSM.size  = 256;
	signatureSM.buffer = calloc(256, sizeof(char));

	modulusSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    modulusSM.size  = 256;
	modulusSM.buffer = calloc(256, sizeof(char));

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

	//printf("signature %s\n", signature);

	op.params[0].memref.parent = &signatureSM;
    op.params[0].memref.size = 256;
    //memcpy(signatureSM.buffer, signature, 256);
    //memcpy(signatureSM.buffer, "signature", 9);

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

	printf("INIT: Invoking DBStore on the TA\n");
	res = TEEC_InvokeCommand(&sess, TA_DBSTORE_INIT, &op,
		 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	if(decrypt_using_private_key(modulusSM.buffer, 256, decrypt_rsa, &decrypt_rsa_len) != 1)
		printf("Bad decrypto...");

	printf("INIT: Decrypted session key\n");
	memcpy(r_iv, cryptoSM.buffer, 16);
	printf("INIT: Received IV\n");

	aes_ctr(signatureSM.buffer, 256, decrypt_aes, &decrypt_aes_len, (unsigned char *) decrypt_rsa, 
		(unsigned char *) r_iv, message_len, 0);

	printf("INIT: Decrypted challenge is %s\n", decrypt_aes);
	
	if(verify_challenge(message, decrypt_aes) == 0)
		printf("INIT: Authenticated DBStore\n");
	else
		printf("INIT: Could not authenticate DBStore\n");

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	free(message);

	memcpy(session_key, decrypt_rsa, 16);
	memcpy(iv, r_iv, 16);
}

void call_ta_inv(int call_type, const char *req, char * session_key, char *iv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = {0};
	// TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	TEEC_UUID uuid = TA_DBSTORE_UUID; //will be DBStore code running on TZ!
	uint32_t err_origin;

	char *re_nonce;
	char *re_req;
	char *re_hmac;

	int out_nonce_len, out_req_len;
	int crypt_nonce_len = (NONCE_LEN/16 + 1) * 32;
	char *crypt_nonce = (char*) malloc(sizeof(char) * crypt_nonce_len);
	int crypt_req_len = (strlen(req)/16 + 1) * 32;
	char *crypt_req = (char*) malloc(sizeof(char) * crypt_req_len);

	int decrypt_reply_len = 2;
	char *decrypt_reply = (char*) malloc(sizeof(char) * decrypt_reply_len);

	char *hmac = (char *) malloc(sizeof(char) * 20);
	int hmac_len, re_hmac_len;

	char *nonce = (char*) malloc(sizeof(char) * NONCE_LEN);

	rand_str(nonce, NONCE_LEN);

	printf("INV: Generated nonce is %s\n", nonce);

	/* Shared buffers */
	TEEC_SharedMemory nonceSM = {0};
	TEEC_SharedMemory reqSM = {0};
	TEEC_SharedMemory hmacSM = {0};

	//char crypto_appid[32];
	//char crypto_nonce[32];

	//Generate HMAC for the message
    gen_hmac((char *) req, strlen(req), hmac, &hmac_len, (unsigned char*) session_key);

    nonceSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    nonceSM.size  = crypt_nonce_len;
	nonceSM.buffer = calloc(crypt_nonce_len, sizeof(char));

	reqSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    reqSM.size  = crypt_req_len;
	reqSM.buffer = calloc(crypt_req_len, sizeof(char));

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
					 TEEC_MEMREF_WHOLE, TEEC_VALUE_INOUT);

	//Encryption phase
	aes_ctr(nonce, NONCE_LEN, crypt_nonce, &out_nonce_len, (unsigned char*) session_key, (unsigned char*) iv, crypt_nonce_len, 1);
	aes_ctr((char *) req, strlen(req), crypt_req, &out_req_len, (unsigned char*) session_key, (unsigned char*) iv, crypt_req_len, 1);

	op.params[0].memref.parent = &nonceSM;
    op.params[0].memref.size = crypt_nonce_len;
    memcpy(nonceSM.buffer, crypt_nonce, crypt_nonce_len);

    op.params[1].memref.parent = &reqSM;
    op.params[1].memref.size = crypt_req_len;
    memcpy(reqSM.buffer, crypt_req, crypt_req_len);

    op.params[2].memref.parent = &hmacSM;
    op.params[2].memref.size = hmac_len;
    memcpy(hmacSM.buffer, hmac, hmac_len);

    op.params[3].value.a = strlen(req);

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
	printf("INV:Invoking DBStore operation with statement %s\n", (char *) reqSM.buffer);
	print_bytes("INV: HMAC - ", hmacSM.buffer, 20);
	res = TEEC_InvokeCommand(&sess, TA_DBSTORE_INV, &op,
		&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	re_nonce = (char *) nonceSM.buffer;
	re_req = (char *) reqSM.buffer;
	re_hmac = (char *) hmacSM.buffer;

	printf("DBStore answered with values %s, %s and %s\n", re_nonce, re_req, re_hmac);

	printf("INV: Decrypting DBStore reply...\n");
	aes_ctr(re_req, crypt_req_len, decrypt_reply, &decrypt_reply_len, (unsigned char*) session_key, (unsigned char*) iv, 2, 0);
	printf("INV: Decrypted DBStore reply - %s\n", decrypt_reply);

	printf("INV: Verifying received HMAC...\n");
	if(verify_hmac(decrypt_reply, 2, re_hmac, &re_hmac_len, (unsigned char*) session_key))
		printf("INV: HMAC verified\n");
	else
		printf("INV: ERROR - Could not verify HMAC\n");

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	free(nonce);
	free(hmac);
	free(crypt_nonce);
	free(crypt_req);
	free(decrypt_reply);
}

int main(int argc, char *argv[])
{	
	char *session_key = NULL;
	char *iv = NULL;
	char input[5];
	while(1) {

		printf("Welcome to DBStore!\n");
		printf("Write \"init\" to start initialization protocol (sending o)\n");
		printf("Write \"inv\" to start invocation protocol (sending o o o and session_key\n");
		printf("Write \"exit\" to quit the program\n");

		fgets(input, 6, stdin);

		if(strncmp(input, "init", 4) == 0) {
			if(session_key == NULL) {
				session_key = (char *) malloc(sizeof(char) * 16);
				iv = (char *) malloc(sizeof(char) * 16);
				call_ta_init(0, "o", session_key, iv);
			}
			else
				printf("ERROR: DBStore was already initialized\n");
		}
		else if(strncmp(input, "inv", 3) == 0) {
			if(session_key != NULL) {
				call_ta_inv(1, "ola", session_key, iv);
			}
			else
				printf("ERROR: DBStore not initialized\n");
		}
		else if(strncmp(input, "exit", 4) == 0) {
			printf("Exiting DBStore... bye!\n");
			break;
		}
		else
			printf("ERROR: Unrecognized call to DBStore\n");
	}
	free(session_key);
	free(iv);
	return 0;
}
