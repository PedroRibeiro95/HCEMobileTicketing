#ifndef CRYPTO_H
#define CRYPTO_H

int verify_challenge(char * challenge, char * received);
void transform_challenge(char * challenge);
int decrypt_using_private_key (unsigned char * in, int in_len, char * out, int * out_len);
int encrypt_using_public_key (uint8_t * modulus, char * in, int in_len, unsigned char * out, int * out_len);
int encrypt_aes_ctr(char * in, int in_len, unsigned char * out, int * out_len, unsigned char * key, unsigned char * iv);
int decrypt_aes_ctr(unsigned char * in, int in_len, char * out, int * out_len, unsigned char * key, unsigned char * iv);
int verify_hmac (char * in, int in_len, unsigned char * hmac, int hmac_len, unsigned char * session_key);
int gen_hmac (char * in, int in_len, unsigned char * out, int * out_len, unsigned char * session_key);
int update_session_key(unsigned char *session_key);

void print_bytes(const char * string, unsigned char * bytes, int len); //to remove from here

#endif /*CRYPTO_H*/
