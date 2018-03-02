#ifndef CRYPTO_H
#define CRYPTO_H

int verify_challenge(char * challenge, char * received);
void transform_challenge(char * challenge);
int decrypt_using_private_key (char * in, int in_len, char * out, int * out_len);
int encrypt_using_public_key (uint8_t * modulus, const char * in, int in_len, char * out, int * out_len);
int encrypt_aes_ctr(char * in, int in_len, char * out, int * out_len, unsigned char * key, unsigned char * iv);
int decrypt_aes_ctr(char * in, int in_len, char * out, int * out_len, unsigned char * key, unsigned char * iv);

#endif /*CRYPTO_H*/
