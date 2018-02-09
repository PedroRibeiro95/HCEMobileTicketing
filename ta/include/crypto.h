#ifndef CRYPTO_H
#define CRYPTO_H

int decrypt_using_private_key (char * in, int in_len, char * out, int * out_len);
int encrypt_using_public_key (uint8_t * modulus, const char * in, int in_len, char * out, int * out_len);

#endif /*CRYPTO_H*/
