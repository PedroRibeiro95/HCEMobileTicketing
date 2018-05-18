/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdlib.h>
#include <dbstore_ta.h>
#include <crypto.h>
#include <dbparser.h>
#include "LittleD/strcat.h"
#include "LittleD/atoi.h"

//#include <stdint.h>

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

uint8_t modulus_dbstore[] = 
"\xc6\xfb\x54\x54\x2c\x73\x18\xd8\x94\xcd\x83\x12\x3b\xff"
"\xb8\x09\x16\xe5\xcc\x89\x0d\x9f\x42\x12\x7a\x74\x73\x02\x48"
"\x45\x8d\x99\x30\xbe\x12\xed\x24\x10\x24\x2f\x1b\x7e\xd2\x9b"
"\x03\x6c\x42\x20\xa8\x9e\xe2\x4d\xea\x19\x15\x58\x1d\x60\x7c"
"\x12\x1e\x78\x7c\x89\x73\x86\xd3\xa2\xc4\xe2\x32\x70\x3e\x1f"
"\x1b\x12\xad\x8a\x1a\x0a\xb6\xd9\xd3\xf6\xbe\x52\xc4\x9f\xa2"
"\x9d\x9c\xc5\xcf\x2e\xf3\xa9\xc4\x5c\xa1\xa7\xf8\xb0\xa9\x86"
"\x59\x2d\x44\x41\x77\xc4\xd5\xff\x72\x9d\xaf\x25\x83\x6a\x0e"
"\x02\xe1\x6f\xb1\xe9\x25\x80\xb7\xed\xc6\x26\xa1\x6f\x8c\x79"
"\xaa\xbb\xa1\x98\x5d\x60\xb7\x87\xc6\x35\x16\xe9\x85\xae\x39"
"\x45\xb2\xc5\x1a\x4e\x13\x17\x32\xa0\x51\xf3\xc1\x37\xcd\xff"
"\xf0\x44\x59\x4c\xa3\xaa\x51\x26\xef\x2c\x88\xe1\xa3\x88\xd3"
"\x38\xe9\xeb\xb5\xec\x76\x43\x3b\x5a\x5a\xc8\x3e\x2f\xac\x26"
"\xd8\xcf\xf5\xca\xb9\x9b\x6b\x27\x45\x1b\x36\xf0\x85\x52\x3f"
"\xab\x2e\x62\xe4\xce\x7a\xf9\xd6\xac\x84\xd2\x45\x81\xfd\x7b"
"\x74\x19\x9f\x5b\x2b\x83\xd1\x64\xc5\x27\xb8\x97\x16\x17\xee"
"\x93\x5d\xcc\x01\x2d\xdc\x01\x4d\x82\x80\x09\x67\x7b\x38\x50"
"\x76\x75";

uint8_t public_key[] =
"\x01\x00\x01";

uint8_t private_key_dbstore[] =
"\x4a\x19\x0b\xa5\x30\xcc\x47\xa3\x57\x7e\x54\x61\xf4\xef\xdc"
"\x43\x9e\x40\x42\xf3\x82\x9c\x1c\xc9\xae\xca\x30\x8d\xd8\x05"
"\xf6\x9d\xe6\x55\xd1\xcc\x77\x52\x7f\x76\xff\x61\x31\xe2\x41"
"\xdb\x0d\xa1\x05\xc9\xec\xf2\x20\xcb\xe8\x73\xe0\xb4\xae\x5f"
"\x3c\xf3\x97\x44\xc4\x3d\xa0\x10\x0c\x0b\x43\xc7\x22\x8b\x08"
"\xd4\xe2\xc4\xfb\xbf\xa3\xa9\xe8\x52\x09\x3b\xdf\x36\xa7\x22"
"\xd4\x5f\xa1\x30\x95\xd2\x51\x6a\x41\x54\xc0\xba\x60\xd6\xc3"
"\xdc\xa4\x7f\x50\xaf\x7f\x15\x5a\x44\x38\x15\xdb\x23\x22\x46"
"\x96\x56\xb6\xc4\xe0\x8f\x57\x6e\x4d\xc9\xd5\xb9\x31\xc1\x2d"
"\x20\xc9\x39\x19\xa8\xe4\x8c\xc9\xe1\x67\xa8\xbc\xcc\x90\x8d"
"\xeb\x0b\x9d\x43\x25\xff\xc2\x0d\x2f\x79\x74\xd4\x10\x0e\xef"
"\xc5\x5c\x56\x76\x5a\xe9\x97\x26\x26\x17\xeb\x69\x74\x30\x93"
"\x17\xd3\x02\xdc\x7b\xcc\x78\xe1\xe4\x7c\x66\x69\x41\x46\x9a"
"\x3a\x5a\x2e\x87\xe7\xbf\xbc\xad\xbf\x46\xe6\xa4\xb8\xd7\x2f"
"\xd4\x97\x41\xfe\x47\x29\xd0\xf3\xa0\x25\x13\x1f\x7b\xff\x16"
"\x8b\x3d\x76\xf4\x8f\xd4\x74\xac\x4e\x23\xd9\x67\xa4\xa0\xfe"
"\xec\xf7\xe0\x60\x45\x79\xaa\x6c\x54\xa0\xb6\xae\x3e\xcc\x94"
"\x61";

//SELECT * FROM t WHERE i=1;

void where_parser(char * sql_stmt, int sql_len) {
  /* LittleD stuff */
  char memseg[400];
  char *to_print;
  char *int_converted;
  db_query_mm_t mm;
  db_op_base_t* root;
  db_tuple_t    tuple;
  int i, where = 0;

  char *select_all = NULL;
  char *where_clause = NULL;
  int aux_int;
  char *aux_char;
  unsigned char *attr_name;

  char temp_hold[40];
  char aux_sprintf[15];
  int clause_ok = 0;

  for(i = 0; i < sql_len; i++) {
    if(i+4 < sql_len && sql_stmt[i] == 'W' && sql_stmt[i+1] == 'H' && sql_stmt[i+2] == 'E' &&
        sql_stmt[i+3] == 'R' && sql_stmt[i+4] == 'E') {
      
      select_all = calloc(i, sizeof(char));
      memcpy(select_all, sql_stmt, i-1);
      select_all[i-1] = ';';

      where = 1;
      where_clause = calloc(sql_len-(i+5), sizeof(char));
      memcpy(where_clause, sql_stmt+i+6, sql_len-(i+6));
    }
  }

  if(where == 0) {
    init_query_mm(&mm, memseg, 400);
    root = parse((char*) sql_stmt, &mm);
  }
  else {
    init_query_mm(&mm, memseg, 400);
    root = parse((char*) select_all, &mm);
    free(select_all);
  }

  if (root == NULL)
  {
      printf((char*) "NULL root\n");
  }
  else
  {
      init_tuple(&tuple, root->header->tuple_size, root->header->num_attr, &mm);

      IMSG("Printing SELECT results:\n");

      to_print = malloc(sizeof(char) * 400);
      memset(temp_hold, 0, 40);

      while(next(root, &tuple, &mm) == 1)
      {

        strcat(to_print, "| ");

        for (i = 0; i < (db_int)(root->header->num_attr); i++) 
        {
          attr_name = (unsigned char*)root->header->names[i];
          if(root->header->types[i] == 0) //the attribute is an integer
          {
            aux_int = getintbyname(&tuple, (char*) attr_name, root->header);
            if(where == 0) {
              strcat(to_print, (char*) attr_name);
              strcat(to_print, ": ");
              int_converted = malloc(sizeof(char) * 10);
              snprintf(int_converted, 10, "%d", aux_int);
              strcat(to_print, int_converted);
              strcat(to_print, " | ");
              free(int_converted);
            }
            else {
              memset(aux_sprintf, 0, 15);
              int_converted = malloc(sizeof(char) * 10);
              snprintf(int_converted, 10, "%d", aux_int);
              snprintf(aux_sprintf, 15, "%s=%s", (char*) attr_name, int_converted);
              if(strncmp(aux_sprintf, where_clause, strlen(aux_sprintf)) == 0)
                clause_ok = 1;
              strcat(temp_hold, int_converted);
              strcat(temp_hold, ":");
              free(int_converted);
            }
          }
          else //the attribute is a string
          {
            aux_char = getstringbyname(&tuple, (char*) attr_name, root->header);
            if(where == 0) {
              strcat(to_print, (char*) attr_name);
              strcat(to_print, ": ");
              strcat(to_print, aux_char);
              strcat(to_print, " | ");
            }
            else {
              memset(aux_sprintf, 0, 15);
              snprintf(aux_sprintf, 15, "%s=%s", (char*) attr_name, aux_char);
              if(strncmp(aux_sprintf, where_clause, strlen(aux_sprintf)) == 0)
                clause_ok = 1;
              strcat(temp_hold, aux_char);
              strcat(temp_hold, ":");
            }
          }
        }
        if(where == 0)
          strcat(to_print, "\n");
        else if(where == 1 && clause_ok == 1) {
          strcat(to_print, temp_hold);
          clause_ok = 0;
        }
        memset(temp_hold, 0, 40);
      }

      printf("%s\n", to_print);
      free(to_print);
  }
}

int is_digit (char c) {
    if ((c>='0') && (c<='9')) return 1;
    return 0;
}

void transform_challenge(char * challenge) {
  int i = 0;

  while(i < (int) strlen(challenge)) {
    challenge[i] += 2;
    i += 2;
  }
}

void print_bytes(const char * string, unsigned char * bytes, int len) {
  printf("%s ", string);
 
    for (int i = 0; i != len; i++)
        printf("%02x", (unsigned int)bytes[i]);
 
    printf("\n");
}

int decrypt_using_private_key (unsigned char * in, int in_len, char * out, int * out_len) {

   TEE_Result ret = TEE_SUCCESS; // return code
   TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
   TEE_Attribute rsa_attrs[3];  // array for the keys
   TEE_ObjectInfo info;
   TEE_OperationHandle handle = (TEE_OperationHandle) NULL;

   uint32_t cipher_len = 256; // return encrypted hash length
   void *cipher = NULL; // return encrypted hash

   uint32_t decoded_len = 512; // return decoded hash length
   void *decoded = NULL; // return decoded hash

   // modulus
   rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
   rsa_attrs[0].content.ref.buffer = modulus_dbstore;
   rsa_attrs[0].content.ref.length = SIZE_OF_VEC(modulus_dbstore);

   // Public key
   rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
   rsa_attrs[1].content.ref.buffer = public_key;
   rsa_attrs[1].content.ref.length = SIZE_OF_VEC(public_key);

   // Private key
   rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
   rsa_attrs[2].content.ref.buffer = private_key_dbstore;
   rsa_attrs[2].content.ref.length = SIZE_OF_VEC(private_key_dbstore);

   // create a transient object
   ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &key);
   if (ret != TEE_SUCCESS) {
      IMSG("ERROR: Crypto bad parameters 1\n");
      return TEE_ERROR_BAD_PARAMETERS;
   }

   // populate the object with your keys
   ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&rsa_attrs, 3);
   if (ret != TEE_SUCCESS) {
      IMSG("ERROR: Crypto bad parameters 2\n");
      return TEE_ERROR_BAD_PARAMETERS;
   }

   cipher = TEE_Malloc(cipher_len, 0);
   decoded = TEE_Malloc(decoded_len, 0);
   if (!cipher || !decoded) {
      IMSG("ERROR: Crypto bad parameters 3\n");
      return TEE_ERROR_BAD_PARAMETERS;
   }
   TEE_MemMove(cipher, in, in_len);
   cipher_len = in_len;

   // setup the info structure about the key
   TEE_GetObjectInfo(key, &info);

   // Allocate the operation
   ret = TEE_AllocateOperation(&handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, 2048);
   if (ret != TEE_SUCCESS) {
      IMSG("ERROR: Crypto allocate\n");
      return -1;
   }

   // set the key
   ret = TEE_SetOperationKey(handle, key);
   if (ret != TEE_SUCCESS) {
      IMSG("ERROR: Crypto set key\n");
      TEE_FreeOperation(handle);
      return -1;
   }
   // decrypt
   ret = TEE_AsymmetricDecrypt (handle, (TEE_Attribute *) NULL, 0, cipher, in_len, decoded, &decoded_len);
   if (ret == TEE_ERROR_SHORT_BUFFER) {
      IMSG("ERROR: Crypto decrypt short input buffer\n");
      TEE_FreeOperation(handle);
      return TEE_ERROR_BAD_PARAMETERS;
   }
   else if (ret == TEE_ERROR_BAD_PARAMETERS) {
      IMSG("ERROR: Crypto decrypt bad parameters\n");
      TEE_FreeOperation(handle);
      return TEE_ERROR_BAD_PARAMETERS;
   }

   // return encrypted
   memcpy (out, decoded, decoded_len);
   *out_len = decoded_len;

   // clean up after yourself
   TEE_FreeOperation(handle);
   TEE_FreeTransientObject (key);
   TEE_Free (cipher);

   // fin
   return 0;
}

int encrypt_using_public_key (uint8_t * modulus, char * in, int in_len, unsigned char * out, int * out_len) {

   TEE_Result ret = TEE_SUCCESS; // return code
   TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
   TEE_Attribute rsa_attrs[2];
   void * to_encrypt = NULL;
   uint32_t cipher_len = 512;
   void * cipher = NULL;
   TEE_ObjectInfo info;
   TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
   unsigned long int sizeofmod = 256; //hack because casting void * to uint8_t * leads to a sizeof of -1

   // modulus
   rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
   rsa_attrs[0].content.ref.buffer = modulus;
   rsa_attrs[0].content.ref.length = sizeofmod;
   // Public key
   rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
   rsa_attrs[1].content.ref.buffer = public_key;
   rsa_attrs[1].content.ref.length = SIZE_OF_VEC (public_key);

   // create a transient object
   ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, 2048, &key);
   if (ret != TEE_SUCCESS) {
      return TEE_ERROR_BAD_PARAMETERS;
   }

   // populate the object with your keys
   ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&rsa_attrs, 2);
   if (ret != TEE_SUCCESS) {
      return TEE_ERROR_BAD_PARAMETERS;
   }

   // create your structures to de / encrypt
   to_encrypt = TEE_Malloc(512, 0);
   cipher = TEE_Malloc(cipher_len, 0);
   if (!to_encrypt || !cipher) {
      return TEE_ERROR_BAD_PARAMETERS;
   }
   TEE_MemMove(to_encrypt, in, in_len);

   // setup the info structure about the key
   TEE_GetObjectInfo (key, &info);

   // Allocate the operation
   ret = TEE_AllocateOperation(&handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, 2048);
   if (ret != TEE_SUCCESS) {
      return -1;
   }

   // set the key
   ret = TEE_SetOperationKey(handle, key);
   if (ret != TEE_SUCCESS) {
      TEE_FreeOperation(handle);
      return -1;
   }

   // encrypt
   ret = TEE_AsymmetricEncrypt (handle, (TEE_Attribute *)NULL, 0, to_encrypt, in_len, cipher, &cipher_len);
   if (ret == TEE_ERROR_SHORT_BUFFER) {
      IMSG("ERROR: Crypto encrypt short input buffer\n");
      TEE_FreeOperation(handle);
      return TEE_ERROR_BAD_PARAMETERS;
   }
   else if (ret == TEE_ERROR_BAD_PARAMETERS) {
      IMSG("ERROR: Crypto encrypt bad parameters\n");
      TEE_FreeOperation(handle);
      return TEE_ERROR_BAD_PARAMETERS;
   }

   // finish off
   memcpy (out, cipher, cipher_len);
   *out_len = cipher_len;
   //out[cipher_len] = '\0';

   // clean up after yourself
   TEE_FreeOperation(handle);
   TEE_FreeTransientObject (key);
   TEE_Free (cipher);


   // finished
   return 0;
}

int encrypt_aes_ctr(char * in, int in_len, unsigned char * out, int * out_len, unsigned char * session_key, unsigned char * iv) {
  TEE_Result ret = TEE_SUCCESS; // return code
  TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
  TEE_Attribute aes_attrs[1];
  void * to_encrypt = NULL;
  void * cipher = NULL;
  TEE_ObjectInfo info;
  TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
  uint32_t encrypted_len = (in_len/16 + 1) * 32;

  //AES key
  aes_attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
  aes_attrs[0].content.ref.buffer = session_key;
  aes_attrs[0].content.ref.length = 16;

  // create a transient object
  ret = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // populate the object with your keys
  ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_attrs, 1);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // create your structures to de / encrypt
  /*to_encrypt = TEE_Malloc(in_len, 0);
  cipher = TEE_Malloc(encrypted_len, 0);*/
  to_encrypt = malloc(sizeof(unsigned char) * in_len);
  cipher = malloc(sizeof(unsigned char) * encrypted_len);
  if (!to_encrypt || !cipher) {
    return TEE_ERROR_BAD_PARAMETERS;
  }
  TEE_MemMove(to_encrypt, in, in_len);

  // setup the info structure about the key
  TEE_GetObjectInfo (key, &info);

  // Allocate the operation
  ret = TEE_AllocateOperation(&handle, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, 128);
  if (ret != TEE_SUCCESS) {
    return -1;
  }

  // set the key
  ret = TEE_SetOperationKey(handle, key);
  if (ret != TEE_SUCCESS) {
    TEE_FreeOperation(handle);
    return -1;
  }

  // encrypt
  TEE_CipherInit(handle, iv, 16);

  ret = TEE_CipherUpdate(handle, to_encrypt, in_len, cipher, &encrypted_len);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    IMSG("ERROR: Cipher update error\n");
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  memcpy (out, cipher, encrypted_len);
  *out_len = encrypted_len;

  ret = TEE_CipherDoFinal(handle, to_encrypt, in_len, cipher, &encrypted_len);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    IMSG("ERROR: Cipher final error\n");
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // finish off
  //memcpy (out, cipher, encrypted_len);
  //*out_len = encrypted_len;
  //out[cipher_len] = '\0';

  // clean up after yourself
  TEE_FreeOperation(handle); //FIXME
  TEE_FreeTransientObject (key);
  //TEE_Free (cipher);
  free(cipher);

  return 0;
}

int decrypt_aes_ctr(unsigned char * in, int in_len, char * out, int * out_len, unsigned char * session_key, unsigned char * iv) {
  TEE_Result ret = TEE_SUCCESS; // return code
  TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
  TEE_Attribute aes_attrs[1];
  void * to_decrypt = NULL;
  void * cipher = NULL;
  TEE_ObjectInfo info;
  TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
  uint32_t decrypted_len = (in_len/16 + 1) * 32;

  //AES key
  aes_attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
  aes_attrs[0].content.ref.buffer = session_key;
  aes_attrs[0].content.ref.length = 16;

  // create a transient object
  ret = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &key);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // populate the object with your keys
  ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_attrs, 1);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // create your structures to de / decrypt
  /*to_decrypt = TEE_Malloc(in_len, 0);
  cipher = TEE_Malloc(decrypted_len, 0);*/
  to_decrypt = malloc(sizeof(unsigned char) * in_len);
  cipher = malloc(sizeof(unsigned char) * decrypted_len);
  if (!to_decrypt || !cipher) {
    return TEE_ERROR_BAD_PARAMETERS;
  }
  TEE_MemMove(to_decrypt, in, in_len);

  // setup the info structure about the key
  TEE_GetObjectInfo (key, &info);

  // Allocate the operation
  ret = TEE_AllocateOperation(&handle, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, 128);
  if (ret != TEE_SUCCESS) {
    return -1;
  }

  // set the key
  ret = TEE_SetOperationKey(handle, key);
  if (ret != TEE_SUCCESS) {
    TEE_FreeOperation(handle);
    return -1;
  }

  // decrypt
  TEE_CipherInit(handle, iv, 16);

  /*ret = TEE_CipherUpdate(handle, to_decrypt, in_len, cipher, &decrypted_len);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    IMSG("ERROR: Cipher update error\n");
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  memcpy (out, cipher, decrypted_len);
  *out_len = decrypted_len;*/

  ret = TEE_CipherDoFinal(handle, to_decrypt, in_len, cipher, &decrypted_len);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    IMSG("ERROR: Cipher final error\n");
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  memcpy (out, cipher, decrypted_len);
  *out_len = decrypted_len;

  // finish off
  //memcpy (out, cipher, decrypted_len);
  //*out_len = decrypted_len;
  //out[cipher_len] = '\0';

  // clean up after yourself
  TEE_FreeTransientObject(key);
  TEE_FreeOperation(handle); //FIXME: BOth of these are crashing for some reason
  //TEE_Free(cipher);
  free(cipher);

  return 0;
}

int verify_hmac (char * in, int in_len, unsigned char * hmac, int hmac_len, unsigned char * session_key) {
  TEE_Result ret = TEE_SUCCESS; // return code
  TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
  TEE_Attribute aes_attrs[1];
  //void * to_hamc = NULL;
  //void * re_hmac = NULL;
  TEE_ObjectInfo info;
  TEE_OperationHandle handle = (TEE_OperationHandle) NULL;

  //AES key
  aes_attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
  aes_attrs[0].content.ref.buffer = session_key;
  aes_attrs[0].content.ref.length = 16;

  // create a transient object
  ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, 128, &key);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // populate the object with your keys
  ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_attrs, 1);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // create your structures to de / decrypt
  //to_hmac = TEE_Malloc(in_len, 0);
  //re_hmac = TEE_Malloc(decrypted_len, 0);
  //if (!to_hmac || !re_hmac) {
  //  return TEE_ERROR_BAD_PARAMETERS;
  //}
  //TEE_MemMove(to_hmac, in, in_len);

  // setup the info structure about the key
  TEE_GetObjectInfo (key, &info);

  // Allocate the operation
  ret = TEE_AllocateOperation(&handle, TEE_ALG_HMAC_SHA1, TEE_MODE_MAC, 128);
  if (ret != TEE_SUCCESS) {
    return -1;
  }

  // set the key
  ret = TEE_SetOperationKey(handle, key);
  if (ret != TEE_SUCCESS) {
    TEE_FreeOperation(handle);
    return -1;
  }

  // hmac
  TEE_MACInit(handle, NULL, 0); //HMAC with SHA1 needs no IV

  /*ret = TEE_CipherUpdate(handle, to_decrypt, in_len, cipher, &decrypted_len);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    IMSG("ERROR: Cipher update error\n");
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }*/

  //IMSG("aqui1\n");

  ret = TEE_MACCompareFinal(handle, in, in_len, hmac, hmac_len);
  if (ret == TEE_ERROR_MAC_INVALID) {
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  //IMSG("aqui2\n");

  //memcpy (out, cipher, decrypted_len);

  // finish off
  //memcpy (out, cipher, decrypted_len);
  //*out_len = decrypted_len;
  //out[cipher_len] = '\0';

  // clean up after yourself
  TEE_FreeOperation(handle); //FIXME: Crashing for some mysterious reason
  TEE_FreeTransientObject(key);

  return 0;
}

int gen_hmac (char * in, int in_len, unsigned char * out, int * out_len, unsigned char * session_key) {
  TEE_Result ret = TEE_SUCCESS; // return code
  TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
  TEE_Attribute aes_attrs[1];
  //void * to_hamc = NULL;
  void * re_hmac = NULL;
  uint32_t re_hmac_len = 20;
  TEE_ObjectInfo info;
  TEE_OperationHandle handle = (TEE_OperationHandle) NULL;

  //AES key
  aes_attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
  aes_attrs[0].content.ref.buffer = session_key;
  aes_attrs[0].content.ref.length = 16;

  // create a transient object
  ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, 128, &key);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // populate the object with your keys
  ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&aes_attrs, 1);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // create your structures to de / decrypt
  //to_hmac = TEE_Malloc(in_len, 0);
  //re_hmac = TEE_Malloc(re_hmac_len, 0);
  re_hmac = malloc(sizeof(unsigned char) * re_hmac_len);
  if (!re_hmac) {
    return TEE_ERROR_BAD_PARAMETERS;
  }
  //TEE_MemMove(to_hmac, in, in_len);

  // setup the info structure about the key
  TEE_GetObjectInfo (key, &info);

  // Allocate the operation
  ret = TEE_AllocateOperation(&handle, TEE_ALG_HMAC_SHA1, TEE_MODE_MAC, 128);
  if (ret != TEE_SUCCESS) {
    return -1;
  }

  // set the key
  ret = TEE_SetOperationKey(handle, key);
  if (ret != TEE_SUCCESS) {
    TEE_FreeOperation(handle);
    return -1;
  }

  // hmac
  TEE_MACInit(handle, NULL, 0); //HMAC with SHA1 needs no IV

  /*ret = TEE_CipherUpdate(handle, to_decrypt, in_len, cipher, &decrypted_len);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    IMSG("ERROR: Cipher update error\n");
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }*/

  ret = TEE_MACComputeFinal(handle, in, in_len, re_hmac, &re_hmac_len);
  if (ret == TEE_ERROR_MAC_INVALID) {
    TEE_FreeOperation(handle);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  //memcpy (out, cipher, decrypted_len);

  // finish off
  memcpy (out, re_hmac, re_hmac_len);
  *out_len = re_hmac_len;
  //out[cipher_len] = '\0';

  // clean up after yourself
  TEE_FreeOperation(handle); //FIXME
  TEE_FreeTransientObject (key);
  free(re_hmac);

  return 0;
}

int update_session_key(unsigned char *session_key) {
  TEE_Result ret = TEE_SUCCESS; // return code
  //void * to_hamc = NULL;
  void * new_key = NULL;
  uint32_t key_size = 20;
  TEE_OperationHandle handle = (TEE_OperationHandle) NULL;

  // create your structures to de / decrypt
  //to_hmac = TEE_Malloc(in_len, 0);
  new_key = TEE_Malloc(key_size, 0);
  if (!new_key) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // Allocate the operation
  ret = TEE_AllocateOperation(&handle, TEE_ALG_SHA1, TEE_MODE_DIGEST, 0);
  if (ret != TEE_SUCCESS) {
    return -1;
  }

  // hmac
  ret = TEE_DigestDoFinal(handle, session_key, 16, new_key, &key_size);
  if (ret == TEE_ERROR_SHORT_BUFFER) {
    TEE_FreeOperation(handle);
    IMSG("ERROR: Buffer too short\n");
    return TEE_ERROR_BAD_PARAMETERS;
  }
  else
    IMSG("INV: Success renewing key!\n");

  //memcpy (out, cipher, decrypted_len);

  // finish off
  memcpy (session_key, new_key, 16);

  // clean up after yourself
  TEE_FreeOperation(handle);

  return 0;
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("DBStore has been called in the TZ\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Closing DBStore\n");
}

/**********************************************************************************************************************/
/**********************************************************************************************************************/
/**********************************************************************************************************************/
/**********************************************************************************************************************/
/**********************************************************************************************************************/
/**********************************************************************************************************************/

/*
 *
 * DBStore initialization protocol
 *
 */

static TEE_Result init(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	TEE_Result res;
	TEE_ObjectHandle file_handle;

  char *decrypted = (char*) calloc(64, sizeof(char));
  int decrypted_len;
  unsigned char *encrypted_rsa = TEE_Malloc(256, 0);
  int encrypted_rsa_len;
  unsigned char *encrypted_aes = TEE_Malloc(256, 0); //FIXME!!!! This may cause a buffer overflow! This one should be dynamically allocated
  int encrypted_aes_len;
  uint8_t * modulus; //params[1]
  unsigned char * encrypted_message; //params[2]
  unsigned char *session_key = malloc(sizeof(unsigned char) * 16);
  unsigned char *iv = malloc(sizeof(unsigned char) * 16);

  char *appid = calloc(8, sizeof(char));
  char *counter_c = calloc(16, sizeof(char));
  int i, parse_counter = 0, int_counter;

  int session_key_id, iv_id, counter_id, int_appid;

	DMSG("has been called");

  modulus = (uint8_t *) params[1].memref.buffer;
  encrypted_message = (unsigned char *) params[2].memref.buffer;

	if (param_types != exp_param_types)
		//return TEE_ERROR_BAD_PARAMETERS;

	IMSG("INIT: Got value %s from NW\n", (char *) params[0].memref.buffer);

  //Decrypting received request
  IMSG("INIT: Decrypting received request from application...\n");
  decrypt_using_private_key(encrypted_message, params[2].memref.size, decrypted, &decrypted_len);
  IMSG("INIT: Decrypted value is %s\n", decrypted);

  //Transforming challenge
  IMSG("INIT: Obtaining appid and counter...\n");
  //transform_challenge(decrypted); //to guarantee the mutual authentication
  for(i = 0; i < (int) strlen(decrypted); i++) {
    if(decrypted[i] != ':' && parse_counter == 0)
      appid[i] = decrypted[i];
    else if(decrypted[i] == ':')
      parse_counter = i + 1;
    else
      counter_c[i - parse_counter] = decrypted[i];
  }
  free(decrypted);
  IMSG("INIT: Appid and counter obatined - %s and %s\n", appid, counter_c);

  int_appid = 2 * atoi(appid);
  session_key_id = int_appid;
  iv_id = int_appid + 1;
  counter_id = int_appid + 2;

  IMSG("INIT: Updating counter to send back to NW...\n");
  int_counter = atoi(counter_c);
  snprintf(counter_c, 16, "%d", ++int_counter);
  IMSG("INIT: Counter updated - %s\n", counter_c);

  //Generating AES session key and IV for AES-CBC encryption
  IMSG("INIT: Generating session key and IV...\n");
  TEE_GenerateRandom(session_key, 16);
  TEE_GenerateRandom(iv, 16);
  IMSG("INIT: Session key and IV generated\n");
  IMSG("INIT: Session key: %s\n", session_key);
  IMSG("INIT: IV: %s\n", iv);

  IMSG("INIT: Encrypting transformed challenge with AES-CTR...\n");
  encrypt_aes_ctr(counter_c, strlen(counter_c) + 1, encrypted_aes, &encrypted_aes_len, session_key, iv);
  IMSG("INIT: Encrypted challenge using AES-CTR\n");

  //Encrypting (session key)+(IV) with PKey to return back to the application
  IMSG("INIT: Encrypting session key using RSA...\n");
  encrypt_using_public_key(modulus, (char *) session_key, 16, encrypted_rsa, &encrypted_rsa_len);
  IMSG("INIT: Session key encrypted using RSA\n");

  TEE_MemMove(params[0].memref.buffer, encrypted_aes, encrypted_aes_len);
  TEE_MemMove(params[1].memref.buffer, encrypted_rsa, 256);
  TEE_MemMove(params[2].memref.buffer, iv, 16);

	IMSG("INIT: Answering to CA\n");

  //Storing session key and IV using persistent storage. Only way to estabilish a session
  IMSG("INIT: Creating persistent objects for storing key and IV...\n");
  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &session_key_id, sizeof(int),
    TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, session_key, 16, &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("Error creating session key object...\n");

  TEE_CloseObject(file_handle);

  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &iv_id, sizeof(int),
    TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, iv, 16, &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("Error creating IV object...\n");

  TEE_CloseObject(file_handle);

  //Updates counter so that it matches the one it should receive in the first inv (helps with file reads)
  snprintf(counter_c, 8, "%d", ++int_counter);

  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &counter_id, sizeof(int),
    TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, counter_c, strlen(counter_c), &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("Error creating counter object...\n");

  TEE_CloseObject(file_handle);

	return TEE_SUCCESS;
}

/*
 *
 * DBStore invocation protocol
 *
 */

static TEE_Result inv(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE);

  TEE_Result res;
	TEE_ObjectHandle file_handle;
    
  char *reply = (char*) "NO";
  //unsigned char *hmac = TEE_Malloc(20, 0);
  unsigned char *hmac = malloc(sizeof(unsigned char) * 20);
  int reply_len, hmac_len;
  uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
  uint32_t read_count;
  //void *dst_req;

  /* LittleD stuff */
  char memseg[400];
  db_query_mm_t mm;
  /*****************/
 
  //db_op_base_t* root;
  //db_tuple_t    tuple;

  int session_key_id, iv_id, counter_id, int_appid = 2; //FIXME
  unsigned char *session_key = malloc(sizeof(unsigned char) * 16);
  unsigned char *iv = malloc(sizeof(unsigned char) * 16);
  char *counter_c = calloc(8, sizeof(char));
  char *re_counter = calloc(8, sizeof(char));

  int decrypt_counter_len, decrypt_req_len;
  char *decrypt_counter = malloc(sizeof(char) * 32);
  char *decrypt_req = malloc(sizeof(char) * 32);

  int int_counter;
  char *decrypted = calloc(8, sizeof(char));
  int sql_len = params[3].value.a;
  char *sql_stmt = malloc(sizeof(char) * (sql_len + 1));

  //unsigned char *re_hmac = params[2].memref.buffer;
  int counter_len = params[2].memref.size - 20;
  unsigned char *re_hmac = calloc(20, sizeof(unsigned char));
  char *appid = calloc(counter_len, sizeof(char));

  int crypt_reply_len, crypt_nonce_len;
  unsigned char *crypt_reply = malloc(sizeof(unsigned char) * 32);
  unsigned char *crypt_nonce = malloc(sizeof(unsigned char) * 32);

	DMSG("has been called");

  memcpy(re_hmac, (unsigned char*) params[2].memref.buffer + counter_len, 20);
  memcpy(appid, params[2].memref.buffer, counter_len);

  printf("appid %s\n", appid);

	if (param_types != exp_param_types)
		//return TEE_ERROR_BAD_PARAMETERS;

  int_appid = 2 * atoi(appid);
  session_key_id = int_appid;
  iv_id = int_appid + 1;
  counter_id = int_appid + 2;
  
  //Will grab both session key and IV from the persistent objects
	IMSG("INV: Opening persistent objects...\n");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &session_key_id, sizeof(int),
		flags, &file_handle);
	if (res != TEE_SUCCESS)
		IMSG("ERROR: Could not open persistent object (session key)...\n");
	TEE_ReadObjectData(file_handle, session_key, 16, &read_count);
	print_bytes("INV: Read session key - ", session_key, 16);
  TEE_CloseObject(file_handle);

  IMSG("INV: Updating session key...\n");
  update_session_key(session_key);
  print_bytes("INV: Updated session key - ", session_key, 16);
  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &session_key_id, sizeof(int),
    TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE, TEE_HANDLE_NULL, session_key, 16, &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("ERROR: Could not write to session key object...\n");
  IMSG("INV: New key Successfully written!\n");
  TEE_CloseObject(file_handle);

  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &iv_id, sizeof(int),
    flags, &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("ERROR: Could not open persistent object (IV)...\n");
  TEE_ReadObjectData(file_handle, iv, 16, &read_count);
  print_bytes("INV: Read IV - ", iv, 16);
  TEE_CloseObject(file_handle);
  /**************************************************************/
	
  //Decrypting both nonce and SQL request received from the remote client
  IMSG("INV: Decrypting the counter received from the remote client...\n");
  decrypt_aes_ctr(params[0].memref.buffer, params[0].memref.size, decrypt_counter, &decrypt_counter_len,
    (unsigned char*) session_key, (unsigned char*) iv);
  memcpy(re_counter, decrypt_counter, 8);
  //decrypted[7] = '\0';
  IMSG("INV: Decrypted counter is %s\n", decrypted);

  IMSG("INV: Obtaining counter saved in persistent object...\n");
  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &counter_id, sizeof(int),
    flags, &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("ERROR: Could not open persistent object (IV)...\n");
  TEE_ReadObjectData(file_handle, counter_c, strlen(re_counter), &read_count);
  IMSG("INV: Read counter - %s\n", counter_c);
  TEE_CloseObject(file_handle);

  if(strncmp(counter_c, re_counter, strlen(counter_c)) == 0) {
    IMSG("INV: Message is fresh\n");
    //free(re_counter);

    IMSG("INV: Decrypting the request received from the remote client...\n");
    decrypt_aes_ctr(params[1].memref.buffer, params[1].memref.size, decrypt_req, &decrypt_req_len, 
      (unsigned char*) session_key, (unsigned char*) iv);
    IMSG("SQL Len %d\n", sql_len);
    memcpy(sql_stmt, decrypt_req, sql_len);
    sql_stmt[sql_len] = '\0';
    IMSG("INV: Decrypted request is %s\n", sql_stmt);

    /**********************************************************************/

    IMSG("INV: Verifying HMAC...\n");
    if(verify_hmac(sql_stmt, sql_len, re_hmac, 20, (unsigned char*) session_key) == 0) {
      IMSG("INV: Successfully verified HMAC\n");
      IMSG("INV: Running query...\n");

      if(!(strncmp(sql_stmt, "SELECT", 6) == 0))
      {
        init_query_mm(&mm, memseg, 400);
        parse(sql_stmt, &mm);
        free(sql_stmt);
        reply = (char*) "OK";
      }
      else
      {
        where_parser(sql_stmt, sql_len);
        reply = (char*) "OK";
      }
    }
    else {
      IMSG("ERROR: Could not verify HMAC\n");
    }
  }
  else
    IMSG("ERROR: Message not fresh\n");

  /*IMSG("INV: Generating new nonce for reply...\n");
  transform_challenge(nonce_re);
  IMSG("INV: Nonce generated - %s\n", nonce_re);*/

  IMSG("INV: Updating counter to sent back to NW...\n");
  int_counter = atoi(counter_c);
  snprintf(counter_c, 8, "%d", ++int_counter);
  IMSG("INV: Counter updated - %s\n", counter_c);
  
  IMSG("INV: Encrypting nonce using AES-CTR...\n");
  encrypt_aes_ctr(counter_c, 8, crypt_nonce, &crypt_nonce_len, (unsigned char*) session_key, (unsigned char*) iv);
  TEE_MemMove(params[0].memref.buffer, crypt_nonce, crypt_nonce_len);
  //free(decrypted);
  free(crypt_nonce);
  print_bytes("INV: Nonce encrypted - ", crypt_nonce, crypt_nonce_len);

  IMSG("INV: Encrypting reply using AES-CTR...\n");
  encrypt_aes_ctr(reply, 2, crypt_reply, &crypt_reply_len, (unsigned char*) session_key, (unsigned char*) iv);
  TEE_MemMove(params[1].memref.buffer, crypt_reply, crypt_reply_len);
  free(crypt_reply);
  print_bytes("INV: Reply encrypted - ", crypt_reply, crypt_reply_len);

  IMSG("INV: Generating HMAC for reply...");
  reply_len = strlen(reply);
  gen_hmac((char*) reply, reply_len, hmac, &hmac_len, (unsigned char*) session_key);
  TEE_MemMove(params[2].memref.buffer, hmac, hmac_len);
  free(hmac);
  print_bytes("INV: HMAC generated - ", hmac, hmac_len);

  //Updates counter so that it matches the one it should receive on the next inv (helps with file reads)
  snprintf(counter_c, 8, "%d", ++int_counter);
  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &counter_id, sizeof(int),
    TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE, TEE_HANDLE_NULL, counter_c, 8, &file_handle);
  if (res != TEE_SUCCESS)
    IMSG("Error creating counter object...\n");
  
  //free(decrypt_nonce); CANT FREE THESE FOR SOME DIABOLIC REASON
  //free(decrypt_req);
  free(session_key);
  free(iv);

	return TEE_SUCCESS;
}


/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_DBSTORE_INIT:
		return init(param_types, params);
	case TA_DBSTORE_INV:
		return inv(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
