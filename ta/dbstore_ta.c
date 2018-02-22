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

#include <dbstore_ta.h>
#include <crypto.h>

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */

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

void transform_challenge(char * challenge) {
  int i = 0;

  while(i < (int) strlen(challenge)) {
    challenge[i] += 2;
    i += 2;
  }
}

int create_digest(char * in, int in_len, unsigned char * out, int * out_len) {
   TEE_Result ret = TEE_SUCCESS; // return code
   TEE_OperationHandle handle = (TEE_OperationHandle) NULL;

   uint32_t message_len = in_len; // return encrypted hash length
   void *message = NULL; // return encrypted hash

   uint32_t digest_len = 20; // return decoded hash length
   void *digest = NULL; // return decoded hash

   message = TEE_Malloc(message_len, 0);
   digest = TEE_Malloc(digest_len, 0);

   TEE_MemMove(message, in, in_len);
   message_len = in_len;

   // Allocate the operation
   ret = TEE_AllocateOperation(&handle, TEE_ALG_SHA1, TEE_MODE_DIGEST, 0);
   if (ret != TEE_SUCCESS) {
      IMSG("ERROR: Digest allocate\n");
      return -1;
   }

   // digest
   //TEE_DigestUpdate(handle, in, in_len);

   ret = TEE_DigestDoFinal(handle, message, in_len, digest, &digest_len);
   if (ret == TEE_ERROR_SHORT_BUFFER) {
      IMSG("ERROR: Digest final short buffer\n");
      return -1;
   }

   // clean up after yourself
   TEE_FreeOperation(handle);
   memcpy(out, digest, digest_len);

   *out_len = digest_len;

   // fin
   return 0;
}

int create_signature(char * in, int in_len, char * out, int * out_len) {

  TEE_Result ret = TEE_SUCCESS; // return code
  TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
  TEE_Attribute rsa_attrs[3];
  TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
  //unsigned long int sizeofmod = 256; //hack because casting void * to uint8_t * leads to a sizeof of -1
  unsigned char digest[20];
  int digest_len;
  void *signature = NULL;
  uint32_t sign_len = 256;
  //char clean_sig[256];
  //int clean_sig_len;

  create_digest(in, in_len, digest, &digest_len);

  IMSG("digest %s\n", digest);
  
  // modulus
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
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // populate the object with your keys
  ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&rsa_attrs, 3);
  if (ret != TEE_SUCCESS) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // Allocate the operation
  ret = TEE_AllocateOperation(&handle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN, 2048);
  if (ret != TEE_SUCCESS) {
    return -1;
  }

  // set the key
  ret = TEE_SetOperationKey(handle, key);
  if (ret != TEE_SUCCESS) {
    TEE_FreeOperation(handle);
    return -1;
  }

  signature = TEE_Malloc(sign_len, 0);

  // verify signature
  ret = TEE_AsymmetricSignDigest(handle, (TEE_Attribute *)NULL, 0, digest, digest_len, signature, &sign_len);
  if(ret == TEE_SUCCESS)
    IMSG("INIT: Success creating signature!\n");
  else if(ret == TEE_ERROR_SHORT_BUFFER)
    IMSG("INIT: Error creating signature!\n");

  memcpy(out, signature, sign_len);
  *out_len = sign_len;

  return 0;
}

int decrypt_using_private_key (char * in, int in_len, char * out, int * out_len) {

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

// encrypt
int encrypt_using_public_key (uint8_t * modulus, const char * in, int in_len, char * out, int * out_len) {

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
	//TEE_ObjectHandle key_handle;

  char decrypted[256] = {0};
  int decrypted_len;
  char encrypted[256] = {0};
  int encrypted_len;
  //char signature[256] = {0};
  //int sign_len;
  uint8_t * modulus; //params[1]
  char * encrypted_message; //params[2]

  //const char to_encrypt[256];
  //const char *certificate;
  const char *content = "teste";
  char *to_sign = (char *) "session_key";
  int object_id = 0;
  //void *dst_certificate;

	DMSG("has been called");

  modulus = (uint8_t *) params[1].memref.buffer;
  encrypted_message = (char *) params[2].memref.buffer;

	if (param_types != exp_param_types)
		//return TEE_ERROR_BAD_PARAMETERS;

	IMSG("INIT: Got value %s from NW\n", (char *) params[0].memref.buffer);

	IMSG("INIT: Creating new persistent object...\n");

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &object_id, sizeof(int),
		TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, content, strlen(content)+1, &file_handle);
	if (res != TEE_SUCCESS)
		//errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		IMSG("Error creating object...\n");

	TEE_CloseObject(file_handle);

  decrypt_using_private_key(encrypted_message, params[2].memref.size, decrypted, &decrypted_len);
  //IMSG("crypto: %s\n", (char *) params[2].memref.buffer);
  IMSG("INIT: Decrypted value is %s\n", decrypted);

  transform_challenge(decrypted); //to guarantee the mutual authentication

  //TEE_MemMove(to_encrypt, (char *) "teste", 5);
  encrypt_using_public_key(modulus, decrypted, decrypted_len, encrypted, &encrypted_len);
	
  TEE_MemMove(params[0].memref.buffer, to_sign, 11);
  TEE_MemMove(params[1].memref.buffer, encrypted, 256);

  /*certificate = "new_certificate";
  certificate_len = strlen(certificate);
  dst_certificate = TEE_Malloc(certificate_len, TEE_MALLOC_FILL_ZERO);
  TEE_MemMove(dst_certificate, certificate, certificate_len);
  TEE_MemMove(params[1].memref.buffer, dst_certificate, certificate_len);*/

	IMSG("INIT: Answering to CA\n");

	return TEE_SUCCESS;
}

static TEE_Result inv(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE);

	//TEE_Result res;
	TEE_ObjectHandle file_handle;
    
    const char *nonce;
    const char *req;
    const char *hmac;
    char read_bytes[255];
    int nonce_len, req_len, hmac_len;
    int object_id = 0;
    size_t read_size = 255;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
    uint32_t read_count;
    void *dst_nonce;
    void *dst_req;
    void *dst_hmac;

	DMSG("has been called");

	if (param_types != exp_param_types)
		//return TEE_ERROR_BAD_PARAMETERS;

	IMSG("INV: Got values %s, %s and %s from NW\n", (char *) params[0].memref.buffer,
		(char *) params[1].memref.buffer, (char *) params[2].memref.buffer);

	IMSG("INV: Opening persistent object...\n");

	TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, &object_id, sizeof(int),
		flags, &file_handle);
	//if (res == TEE_HANDLE_NULL)
		//errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	//	IMSG("Bad handle...\n");

	TEE_ReadObjectData(file_handle, read_bytes, read_size, &read_count);

	IMSG("INV: Read \"%s\" from persistent object\n", read_bytes);

	TEE_CloseObject(file_handle);
	
	nonce = "new_nonce";
	nonce_len = strlen(nonce);
    dst_nonce = TEE_Malloc(nonce_len, TEE_MALLOC_FILL_ZERO);
    TEE_MemMove(dst_nonce, nonce, nonce_len);
    TEE_MemMove(params[0].memref.buffer, dst_nonce, nonce_len);

    req = "new_req";
    req_len = strlen(req);
    dst_req = TEE_Malloc(req_len, TEE_MALLOC_FILL_ZERO);
    TEE_MemMove(dst_req, req, req_len);
    TEE_MemMove(params[1].memref.buffer, dst_req, req_len);

    hmac = "new_hmac";
    hmac_len = strlen(hmac);
    dst_hmac = TEE_Malloc(hmac_len, TEE_MALLOC_FILL_ZERO);
    TEE_MemMove(dst_hmac, hmac, hmac_len);
    TEE_MemMove(params[2].memref.buffer, dst_hmac, hmac_len);

	IMSG("INV: Answering with values %s, %s and %s\n", (char *) params[0].memref.buffer,
		(char *) params[1].memref.buffer, (char *) params[2].memref.buffer);

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
