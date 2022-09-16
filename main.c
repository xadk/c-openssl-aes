/**
 * @file aes.c
 * @author xadk (adk@krauv.com)
 * @brief just an example on how to use OpenSSL encryption APIs.
 * @date 2022-09-16
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

int OpenSSL_aes_256_cbc_cts_crypt(
    unsigned char key[32],
    unsigned char iv[16],
    const unsigned char *msg,
    size_t msg_len,
    unsigned char *out,
    int do_crypt)
{
  /*
   * This assumes that key size is 32 bytes and the iv is 16 bytes.
   * For ciphertext stealing mode the length of the ciphertext "out" will be
   * the same size as the plaintext size "msg_len".
   * The "msg_len" can be any size >= 16.
   */
  int ret = 0, outlen, len;
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_CIPHER *cipher = NULL;
  OSSL_PARAM params[2];

  ctx = EVP_CIPHER_CTX_new();
  cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", NULL);
  if (ctx == NULL || cipher == NULL)
    goto err;

  /*
   * The default is "CS1" so this is not really needed,
   * but would be needed to set either "CS2" or "CS3".
   */
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                               "CS1", 0);
  params[1] = OSSL_PARAM_construct_end();

  if (!EVP_CipherInit_ex2(ctx, cipher, key, iv, do_crypt, params))
    goto err;

  /* NOTE: CTS mode does not support multiple calls to EVP_CipherUpdate() */
  if (!EVP_CipherUpdate(ctx, out, &outlen, msg, msg_len))
    goto err;
  if (!EVP_CipherFinal_ex(ctx, out + outlen, &len))
    goto err;
  ret = 1;

err:
  EVP_CIPHER_free(cipher);
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int OpenSSL_aes_128_cbc_file_crypt(
    FILE *in,
    FILE *out,
    unsigned char key[16],
    unsigned char iv[16],
    int do_encrypt)
{
  /* Allow enough space in output buffer for additional block */
  unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
  int inlen, outlen;
  EVP_CIPHER_CTX *ctx;

  /* Don't set key or IV right away; we want to check lengths */
  ctx = EVP_CIPHER_CTX_new();
  EVP_CipherInit_ex2(ctx, EVP_aes_128_cbc(), NULL, NULL,
                     do_encrypt, NULL);
  OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);
  OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(ctx) == 16);

  /* Now we can set key and IV */
  EVP_CipherInit_ex2(ctx, NULL, key, iv, do_encrypt, NULL);

  for (;;)
  {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0)
      break;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
    {
      /* Error */
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
    fwrite(outbuf, 1, outlen, out);
  }

  if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
  {
    /* Error */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  fwrite(outbuf, 1, outlen, out);

  EVP_CIPHER_CTX_free(ctx);
  return 1;
}

int test_file_encryption()
{
  FILE *in, *fcipher, *out;
  in = fopen("in.jpg", "rb");
  fcipher = fopen("enc.txt", "wb+");
  out = fopen("out.jpg", "wb");

  /*
   * for aes_128_cbc: key and iv must be atleast 16 bytes
   * P.S. Bogus key and IV: I'd normally set these from
   * another source.
   */
  unsigned char key[] = "0123456789abcdeF";
  unsigned char iv[] = "1234567887654321";

  int ret;

  /**
   *  Encryption
   */
  ret = OpenSSL_aes_128_cbc_file_crypt(in, fcipher, key, iv, 1);

  /**
   * Resets seek for reading
   */
  fseek(fcipher, 0, SEEK_SET);

  /**
   * Decryption
   */
  ret = OpenSSL_aes_128_cbc_file_crypt(fcipher, out, key, iv, 0);

  fclose(in);
  fclose(fcipher);
  fclose(out);
  return ret;
}

int test_encryption()
{
  /*
   * for aes_256_cbc: key must be atleast 32 bytes
   * while iv must be 16 bytes
   */
  unsigned char key[] = "0123456789abcdeF0123456789abcdeF";
  unsigned char iv[] = "1234567887654321";

  /**
   * for aes_256_cbc: msg must be atleast 16 bytes or more
   */
  unsigned char msg[] = "Hello from OpenSSL!";
  size_t msg_len = strlen(msg);

  unsigned char cipher_text[msg_len + 1];
  unsigned char decrypted_text[msg_len + 1];

  int ret;

  /**
   * @brief Encryption
   */

  ret = OpenSSL_aes_256_cbc_cts_crypt(key, iv, msg, msg_len, cipher_text, 1);
  printf("ret: %d; cipher_text   :  ", ret);
  for (int i = 0; i < msg_len; ++i)
    printf("%02X ", cipher_text[i]);
  printf("\n");

  /**
   * @brief Decryption
   */

  ret = OpenSSL_aes_256_cbc_cts_crypt(key, iv, cipher_text, msg_len, decrypted_text, 0);
  printf("ret: %d; decrypted_text:  %s\n", ret, decrypted_text);

  return ret;
}

int main(void)
{
  /**
   * @brief make sure you run gcc with `-lssl -lcrypto` flags
   * OpenSSL implementations of AES 128 bit file encryption
   * and AES 256 bit string encryption
   */

  // string encryption
  test_encryption();
  // file encryption
  // test_file_encryption();

  return 0;
}