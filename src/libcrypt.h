#ifndef LIBCRYPT_H
#define LIBCRYPT_H

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define IV_SIZE 16
#define HEADER_SIZE 252   
#define HEADER_BYTES 504   
#define ENCRYPTED_HEADER_SIZE 512

void encrypt_file(const char *password, const char *input_file, const char *output_file);
void decrypt_file(const char *password, const char *input_file, char *output_file);

unsigned char* AesEncrypt(const char* password, unsigned char* input, int input_len, int* output_len, unsigned char* iv);
unsigned char* AesDecrypt(const char* password, unsigned char* input, int input_len, int* output_len, unsigned char* iv);

#endif // LIBCRYPT_H