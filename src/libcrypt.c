#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "config.h"
#include "libcrypt.h"
#include "libutils.h"

unsigned char* AesEncrypt(const char* password, unsigned char* input, int input_len, int* output_len, unsigned char* iv)
{
    unsigned char key[AES_KEY_SIZE];
    derive_key_from_password(password, key);

    int max_output_len = input_len + AES_BLOCK_SIZE;
    unsigned char* output = malloc(max_output_len);
    if (!output)
    {
        fprintf(stderr, "Error: Memory allocation failed during encryption.\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create cipher context.\n");
        free(output);
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error: Encryption initialization failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, output, &len, input, input_len) != 1)
    {
        fprintf(stderr, "Error: Encryption failed during update.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    *output_len = len;

    if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1)
    {
        fprintf(stderr, "Error: Encryption failed during finalization.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Clean up sensitive data
    OPENSSL_cleanse(key, AES_KEY_SIZE);

    return output;
}

unsigned char* AesDecrypt(const char* password, unsigned char* input, int input_len, int* output_len, unsigned char* iv)
{
    unsigned char key[AES_KEY_SIZE];
    derive_key_from_password(password, key);

    unsigned char* output = malloc(input_len);
    if (!output)
    {
        fprintf(stderr, "Error: Memory allocation failed during decryption.\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create cipher context.\n");
        free(output);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error: Decryption initialization failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, output, &len, input, input_len) != 1)
    {
        fprintf(stderr, "Error: Decryption failed during update.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    *output_len = len;

    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1)
    {
        fprintf(stderr, "Error: Decryption failed during finalization. Possibly incorrect password or corrupted data.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    *output_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Clean up sensitive data
    OPENSSL_cleanse(key, AES_KEY_SIZE);

    return output;
}

void encrypt_file(const char *password, const char *input_file, const char *output_file)
{
    // Open input and output files
    FILE *in_fp = fopen(input_file, "rb");
    FILE *out_fp = fopen(output_file, "wb");

    if (in_fp == NULL || out_fp == NULL)
    {
        fprintf(stderr, "Error: Opening input or output file.\n");
        if (in_fp) fclose(in_fp);
        if (out_fp) fclose(out_fp);
        return;
    }

    // Compute SHA-256 hash of the input file
    unsigned char file_hash[SHA256_DIGEST_LENGTH];
    compute_sha256_hash(input_file, file_hash);

    // Get the filename from the input_file path
    const char *filename = strrchr(input_file, '/');
    if (filename == NULL)
    {
        filename = input_file;
    }
    else
    {
        filename++; // Skip past '/'
    }

    // Generate random IV
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE))
    {
        fprintf(stderr, "Error: Generating random IV.\n");
        fclose(in_fp);
        fclose(out_fp);
        return;
    }

    // Write plaintext header: magic number, version, IV
    fwrite(MAGIC_NUMBER, 1, MAGIC_NUMBER_LEN, out_fp); // Magic number
    fwrite(VERSION_NEW, 1, VERSION_LENGTH, out_fp);    // Version number ("0004")
    fwrite(iv, 1, IV_SIZE, out_fp);                    // Random IV

    // Create the header string
    char header_template[] = "[JLK][v]%s[/v][f]%s[/f][h]%s[/h][/JLK]";
    char file_hash_hex[SHA256_DIGEST_LENGTH * 2 + 1] = {0};

    // Convert file_hash to uppercase hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(&file_hash_hex[i * 2], "%02X", file_hash[i]);
    }

    // Create the header string with version VERSION_NEW
    char header_str[HEADER_SIZE + 1]; // 252 characters + null terminator
    snprintf(header_str, sizeof(header_str), header_template, VERSION_NEW, filename, file_hash_hex);

    // Pad the header to 252 characters with '0's
    size_t header_len = strlen(header_str);
    if (header_len < HEADER_SIZE)
    {
        memset(header_str + header_len, '0', HEADER_SIZE - header_len);
        header_str[HEADER_SIZE] = '\0'; // Null terminator
    }

    // Convert header_str to UTF-16LE bytes
    unsigned char header_utf16le[HEADER_BYTES];
    for (int i = 0; i < HEADER_SIZE; i++)
    {
        header_utf16le[i * 2] = header_str[i];       // Low byte
        header_utf16le[i * 2 + 1] = 0x00;            // High byte
    }

    // Encrypt the header using the random IV
    int encrypted_header_len = 0;
    unsigned char *encrypted_header = AesEncrypt(password, header_utf16le, HEADER_BYTES, &encrypted_header_len, iv);
    if (encrypted_header == NULL || encrypted_header_len != ENCRYPTED_HEADER_SIZE)
    {
        // Handle error
        fprintf(stderr, "Error: Encrypting header.\n");
        fclose(in_fp);
        fclose(out_fp);
        return;
    }

    // Write the encrypted header to the output file
    fwrite(encrypted_header, 1, encrypted_header_len, out_fp);
    free(encrypted_header);

    // Encrypt and write file content in chunks using the random IV
    unsigned char inbuf[5242880]; // 5 MB chunks
    size_t inlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in_fp)) > 0)
    {
        int encrypted_data_len = 0;
        unsigned char *encrypted_data = AesEncrypt(password, inbuf, inlen, &encrypted_data_len, iv);
        if (encrypted_data == NULL)
        {
            fprintf(stderr, "Error: Encrypting file data.\n");
            fclose(in_fp);
            fclose(out_fp);
            return;
        }
        fwrite(encrypted_data, 1, encrypted_data_len, out_fp);
        free(encrypted_data);
    }

    // Close files
    fclose(in_fp);
    fclose(out_fp);
}

void decrypt_file(const char *password, const char *input_file, char *output_file)
{
    // Open input file
    FILE *in_fp = fopen(input_file, "rb");
    if (in_fp == NULL)
    {
        fprintf(stderr, "Error: Opening input file.\n");
        return;
    }

    // Read the magic number
    char magic_number[MAGIC_NUMBER_LEN + 1] = {0};
    size_t read_bytes = fread(magic_number, 1, MAGIC_NUMBER_LEN, in_fp);
    if (read_bytes != MAGIC_NUMBER_LEN)
    {
        fprintf(stderr, "Error: Reading magic number.\n");
        fclose(in_fp);
        return;
    }

    unsigned char iv[IV_SIZE] = {
            0xd7, 0x90, 0x95, 0xd7, 0xf6, 0x4e, 0x9d, 0x52,
            0x37, 0xad, 0x8e, 0x30, 0x93, 0x82, 0x0d, 0x06
        };

    if (strncmp(magic_number, MAGIC_NUMBER, MAGIC_NUMBER_LEN) == 0)
    {
        // Version 0004 with random IV
        char version[VERSION_LENGTH + 1] = {0};
        fread(version, 1, VERSION_LENGTH, in_fp);
        fread(iv, 1, IV_SIZE, in_fp);
    }
    else
    {
        fseek(in_fp, 0, SEEK_SET);
    }


    unsigned char encrypted_header[ENCRYPTED_HEADER_SIZE];
    size_t header_size = fread(encrypted_header, 1, ENCRYPTED_HEADER_SIZE, in_fp);
    if (header_size != ENCRYPTED_HEADER_SIZE)
    {
        fprintf(stderr, "Error: Reading encrypted header.\n");
        fclose(in_fp);
        return;
    }


    int decrypted_header_len = 0;
    unsigned char *decrypted_header = AesDecrypt(password, encrypted_header, ENCRYPTED_HEADER_SIZE, &decrypted_header_len, iv);
    if (decrypted_header == NULL || decrypted_header_len != HEADER_BYTES)
    {
        fprintf(stderr, "Error: Decrypting header.\n");
        fclose(in_fp);
        return;
    }


    char header_str[HEADER_SIZE + 1];
    for (int i = 0; i < HEADER_SIZE; i++)
    {
        header_str[i] = decrypted_header[i * 2]; 
    }
    header_str[HEADER_SIZE] = '\0';
    free(decrypted_header);

    // Remove '0's padding
    for (int i = HEADER_SIZE - 1; i >= 0; i--)
    {
        if (header_str[i] == '0')
            header_str[i] = '\0';
        else
            break;
    }


    char *start_filename = strstr(header_str, "[f]");
    char *end_filename = strstr(header_str, "[/f]");
    if (start_filename && end_filename)
    {
        start_filename += 3; 
        *end_filename = '\0';

        char extracted_filename[256];
        strncpy(extracted_filename, start_filename, sizeof(extracted_filename));
        extracted_filename[sizeof(extracted_filename) - 1] = '\0';

        char *header_extension = strrchr(extracted_filename, '.');
 
        if (output_file == NULL || strlen(output_file) == 0)
        {
            output_file = extracted_filename;
        }
        else
        {
            char *user_extension = strrchr(output_file, '.');
            if (user_extension)
            {
                // Warn if extensions differ
                if (header_extension && strcmp(user_extension, header_extension) != 0)
                {
                    fprintf(stderr, "Warning: File extension in the header (%s) differs from the user-provided extension (%s).\n", header_extension, user_extension);
                }
            }
            else if (header_extension)
            {
                strcat(output_file, header_extension);
            }
        }
    }
    else
    {
        fprintf(stderr, "Error: Parsing filename from header.\n");
        fclose(in_fp);
        return;
    }

    FILE *out_fp = fopen(output_file, "wb");
    if (out_fp == NULL)
    {
        fprintf(stderr, "Error: Opening output file.\n");
        fclose(in_fp);
        return;
    }

    unsigned char inbuf[5242896]; // 5 MB + padding
    size_t inlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in_fp)) > 0)
    {
        int decrypted_data_len = 0;
        unsigned char *decrypted_data = AesDecrypt(password, inbuf, inlen, &decrypted_data_len, iv);
        if (decrypted_data == NULL)
        {
            fprintf(stderr, "Error: Decrypting file data.\n");
            fclose(in_fp);
            fclose(out_fp);
            return;
        }
        fwrite(decrypted_data, 1, decrypted_data_len, out_fp);
        free(decrypted_data);
    }

    fclose(in_fp);
    fclose(out_fp);
}