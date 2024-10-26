/*!
    @file   libchecksum.c
    @brief  Provides checksum computation and printing functions for MD5, SHA1, and SHA256
    @t.odo  -
    ---------------------------------------------------------------------------
    
	MIT License
	Copyright (c) 2024 Io. D (Devcoons)
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/
/******************************************************************************
* Includes
******************************************************************************/

#include "libchecksum.h"
#include <openssl/evp.h>
#include <stdio.h>

/******************************************************************************
* Definition | Public Functions
******************************************************************************/

/*!
    @brief Prints a checksum in hexadecimal format with a fixed-width label
    @param[in] label - The label for the checksum (e.g., "MD5")
    @param[in] digest - The checksum byte array
    @param[in] length - The length of the checksum
*/
void print_checksum(const char *label, unsigned char *digest, unsigned int length) 
{
    printf("%-10s: ", label);
    for (unsigned int i = 0; i < length; i++) 
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/*!
    @brief Computes and prints MD5, SHA1, and SHA256 checksums of a given file
    @param[in] file_path - Path to the file for which checksums are to be computed
    @return EXIT_SUCCESS (0) on success, EXIT_FAILURE (1) on failure
*/
int compute_and_print_checksums(const char *file_path) 
{
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) 
    {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha1_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX *sha256_ctx = EVP_MD_CTX_new();
    if (!md5_ctx || !sha1_ctx || !sha256_ctx) 
    {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        fclose(file);
        return EXIT_FAILURE;
    }

    if (EVP_DigestInit_ex(md5_ctx, EVP_md5(), NULL) != 1 ||
        EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL) != 1 ||
        EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL) != 1) 
    {
        fprintf(stderr, "Failed to initialize digest contexts\n");
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        fclose(file);
        return EXIT_FAILURE;
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) 
    {
        if (EVP_DigestUpdate(md5_ctx, buffer, bytes_read) != 1 ||
            EVP_DigestUpdate(sha1_ctx, buffer, bytes_read) != 1 ||
            EVP_DigestUpdate(sha256_ctx, buffer, bytes_read) != 1) 
        {
            fprintf(stderr, "Failed to update digest\n");
            EVP_MD_CTX_free(md5_ctx);
            EVP_MD_CTX_free(sha1_ctx);
            EVP_MD_CTX_free(sha256_ctx);
            fclose(file);
            return EXIT_FAILURE;
        }
    }

    if (ferror(file)) 
    {
        perror("Error reading file");
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        fclose(file);
        return EXIT_FAILURE;
    }

    unsigned char md5_digest[EVP_MAX_MD_SIZE];
    unsigned int md5_length;
    if (EVP_DigestFinal_ex(md5_ctx, md5_digest, &md5_length) != 1) 
    {
        fprintf(stderr, "Failed to finalize MD5 checksum\n");
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        fclose(file);
        return EXIT_FAILURE;
    }

    unsigned char sha1_digest[EVP_MAX_MD_SIZE];
    unsigned int sha1_length;
    if (EVP_DigestFinal_ex(sha1_ctx, sha1_digest, &sha1_length) != 1) 
    {
        fprintf(stderr, "Failed to finalize SHA1 checksum\n");
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        fclose(file);
        return EXIT_FAILURE;
    }

    unsigned char sha256_digest[EVP_MAX_MD_SIZE];
    unsigned int sha256_length;
    if (EVP_DigestFinal_ex(sha256_ctx, sha256_digest, &sha256_length) != 1) 
    {
        fprintf(stderr, "Failed to finalize SHA256 checksum\n");
        EVP_MD_CTX_free(md5_ctx);
        EVP_MD_CTX_free(sha1_ctx);
        EVP_MD_CTX_free(sha256_ctx);
        fclose(file);
        return EXIT_FAILURE;
    }

    fclose(file);
    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha1_ctx);
    EVP_MD_CTX_free(sha256_ctx);

    print_checksum("MD5", md5_digest, md5_length);
    print_checksum("SHA1", sha1_digest, sha1_length);
    print_checksum("SHA256", sha256_digest, sha256_length);

    return EXIT_SUCCESS;
}

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/