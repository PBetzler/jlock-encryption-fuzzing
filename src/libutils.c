/*!
    @file   libutils.c
    @brief  Utility functions for file handling, password input, and hashing
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

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include "config.h"
#include "libutils.h"

/******************************************************************************
* Definition | Public Functions
******************************************************************************/

/*!
    @brief Prompts the user to enter a password, hiding input characters
    @param[out] password - Buffer to store the entered password
    @param[in] max_length - Maximum length of the password buffer
*/
void get_password(char *password, size_t max_length)
{
#ifdef _WIN32
    printf("Enter password: ");
    fflush(stdout);

    size_t index = 0;
    int ch;

    while ((ch = _getch()) != '\r' && ch != '\n' && index < max_length - 1)
    {
        if (ch == '\b' && index > 0) 
        {
            index--;
            printf("\b \b");
        }
        else
        {
            password[index++] = ch;
            printf("*");
        }
    }
    password[index] = '\0';
    printf("\n");
#else
    struct termios oldt, newt;

    printf("Enter password: ");
    fflush(stdout);

    tcgetattr(fileno(stdin), &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &newt);
    fgets(password, max_length, stdin);
    tcsetattr(fileno(stdin), TCSANOW, &oldt);
    printf("\n");

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
    {
        password[len - 1] = '\0';
    }
#endif
}

/*!
    @brief Derives a SHA-256 hash key from the given password
    @param[in] password - Input password string
    @param[out] key - Buffer to store the derived key
*/
void derive_key_from_password(const char *password, unsigned char *key)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, key, NULL);
    EVP_MD_CTX_free(mdctx);
}

/*!
    @brief Computes the SHA-256 hash of a given file
    @param[in] filename - Name of the file to hash
    @param[out] output_hash - Buffer to store the computed hash
*/
void compute_sha256_hash(const char *filename, unsigned char *output_hash)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "Error: Opening file to compute SHA256 hash.\n");
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);

    unsigned char buffer[1024];
    int bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    EVP_DigestFinal_ex(mdctx, output_hash, NULL);

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

/*!
    @brief Checks if a file exists by attempting to open it
    @param[in] filename - Name of the file to check
    @return 0 if file exists, -1 otherwise
*/
int file_exists(const char *filename) 
{
    FILE *file = fopen(filename, "r");
    if (file != NULL) 
    {
        fclose(file);
        return 0;
    }
    return -1;
}

/*!
    @brief Checks if a file can be opened for writing (appending)
    @param[in] filename - Name of the file to check
    @return 0 if file can be written to, -1 otherwise
*/
int can_write_file_fopen(const char *filename) 
{
    FILE *file = fopen(filename, "a");
    if (file != NULL) 
    {
        fclose(file);
        return 0;
    }
    return -1;
}

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/