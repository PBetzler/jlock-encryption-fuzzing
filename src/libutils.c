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

void derive_key_from_password(const char *password, unsigned char *key)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, key, NULL);
    EVP_MD_CTX_free(mdctx);
}

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