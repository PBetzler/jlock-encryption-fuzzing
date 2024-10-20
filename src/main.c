#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "libcrypt.h"
#include "libutils.h"

void print_usage(FILE *stream);

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(stdout);
            return 0;
        }
    }

    if (argc < 4)
    {
        fprintf(stderr, "Error: Missing required arguments.\n");
        print_usage(stderr);
        return 1;
    }

    char *mode = NULL;
    char password[256] = {0};
    char *input_file = NULL;
    char *output_file = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--encrypt") == 0)
        {
            mode = "encrypt";
        }
        else if (strcmp(argv[i], "--decrypt") == 0)
        {
            mode = "decrypt";
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            if (i + 1 < argc)
            {
                input_file = argv[i + 1];
                i++;
            }
            else
            {
                fprintf(stderr, "Error: Missing input file after -i\n");
                print_usage(stderr);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            if (i + 1 < argc)
            {
                output_file = argv[i + 1];
                i++;
            }
            else
            {
                fprintf(stderr, "Error: Missing output file after -o\n");
                print_usage(stderr);
                return 1;
            }
        }
    }

    if (mode == NULL || input_file == NULL)
    {
        fprintf(stderr, "Error: Missing required arguments.\n");
        print_usage(stderr);
        return 1;
    }

    get_password(password, sizeof(password));

    if (strcmp(mode, "encrypt") == 0)
    {
        if (output_file == NULL)
        {
            size_t output_file_len = strlen(input_file) + 5;
            output_file = malloc(output_file_len);
            if (!output_file)
            {
                fprintf(stderr, "Error: Memory allocation failed for output filename.\n");
                return 1;
            }
            strcpy(output_file, input_file);
            strcat(output_file, ".jlk");
        }

        encrypt_file(password, input_file, output_file);

        if (output_file != NULL)
        {
            free(output_file);
        }
    }
    else if (strcmp(mode, "decrypt") == 0)
    {
        decrypt_file(password, input_file, output_file);

        if (output_file != NULL)
        {
            free(output_file);
        }
    }
    else
    {
        fprintf(stderr, "Error: Invalid mode.\n");
        print_usage(stderr);
        return 1;
    }

    return 0;
}

void print_usage(FILE *stream)
{
    fprintf(stream, "\nJLock - File encryption and decryption\n");
    fprintf(stream, "Developed by: devcoons\n\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  jlock --encrypt|--decrypt -i <input_file> [-o <output_file>]\n\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  --encrypt          Encrypt the input file.\n");
    fprintf(stream, "  --decrypt          Decrypt the input file.\n");
    fprintf(stream, "  -i <input_file>    Input file to encrypt/decrypt.\n");
    fprintf(stream, "  -o <output_file>   Output file name (optional).\n");
    fprintf(stream, "  -h, --help         Show this help message and exit.\n");
    fprintf(stream, "\nNote: You will be prompted to enter the password.\n");
}
