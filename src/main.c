/*!
    @file   main.c
    @brief  JLock - A tool for file encryption, decryption, and checksum operations
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "libcrypt.h"
#include "libchecksum.h"
#include "libutils.h"

/******************************************************************************
* Enumerations, Structures & Variables
******************************************************************************/

static const struct 
{
    const char *option;
    const char *mode;
} option_mode_map[] = 
{
    {"--encrypt",   "encrypt"},
    {"-e",          "encrypt"},
    {"--decrypt",   "decrypt"},
    {"-d",          "decrypt"},
    {"--checksum",  "checksum"},
    {"-c",          "checksum"},
    {NULL,          NULL}
};

/******************************************************************************
* Declaration | Static Functions
******************************************************************************/

char* get_mode(const char *arg);
void print_usage(FILE *stream);

/******************************************************************************
* Definition | Static Functions
******************************************************************************/

/*!
    @brief Retrieves the mode based on the provided argument.
    @param[in] arg - Command-line argument specifying the mode
    @return Mode string if found, NULL otherwise
*/
char* get_mode(const char *arg) 
{
    for (int i = 0; option_mode_map[i].option != NULL; i++)
    {
        if (strcmp(arg, option_mode_map[i].option) == 0)
        {
            return (char*)option_mode_map[i].mode;
        }
    }
    return NULL;
}

/*!
    @brief Displays usage information for JLock
    @param[in] stream - Output stream to print the usage information
*/
void print_usage(FILE *stream) 
{
    fprintf(stream, "\nJLock - File encryption and decryption\n");
    fprintf(stream, "Developed by: devcoons\n\n");
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  jlock --encrypt|--decrypt|--checksum <input_file> [key_file]\n\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  --encrypt(-e)  <original file>       Encrypt the input file.\n");
    fprintf(stream, "  --decrypt(-d)  <encrypted file>      Decrypt the input file.\n");
    fprintf(stream, "  --checksum(-c) <input file>          Input file name.\n");
    fprintf(stream, "  -h, --help                           Show this help message and exit.\n");
    fprintf(stream, "\nNote: You will be prompted to enter the password.\n");
}

/******************************************************************************
* Definition | Public Functions
******************************************************************************/

/*!
    @brief Main entry point for JLock
    @param[in] argc - Number of command-line arguments
    @param[in] argv - Array of command-line arguments
    @return 0 on success, non-zero on error
*/
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

    if (argc < 2)
    {
        fprintf(stderr, "Error: Missing required arguments.\n");
        print_usage(stderr);
        return 1;
    }
    
    char *mode = get_mode(argv[1]);
    
    if (mode == NULL)
    {
        fprintf(stderr, "Error: Missing jlock 'action'\n");
        print_usage(stderr);
        return 1;
    }
    
    if (strcmp(mode, "encrypt") == 0)
    {
        char password[512] = {0};
        char *input_file = argv[2];

        if (file_exists(input_file) != 0)
        {
            fprintf(stderr, "Error: The selected file doesn't exist.\n");
            return 1;
        }

        char *output_file = malloc(strlen(input_file) + 10);

        if (!output_file)
        {
            fprintf(stderr, "Error: Memory allocation failed for output filename.\n");
            return 1;
        }

        strcpy(output_file, input_file);
        strcat(output_file, ".jlk");

        if (can_write_file_fopen(output_file) != 0)
        {
            fprintf(stderr, "Error: Cannot access/write the output file.\n");
            free(output_file);
            return 1;
        }

        get_password(password, sizeof(password));
        encrypt_file(password, input_file, output_file);
        free(output_file);

    } 
    else if (strcmp(mode, "decrypt") == 0)
    {
        char password[512] = {0};
        char *input_file = argv[2];

        if (file_exists(input_file) != 0)
        {
            fprintf(stderr, "Error: The selected file doesn't exist.\n");
            return 1;
        }

        get_password(password, sizeof(password));
        decrypt_file(password, input_file, NULL);

    } 
    else if (strcmp(mode, "checksum") == 0)
    {
        char *input_file = argv[2];

        if (file_exists(input_file) != 0)
        {
            fprintf(stderr, "Error: The selected file doesn't exist.\n");
            return 1;
        }

        compute_and_print_checksums(input_file);
    }

    return 0;
}

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/