/*!
	@file   libcrypt.h
	@brief  Header file for file encryption and decryption functions using AES-256-CBC
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

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/
/******************************************************************************
* Preprocessor Definitions & Macros
******************************************************************************/

#ifndef LIBCRYPT_H
#define LIBCRYPT_H

/******************************************************************************
* Macro Definitions
******************************************************************************/

#define AES_KEY_SIZE            32    /*!< AES key size in bytes (256-bit key) */
#define AES_BLOCK_SIZE          16    /*!< AES block size in bytes */
#define IV_SIZE                 16    /*!< Initialization vector (IV) size in bytes */
#define HEADER_SIZE             252   /*!< Size of the header section in plain text */
#define HEADER_BYTES            504   /*!< Size of the header in UTF-16LE encoding */
#define ENCRYPTED_HEADER_SIZE   512   /*!< Size of the encrypted header in bytes */

/******************************************************************************
* Function Prototypes
******************************************************************************/

/*!
    @brief Encrypts a file using AES-256-CBC and saves to the output file
    @param[in] password - Password for key derivation
    @param[in] input_file - Path to the input file to encrypt
    @param[in] output_file - Path to the output file for encrypted data
*/
void encrypt_file(const char *password, const char *input_file, const char *output_file);

/*!
    @brief Decrypts an AES-256-CBC encrypted file and saves to the output file
    @param[in] password - Password for key derivation
    @param[in] input_file - Path to the encrypted input file
    @param[in] output_file - Path to the output file for decrypted data
*/
void decrypt_file(const char *password, const char *input_file, const char *output_file);

/*!
    @brief Encrypts data using AES-256-CBC with a password-derived key
    @param[in] password - Password for key derivation
    @param[in] input - Data to be encrypted
    @param[in] input_len - Length of the input data
    @param[out] output_len - Pointer to store length of encrypted data
    @param[in] iv - Initialization vector for encryption
    @return Pointer to encrypted data or NULL on failure
*/
unsigned char* AesEncrypt(const char* password, unsigned char* input, int input_len, int* output_len, unsigned char* iv);

/*!
    @brief Decrypts data using AES-256-CBC with a password-derived key
    @param[in] password - Password for key derivation
    @param[in] input - Encrypted data to be decrypted
    @param[in] input_len - Length of the encrypted data
    @param[out] output_len - Pointer to store length of decrypted data
    @param[in] iv - Initialization vector for decryption
    @return Pointer to decrypted data or NULL on failure
*/
unsigned char* AesDecrypt(const char* password, unsigned char* input, int input_len, int* output_len, unsigned char* iv);

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/
#endif // LIBCRYPT_H
