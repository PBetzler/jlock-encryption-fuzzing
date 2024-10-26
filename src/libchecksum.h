/*!
	@file   libchecksum.h
	@brief  Header file for checksum computation and printing functions
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

#ifndef LIBCHECKSUM_H
#define LIBCHECKSUM_H

/******************************************************************************
* Includes
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/******************************************************************************
* Macro Definitions
******************************************************************************/

#define BUFFER_SIZE 4096  /*!< Buffer size used for reading file chunks */

/******************************************************************************
* Function Prototypes
******************************************************************************/

/*!
    @brief Computes and prints the MD5, SHA1, and SHA256 checksums for a file
    @param[in] file_path - Path to the file for checksum computation
    @return 0 on success, non-zero on failure
*/
int compute_and_print_checksums(const char *file_path);

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/
#endif // LIBCHECKSUM_H
