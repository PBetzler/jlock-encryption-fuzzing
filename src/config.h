/*!
	@file   config.h
	@brief  Configuration file defining constants for versioning and file identification
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

#ifndef CONFIG_H
#define CONFIG_H

/******************************************************************************
* Versioning and Magic Number Definitions
******************************************************************************/

#define VERSION_OLD        "0003"     /*!< Previous file version identifier */
#define VERSION_NEW        "0004"     /*!< Current file version identifier */
#define MAGIC_NUMBER       "JLKFILE"  /*!< Identifier for file type recognition */
#define MAGIC_NUMBER_LEN   7          /*!< Length of the magic number */
#define VERSION_LENGTH     4          /*!< Length of the version string */

/******************************************************************************
* EOF - NO CODE AFTER THIS LINE
******************************************************************************/
#endif // CONFIG_H
