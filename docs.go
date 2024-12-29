package main

const help = `
NAME:
    snipper.exe - A secured military grade encryption tool

USAGE:
    snipper.exe command [options]

VERSION:
    v.1.1.3

AUTHOR:
    Max <Max9836@github>

DESCRIPTION:
    It is a command-line encryption and decryption tool leveraging military-grade encryption standards.
    It is lightweight, easy to use, and optimized for secure data operations.

COMMANDS:
    help                Shows a list of all commands
    license	        Shows the license information
    encrypt             Encryption service
    decrypt             Decryption service
    hash                Hashing service
    keygen              Generate asymmetric encryption key pair

OPTIONS:
    Options for encryption commands:
        --mode [UAC|AES|RSA|XOR]     Mode of the encryption, it can be UAC (Unified Advanced Cipher), AES, RSA, or XOR
        --type [FILE|TEXT]           Acknowledge the input type
        --in value                   Input of the encryption process. It can be a file path or a string of text with quotation marks
        --key                        Key for encryption (input path to the key file for asymmetric encryption)

    Options for hash command:	
        --mode [SHA2-256|SHA2-512|SHA3-256|SHA3-512|SHAKE-256]      Mode of hashing (note that we use SHA-3 for SHA-256 and SHA 512)
        --type [FILE|TEXT]           Acknowledge the input type
        --in value                   Input of hashing process. It can be a file path or a string of text with quotation marks
        [--length value]             Length of the output hash (only for SHAKE-256)  

    Options for keygen:
        --mode [RSA]                 Mode of the encryption. (This decides the format of the key file)
        --length value               Length of the key file. (default: 4096)
`
const license = `
Copyright 2025 Max <Max9836@github>

This project is licensed under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
`
