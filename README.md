# Snipper: Command-Line Encryption and Decryption Tool

## Description
This is a command-line encryption and decryption tool leveraging military-grade encryption standards. It is lightweight, easy to use, and optimized for secure data operations.

## Commands
- `help`: Shows a list of all commands
- `license`: Shows the license information
- `encrypt`: Encryption service
- `decrypt`: Decryption service
- `hash`: Hashing service
- `keygen`: Generate asymmetric encryption key pair

## Options

### Encryption Commands
- `--mode [UAC|AES|RSA|XOR]`: Mode of the encryption, it can be UAC (Unified Advanced Cipher, this is a new cryptography standard defined in `cryptography/whitepapers`), AES, RSA, or XOR
- `--type [FILE|TEXT]`: Acknowledge the input type
- `--in value`: Input of the encryption process. It can be a file path or a string of text with quotation marks
- `--key`: Key for encryption (input path to the key file for asymmetric encryption)

### Hash Command
- `--mode [SHA2-256|SHA2-512|SHA3-256|SHA3-512|SHAKE-256]`: Mode of hashing (note that we use SHA-3 for SHA-256 and SHA-512)
- `--type [FILE|TEXT]`: Acknowledge the input type
- `--in value`: Input of hashing process. It can be a file path or a string of text with quotation marks
- `[--length value]`: Length of the output hash (only for SHAKE-256)

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.