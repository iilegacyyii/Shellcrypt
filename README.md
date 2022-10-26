# Shellcrypt

A single-file cross-platform quality of life tool to obfuscate a given shellcode file and output in a useful format for pasting directly into your source code.

![Screenshot of Shellcrypt encrypting shellcode](https://i.imgur.com/DavG7ad.png)

## Contributors

These are going here because they deserve it
- An00bRektn [github](https://github.com/An00bRektn) [twitter](https://twitter.com/An00bRektn) ♥
- 0xtejas [github](https://github.com/0xtejas)

## Encryption Methods

Shellcrypt currently supports the following encryption methods (more to come in the future!)

- AES (128-bit CBC)
- ChaCha20
- RC4
- Salsa20
- XOR

## Supported Formats

Shellcrypt currently supports the following output formats (more to come in the future!)

- C
- C#
- Nim
- Golang
- Python
- Powershell
- Visual Basic for Applications (VBA)
- Visual Basic Script (VBS)
- Raw

## Usage 
**Encrypt shellcode with a random key**
```plaintext
python ./shellcrypt.py -i ./shellcode.bin -f c
```
**Encrypt shellcode with 128-bit AES CBC**
```plaintext
python ./shellcrypt.py -i ./shellcode.bin -e aes -f c
```
**Encrypt shellcode with a user-specified key**
```plaintext
python ./shellcrypt.py -i ./shellcode.bin -f c -k 6d616c77617265
```
**Output in nim format**
```plaintext
python ./shellcrypt.py -i ./shellcode.bin -f nim
```
**Output to file**
```plaintext
python ./shellcrypt.py -i ./shellcode.bin -f nim -o ./shellcode_out.nim
```
**Get a list of encryption methods**
```plaintext
python ./shellcrypt.py --ciphers
```
**Get a list of output formats**
```plaintext
python ./shellcrypt.py --formats
```
**Help**
```plaintext
███████╗██╗  ██╗███████╗██╗     ██╗      ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
███████╗███████║█████╗  ██║     ██║     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║
╚════██║██╔══██║██╔══╝  ██║     ██║     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║
███████║██║  ██║███████╗███████╗███████╗╚██████╗██║  ██║   ██║   ██║        ██║
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝
v1.5 beta

 ~ @0xLegacyy (Jordan Jay)

usage: shellcrypt [-h] [-i INPUT] [-e ENCRYPT] [-k KEY] [-n NONCE] [-f FORMAT] [--formats] [--ciphers] [-o OUTPUT]
                  [-v]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to file to be encrypted.
  -e ENCRYPT, --encrypt ENCRYPT
                        Encryption method to use, default 'xor'.
  -k KEY, --key KEY     Encryption key in hex format, default (random 16 bytes).
  -n NONCE, --nonce NONCE
                        Encryption nonce in hex format, default (random 16 bytes).
  -f FORMAT, --format FORMAT
                        Output format, specify --formats for a list of formats.
  --formats             Show a list of valid formats
  --ciphers             Show a list of valid ciphers
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -v, --version         Shows the version and exits
```

## Future Development Goals

1. More output formats (rust etc.)
2. More encryption methods
3. Compression methods
4. Create a config system that allows for chaining encryption/encoding/compression methods
5. Flag to add a decrypt method to the generated code
6. [Shikata](https://github.com/EgeBalci/sgn) encoder mayhaps?

_**pssst** this is still heavily in development so if you'd like to contribute, have a go at working on one of the many `TODO`'s in the code :)_
