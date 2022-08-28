# Shellcrypt

A quality of life tool to obfuscate a given shellcode file and output in a useful format for pasting directly into your source code.

![Screenshot of Shellcrypt encrypting shellcode](https://i.imgur.com/Ct6DOg2.png)

## Supported Formats

Shellcrypt currently supports the following output formats (more to come in the future!)

- C
- C#
- Nim

## Usage 
**Encrypt shellcode with a random key**
```plaintext
python ./shellcrypt.py -i ./shellcode.bin -f c
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
**Help**
```plaintext
███████╗██╗  ██╗███████╗██╗     ██╗      ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
███████╗███████║█████╗  ██║     ██║     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║
╚════██║██╔══██║██╔══╝  ██║     ██║     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║
███████║██║  ██║███████╗███████╗███████╗╚██████╗██║  ██║   ██║   ██║        ██║
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝


 ~ @0xLegacyy (Jordan Jay)

python ./shellcrypt.py [-h] [-i INPUT] [-k KEY] [-f FORMAT] [--formats] [-o OUTPUT] [-v]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to file to be encrypted.
  -k KEY, --key KEY     Encryption key in hex format, default (random 8 bytes).
  -f FORMAT, --format FORMAT
                        Output format, specify --formats for a list of formats.
  --formats             Show a list of valid formats
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -v, --version         Shows the version and exits
```

## Future Development Goals

1. More output formats
2. More encryption methods
3. Compression methods
4. Create a config system that allows for chaining encryption/encoding/compression methods

_**pssst** this is still heavily in development so if you'd like to contribute, have a go at working on one of the many `TODO`'s in the code :)_
