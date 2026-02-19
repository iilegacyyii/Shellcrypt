# Shellcrypt

A cross-platform quality of life tool to obfuscate a given shellcode file and output in a useful format for pasting directly into your source code.

![Screenshot of Shellcrypt encrypting shellcode](https://i.imgur.com/DavG7ad.png)
![Screenshot of Shellcrypt encrypting, encoding, and compressing shellcode](./assets/Shellcrypt%20Demo.png)

# Contributors

These are going here because they deserve it
- An00bRektn [github](https://github.com/An00bRektn) [twitter](https://twitter.com/An00bRektn) ♥
- 0xtejas [github](https://github.com/0xtejas)
- Lavender-exe [github](https://github.com/Lavender-exe) 💜

# Shellcode Conversions
## Crypters
### Encryption

Shellcrypt currently supports the following encryption methods (more to come in the future!)

- AES CBC - 128
- AES CBC - 256
- AES ECB - 256
- ChaCha20
- RC4
- Salsa20
- XOR
- XOR with Linear Congruential Generator (LCG)

### Encoding

- Alpha32
- Ascii85
- Base64
- Words256

### Compression

- LZNT1 (Windows Only)
- RLE

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
- Rust
- Javascript
- Zig
- Raw

# Usage Information
**Encrypt shellcode with a random key**
```bash
uv run main.py -i ./shellcode.bin -f c
```
**Encrypt shellcode with 128-bit AES CBC**
```bash
uv run main.py -i ./shellcode.bin -e aes -f c
```
**Encrypt shellcode with XOR and LZNT1 Compression**
```bash
uv run main.py -i '.\test\shellcode.bin' -f c -a shellcode -e xor -k 4141 -c lznt
```
**Encrypt shellcode with a user-specified key**
```bash
uv run main.py -i ./shellcode.bin -f c -k 6d616c77617265
```
**Output in nim format with an array name of "shellcode"**
```bash
uv run main.py -i ./shellcode.bin -f nim -a shellcode
```
**Output to file**
```bash
uv run main.py -i ./shellcode.bin -f nim -o ./shellcode_out.nim
```
**Obfuscate via Config**
*config.yaml*
```yaml
chain:
  - type: compress
    method: lznt
  - type: encrypt
    method: aes_cbc
    key: "41414141414141414141414141414141"
    nonce: "41414141414141414141414141414141"
  - type: encode
    method: base64
```

```bash
uv run main.py -i ./shellcode.bin -f c -o config_obfuscation.c
```
**Get a list of compression methods**
```bash
uv run main.py --compressors
```
**Get a list of encoding methods**
```bash
uv run main.py --encoders
```
**Get a list of encryption methods**
```bash
uv run main.py --ciphers
```
**Get a list of output formats**
```bash
uv run main.py --formats
```

**Help**
```plaintext
   _____ __         ____                      __
  / ___// /_  ___  / / /___________  ______  / /_
  \__ \/ __ \/ _ \/ / / ___/ ___/ / / / __ \/ __/
 ___/ / / / /  __/ / / /__/ /  / /_/ / /_/ / /_
/____/_/ /_/\___/_/_/\___/_/   \__, / .___/\__/
                              /____/_/
v2.0 - Release

By: @0xLegacyy (Jordan Jay)

usage: shellcrypt [-h] -i INPUT [-e ENCRYPT] [--decrypt] [-d ENCODE] [-c COMPRESS] [-k KEY] [-n NONCE] [-f FORMAT] [--formats] [--ciphers] [--encoders] [--compressors] [-o OUTPUT] [-a ARRAY] [-v]
                  [--preserve-null] [--key-length KEY_LENGTH]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to file to be encrypted.
  -e ENCRYPT, --encrypt ENCRYPT
                        Encryption method to use, default None.
  --decrypt             Enable decryption functionality (not yet implemented).
  -d ENCODE, --encode ENCODE
                        Encoding method to use, default None.
  -c COMPRESS, --compress COMPRESS
                        Compression method to use.
  -k KEY, --key KEY     Encryption key in hex format, default (random 16 bytes).
  -n NONCE, --nonce NONCE
                        Encryption nonce in hex format, default (random 16 bytes).
  -f FORMAT, --format FORMAT
                        Output format, specify --formats for a list of formats.
  --formats             Show a list of valid formats
  --ciphers             Show a list of valid ciphers
  --encoders            Show a list of valid encoders
  --compressors         Show a list of valid compressors
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -a ARRAY, --array ARRAY
                        Array Name, default sh3llc0d3
  -v, --version         Shows the version and exits
  --preserve-null       Avoid XORing null bytes during XOR encryption.
  --key-length KEY_LENGTH
                        Specify the key length in bytes (default is 16).
```

## Future Development Goals

- [x] More output formats (rust etc.)
- [x] More encryption methods
- [x] Compression methods
- [x] Create a config system that allows for chaining encryption/encoding/compression methods
- [ ] Flag to add a decrypt method to the generated code
- [ ] [Shikata](https://github.com/EgeBalci/sgn) encoder mayhaps?

_**pssst** this is still heavily in development so if you'd like to contribute, have a go at working on one of the many `TODO`'s in the code :)_
