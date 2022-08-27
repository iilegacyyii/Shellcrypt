# Shellcrypt

A QoL tool to obfuscate shellcode. In the future will be able to chain encoding/encryption/compression methods.

(I made this in ~30 minutes so there's a decent amount of TODO's if you want a free commit)

![Screenshot of Shellcrypt encrypting shellcode](https://i.imgur.com/9KUIcIu.png)

## Usage

```plaintext
python ./shellcrypt.py [-h] -i INPUT [-k KEY] -f {c} [-o OUTPUT] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to file to be encrypted.
  -k KEY, --key KEY     Encryption key in hex format, default (random 8 bytes).
  -f {c}, --format {c}  Output format, specify --formats for a list of formats.
  -o OUTPUT, --output OUTPUT
                        Path to output file
  -v, --version         Shows the version and exits
```