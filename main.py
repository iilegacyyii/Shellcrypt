"""
~ @0xLegacyy (Jordan Jay)

Shellcrypt: Quality of Life Shellcode Obfuscation Tool

/ - Shellcrypt.py  : Main Program
/utils/
    - /crypters.py : Encryption, Encoding & Compression Toolkit
    - /winapi.py   : LZNT1 Compression WinAPI Helper
    - /logging.py  : Logging Helper
"""
import argparse
import logging
import pyfiglet

import yaml
from os.path import exists

from rich.console import Console
from rich.theme import Theme
from binascii import hexlify
from os import urandom
from os.path import isfile
from string import hexdigits

from utils.crypters import Encode, Encrypt, Compress, ShellcodeFormatter
from utils.logging import Log

theme = Theme({
    "success" : "spring_green3",
    "info" : "cornflower_blue",
    "error" : "red",
    "exception" : "red",
})
console = Console(theme=theme, color_system="auto")

# global vars
OUTPUT_FORMATS = [
    "c",
    "csharp",
    "nim",
    "go",
    "py",
    "ps1",
    "vba",
    "vbscript",
    "raw",
    "rust",
    "js",
    "zig"
]


CIPHERS = [
    "aes_128",
    "aes_ecb",
    "aes_cbc",
    "chacha20",
    "rc4",
    "salsa20",
    "xor",
    "xor_complex"
]

ENCODING = [
    "alpha32",
    "ascii85",
    "base64",
    "words256"
]

COMPRESSION = [
    "lznt",
    "rle",
]

VERSION = "v2.0 - Release"

def show_banner():
    banner = pyfiglet.figlet_format("Shellcrypt", font="slant", justify="left")
    console.print(f"[bold yellow]{banner}{VERSION}\n[/bold yellow]")
    console.print("By: @0xLegacyy (Jordan Jay)\n", style="green4")

def parse_args():
    # Parse arguments with additional features
    # TODO: Add decryption routines in the future

    argparser = argparse.ArgumentParser(prog="shellcrypt")

    # Required argument: Input file
    argparser.add_argument("-i", "--input", help="Path to file to be encrypted.", required=True)

    # Encryption related options
    argparser.add_argument("-e", "--encrypt", default=None, help="Encryption method to use, default None.")
    argparser.add_argument("--decrypt", action="store_true", help="Enable decryption functionality (not yet implemented).")

    # Encoding related options
    argparser.add_argument("-d", "--encode", default=None, help="Encoding method to use, default None.")

    # Compression related options
    argparser.add_argument("-c", "--compress", default=None, help="Compression method to use.")

    # Key and nonce options
    argparser.add_argument("-k", "--key", help="Encryption key in hex format, default (random 16 bytes).")
    argparser.add_argument("-n", "--nonce", help="Encryption nonce in hex format, default (random 16 bytes).")

    # Format related options
    argparser.add_argument("-f", "--format", help="Output format, specify --formats for a list of formats.")

    # Info-related arguments
    argparser.add_argument("--formats", action="store_true", help="Show a list of valid formats")
    argparser.add_argument("--ciphers", action="store_true", help="Show a list of valid ciphers")
    argparser.add_argument("--encoders", action="store_true", help="Show a list of valid encoders")
    argparser.add_argument("--compressors", action="store_true", help="Show a list of valid compressors")

    # Output file and version
    argparser.add_argument("-o", "--output", help="Path to output file")
    argparser.add_argument("-a", "--array", default="sh3llc0d3", help="Array Name, default sh3llc0d3")
    argparser.add_argument("-v", "--version", action="store_true", help="Shows the version and exits")

    # Additional Features
    # Preserve null bytes during XOR encryption
    argparser.add_argument("--preserve-null", action="store_true", help="Avoid XORing null bytes during XOR encryption.")

    # Specify key length (if greater than 16)
    argparser.add_argument("--key-length", type=int, default=16, help="Specify the key length in bytes (default is 16).")

    return argparser.parse_args()

def print_available_options(option_type, options, exit_on_print=True):
    print(f"The following {option_type} are available:")
    for option in options:
        print(f" - {option}")
    if exit_on_print:
        exit()

def validate_input_file(input_file):
    if input_file is None:
        Log.logError("""Must specify an input file e.g.
                     -i shellcode.bin (specify --help for more info)""")
        exit()
    if not isfile(input_file):
        Log.logError(f"Input file '{input_file}' does not exist.")
        exit()
    Log.logSuccess(f"Input file: '{input_file}'")

def validate_and_get_key(key, encrypt_type):
    if key is None:
        return urandom(32)

    if len(key) < 2 or len(key) % 2 == 1 or any(i not in hexdigits for i in key):
        Log.logError("Key must be valid byte(s) in hex format (e.g. 4141).")
        exit()

    if encrypt_type == "aes" and len(key) != 32:
        Log.logError("AES-128 key must be exactly 16 bytes long.")
        exit()

    return bytearray.fromhex(key)

def validate_and_get_nonce(nonce):
    if nonce is None:
        return urandom(16)

    if len(nonce) != 32 or any(i not in hexdigits for i in nonce):
        Log.logError("Nonce must be 16 valid bytes in hex format (e.g. 7468697369736d616c6963696f757321)")
        exit()

    return bytearray.fromhex(nonce)

def process_encoding(input_bytes, args, encoder):
    if args.encode:
        input_bytes = encoder.encode(args.encode, input_bytes)
    return input_bytes

def process_compression(input_bytes, args, compressor):
    if args.compress:
        input_bytes = compressor.compress(args.compress, input_bytes)
    return input_bytes

def process_encryption(input_bytes, args, cryptor, key, nonce):
    if args.encrypt:
        input_bytes = cryptor.encrypt(args.encrypt, input_bytes, key, nonce)
    return input_bytes

def main():
    try:
        # Show banner and parse arguments
        show_banner()
        args = parse_args()

        # --------- Config System ---------
        config_chain = None
        if exists("config.yaml"):
            with open("config.yaml", "r") as f:
                config = yaml.safe_load(f)
                config_chain = config.get("chain", None)

        # --------- Info-only arguments ---------
        if args.formats:
            print_available_options("formats", OUTPUT_FORMATS)
        if args.ciphers:
            print_available_options("ciphers", CIPHERS)
        if args.encoders:
            print_available_options("encoders", ENCODING)
        if args.compressors:
            print_available_options("compressors", COMPRESSION)
        if args.version:
            print(VERSION)
            exit()

        # --------- Argument Validation ---------
        Log.logDebug(msg="Validating arguments")

        validate_input_file(args.input)

        if args.format not in OUTPUT_FORMATS:
            Log.logError("""Invalid format specified, please specify a valid format e.g.
                         -f c (--formats gives a list of valid formats)""")
            exit()

        Log.logSuccess(f"Output format: {args.format}")

        if args.encrypt and args.encrypt not in CIPHERS:
            Log.logError("""Invalid cipher specified, please specify a valid cipher e.g.
                         -e xor (--ciphers gives a list of valid ciphers)""")
            exit()

        if args.encode and args.encode not in ENCODING:
            Log.logError("""Invalid encoder specified, please specify a valid encoder e.g.
                         -d ascii85 (--encoders gives a list of valid encoders)""")
            exit()

        if args.compress and args.compress not in COMPRESSION:
            Log.logError("""Invalid compression specified, please specify a valid compression e.g.
                         -c lznt (--compressors gives a list of valid compressors)""")
            exit()

        if args.compress != None:
            Log.logSuccess(f"Output Compression: {args.compress}")
        
        if args.encrypt != None:
            Log.logSuccess(f"Output Encryption: {args.encrypt}")
        else:
            Log.logInfo("No encryption found, defaulting to XOR")
        
        if args.encode != None:
            Log.logSuccess(f"Output Encoding: {args.encode}")

        key = validate_and_get_key(args.key, args.encrypt)
        Log.logSuccess(f"Using key: {hexlify(key).decode()}")

        nonce = validate_and_get_nonce(args.nonce)
        if args.encrypt == "aes":
            Log.logSuccess(f"Using nonce: {hexlify(nonce).decode()}")

        Log.logDebug("Arguments validated")

        # --------- Read Input File ---------
        with open(args.input, "rb") as input_handle:
            input_bytes = input_handle.read()

        # --------- Input File Processing ---------
        cryptor = Encrypt()
        compressor = Compress()
        encoder = Encode()

        # If config.yaml exists and chain is specified, use it
        if config_chain:
            for step in config_chain:
                step_type = step.get("type")
                method = step.get("method")
                if step_type == "compress":
                    Log.logSuccess(f"Output Compression: {method}")
                    input_bytes = compressor.compress(method, input_bytes)
                elif step_type == "encrypt":
                    Log.logSuccess(f"Output Encryption: {method}")
                    step_key = step.get("key")
                    step_nonce = step.get("nonce")
                    import re
                    def to_hex_str(val):
                        if val is None:
                            return None
                        if isinstance(val, int):
                            return format(val, 'x')
                        return str(val)
                    def validate_hex(val, expected_len, name):
                        if val is None:
                            return None
                        hex_str = to_hex_str(val)
                        if not re.fullmatch(r'[0-9a-fA-F]+', hex_str):
                            Log.logError(f"{name} in config.yaml must be a valid hex string.")
                            exit()
                        if len(hex_str) != expected_len:
                            Log.logError(f"{name} in config.yaml must be {expected_len} hex digits ({expected_len//2} bytes). Got {len(hex_str)}.")
                            exit()
                        return hex_str
                    use_key = bytearray.fromhex(validate_hex(step_key, 32, "key")) if step_key else key
                    use_nonce = bytearray.fromhex(validate_hex(step_nonce, 32, "nonce")) if step_nonce else nonce
                    input_bytes = cryptor.encrypt(method, input_bytes, use_key, use_nonce)
                elif step_type == "encode":
                    Log.logSuccess(f"Output Encoder: {method}")
                    input_bytes = encoder.encode(method, input_bytes)
                else:
                    Log.logError(f"Unknown step type in config: {step_type}")
                    exit()
        else:
            if args.compress:
                logging.info("Compressing Shellcode")
                input_bytes = process_compression(input_bytes, args, compressor)

            if args.encrypt:
                logging.info("Encrypting Shellcode")
                input_bytes = process_encryption(input_bytes, args, cryptor, key, nonce)

            if args.encode:
                logging.info("Encoding Shellcode")
                input_bytes = process_encoding(input_bytes, args, encoder)

        Log.logSuccess(f"Successfully processed input file ({len(input_bytes)} bytes)")
        Log.logInfo("Deobfuscation Routine: Decode -> Decrypt -> Decompress\n")

        # --------- Output Generation ---------
        arrays = {"key": key}
        if args.encrypt and args.encrypt in ["aes_128", "aes_ecb", "aes_cbc"]:
            arrays["nonce"] = nonce
        arrays[args.array] = input_bytes

        # Generate formatted output
        shellcode_formatter = ShellcodeFormatter()
        output = shellcode_formatter.generate(args.format, arrays)

        # --------- Output ---------
        if args.output is None:
            console.print(output.decode("latin1") if isinstance(output, bytearray) else output)
            exit()

        write_mode = "wb" if isinstance(output, bytearray) else "w"
        with open(args.output, write_mode) as file_handle:
            file_handle.write(output)

        Log.logSuccess(f"Output written to '{args.output}'")

    except Exception as e:
        Log.LogException(f"Exception Caught: {e}")

if __name__ == "__main__":
    main()
