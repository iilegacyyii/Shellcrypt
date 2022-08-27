# Shellcraft - 
# ~ @0xLegacyy (Jordan Jay)
import argparse
from colorama import Fore, Back, Style
from colorama import init as colorama_init

from binascii import hexlify
from itertools import cycle
from os import urandom
from os.path import isfile
from random import choices
from string import hexdigits


VERSION = "v1.0 beta"


def show_banner():
    # TODO: add support for nocolour maybe?
    banner = f"""{Fore.CYAN}
███████╗██╗  ██╗███████╗██╗     ██╗      ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
███████╗███████║█████╗  ██║     ██║     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
╚════██║██╔══██║██╔══╝  ██║     ██║     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
███████║██║  ██║███████╗███████╗███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   

{Style.RESET_ALL}
 ~ @0xLegacyy (Jordan Jay)
"""
    print(banner)


class Log(object):
    def __init__(self):
        super(Banner, self).__init__()
        return
    
    def logSuccess(msg):
        print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return


    def logInfo(msg):
        print(f"{Style.BRIGHT}{Fore.BLUE}[*]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return


    def logDebug(msg):
        if DEBUG:
            print(f"{Style.BRIGHT}{Fore.MAGENTA}[debug]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return


    def logError(msg):
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return




if __name__ == "__main__":
    # --------- Initialisation ---------
    # Debug mode toggle (logging)
    DEBUG = False

    # Completely unnecessary stuff (unless you're cool)
    colorama_init()
    show_banner()

    # Parse arguments
    argparser = argparse.ArgumentParser(prog="shellcrypt")
    argparser.add_argument("-i", "--input", required=True, help="Path to file to be encrypted.")
    #argparser.add_argument("-e", "--encrypt", default="xor", help="Encryption method to use, default 'xor'.")
    argparser.add_argument("-k", "--key", help="Encryption key in hex format, default (random 8 bytes).")
    argparser.add_argument("-f", "--format", required=True, choices=["c"], help="Output format, specify --formats for a list of formats.")
    argparser.add_argument("-o", "--output", help="Path to output file")
    argparser.add_argument("-v", "--version", action="store_true", help="Shows the version and exits")
    args = argparser.parse_args()

    # If version specified
    if args.version:
        print(VERSION)
        exit()

    # --------- Argument Validation ---------
    Log.logDebug("Validating arguments")

    # Check input file exists
    if not isfile(args.input):
        Log.logError(f"Input file '{args.input}' does not exist.")
        exit()
    
    # TODO: check we can read the file.

    Log.logSuccess(f"Input file: '{args.input}'")
    
    # Check if key is specified.
    # if so => validate and store in key
    # else => generate and store in key
    if args.key is None:
        key = urandom(8)
    else:
        if len(args.key) < 2 or len(args.key) % 1 == 1:
            Log.logError(f"Key must be valid byte(s) in hex format (e.g. 4141).")
            exit()
        for i in args.key:
            if i not in hexdigits:
                Log.logError(f"Key must be valid byte(s) in hex format (e.g. 4141).")
                exit()
        
        key = bytearray.fromhex(args.key)
    
    Log.logSuccess(f"Using key: {hexlify(key).decode()}")
    
    # TODO: more validation when more args are used

    Log.logDebug("Arguments validated")

    # --------- Read Input File ---------
    input_bytes = None
    with open(args.input, "rb") as input_handle:
        input_bytes = input_handle.read()

    # --------- Input File Encryption ---------
    #Log.logInfo(f"Encrypting {len(input_bytes)} bytes") (came up with a better idea, keeping for future reminder)
    Log.logDebug(f"Encrypting input file")

    input_bytes  = bytearray(a ^ b for (a, b) in zip(input_bytes, cycle(key)))
    input_length = len(input_bytes)

    Log.logSuccess(f"Successfully encrypted input file ({len(input_bytes)} bytes)")

    # --------- Output ---------
    # convert input_bytes and key to C array syntax, similar format to msfvenom's csharp output
    output = f"unsigned char key[{len(key)}] = {{"
    for i in range(len(key) - 1):
        if i % 15 == 0:
            output += "\n\t"
        output += f"0x{key[i]:0>2x},"
    output += f"0x{key[-1]:0>2x}\n}};\n\n"
    output += f"unsigned char sh3llc0d3[{input_length}] = {{"
    for i in range(input_length - 1):
        if i % 15 == 0:
            output += "\n\t"
        output += f"0x{input_bytes[i]:0>2x},"
    output += f"0x{input_bytes[-1]:0>2x}\n}};"
    
    # If no output file specified.
    if args.output is None:
        print(output)
        exit()
    
    # If output file specified.
    with open(args.output, "w") as file_handle:
        file_handle.write(output)
    
    Log.logSuccess(f"Output written to '{args.output}'")
