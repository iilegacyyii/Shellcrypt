# Shellcraft
# A QoL tool to obfuscate shellcode. 
# In the future will be able to chain encoding/encryption/compression methods.
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

# global vars
VERSION = "v1.0 beta"
OUTPUT_FORMATS = [
    "c",
    "csharp",
    "nim"
]


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
    """ Handles all styled terminal output. """
    def __init__(self):
        super(Log, self).__init__()
        return
    
    def logSuccess(msg:str):
        """ Logs msg to the terminal with a green [+] appended.
            Used to show task success.
        :param msg: User-specified message to be output
        :return:
        """
        print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return

    def logInfo(msg:str):
        """ Logs msg to the terminal with a blue [*] appended
            Used to show task status / info.
        :param msg: User-specified message to be output
        :return:
        """
        print(f"{Style.BRIGHT}{Fore.BLUE}[*]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return

    def logDebug(msg:str):
        """ Logs msg to the terminal with a magenta [debug] appended
            Used to show debug info for nerds.
        :param msg: User-specified message to be output
        :return:
        """
        if DEBUG:
            print(f"{Style.BRIGHT}{Fore.MAGENTA}[debug]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return

    def logError(msg:str):
        """ Logs msg to the terminal with a red [!] appended
            Used to show error messages.
        :param msg: User-specified message to be output
        :return:
        """
        print(f"{Style.BRIGHT}{Fore.RED}[!]{Fore.RESET}{Style.RESET_ALL} {msg}")
        return


class ShellcodeFormatter(object):
    """ Enables for easy output generation in multiple formats. """
    def __init__(self):
        super(ShellcodeFormatter, self).__init__()
        self.__format_handlers = {
            "c":      self.__output_c,
            "csharp": self.__output_csharp,
            "nim":    self.__output_nim
        }
        return
    
    def __generate_array_contents(self, input_bytes:bytearray) -> str:
        """ Takes a byte array, and generates a string in format
            0xaa,0xff,0xab(up to 15),
            0x4f...
        :param input_bytes: bytearray
        :return: string containing formatted array contents
        """
        output = ""
        for i in range(len(input_bytes) - 1):
            if i % 15 == 0:
                output += "\n\t"
            output += f"0x{input_bytes[i]:0>2x},"
        output += f"0x{input_bytes[-1]:0>2x}"
        return output[1:] # (strip first \n)

    def __output_c(self, arrays:dict) -> str:
        """ Private method to output in C format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in c format, similar
                        to msfvenom's csharp format.
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"unsigned char key[{len(arrays[array_name])}] = {{\n"
            output += self.__generate_array_contents(arrays[array_name])
            output += "\n};\n\n"
        
        return output
    
    def __output_csharp(self, arrays:dict) -> str:
        """ Private method to output in C# format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in C# format
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"byte[] key = new byte[{len(arrays[array_name])}] {{\n"
            output += self.__generate_array_contents(arrays[array_name])
            output += "\n};\n\n"
        
        return output

    def __output_nim(self, arrays:dict) -> str:
        """ Private method to output in nim format.
        :param arrays: dictionary containing array names and their respective bytes
        :return output: string containing shellcode in nim format
        """
        # Generate arrays
        output = str()
        for array_name in arrays:
            output += f"var {array_name}: array[{len(arrays[array_name])}, byte] = [\n"
            output += "\tbyte " + self.__generate_array_contents(arrays[array_name])[1:]
            output += "\n]\n\n"
        return output

    def generate(self, output_format:str, arrays:dict) -> str:
        """ Generates output given the current class configuration
        :param output_format: Output format to generate e.g. "c" or "csharp"
        :param shellcode: dictionary containing {"arrayname":array_bytes} pairs
        :return output: string containing formatted shellcode + key(s)
        """
        # In future, too many formats to be displayed as choices in argparse
        # so look to do some format validation here, and add a --formats argument

        # Pass execution to the respective handler and return
        return self.__format_handlers[output_format](arrays)




if __name__ == "__main__":
    # --------- Initialisation ---------
    # Debug mode toggle (logging)
    DEBUG = False

    # Completely unnecessary stuff (unless you're cool)
    colorama_init()
    show_banner()

    # Parse arguments
    argparser = argparse.ArgumentParser(prog="shellcrypt")
    argparser.add_argument("-i", "--input", help="Path to file to be encrypted.")
    #argparser.add_argument("-e", "--encrypt", default="xor", help="Encryption method to use, default 'xor'.")
    argparser.add_argument("-k", "--key", help="Encryption key in hex format, default (random 8 bytes).")
    argparser.add_argument("-f", "--format", help="Output format, specify --formats for a list of formats.")
    argparser.add_argument("--formats", action="store_true", help="Show a list of valid formats")
    argparser.add_argument("-o", "--output", help="Path to output file")
    argparser.add_argument("-v", "--version", action="store_true", help="Shows the version and exits")
    args = argparser.parse_args()

    # --------- Info-only arguments ---------
    # If formats specified
    if args.formats:
        print("The following formats are available:")
        for i in OUTPUT_FORMATS:
            print(f" - {i}")
        exit()

    # If version specified
    if args.version:
        print(VERSION)
        exit()
    
    # --------- Argument Validation ---------
    Log.logDebug("Validating arguments")

    # Check input file is specified
    if args.input is None:
        Log.logError("Must specify an input file e.g. -i .\shellcode.bin (specify --help for more info)")
        exit()

    # Check input file exists
    if not isfile(args.input):
        Log.logError(f"Input file '{args.input}' does not exist.")
        exit()
    
    # TODO: check we can read the file.

    Log.logSuccess(f"Input file: '{args.input}'")

    # Check format is specified
    if args.format not in OUTPUT_FORMATS:
        Log.logError("Invalid format specified, please specify a valid format e.g. -f c (--formats gives a list of valid formats) ") 
        exit()
    
    Log.logSuccess(f"Output format: {args.format}")

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

    # --------- Output Generation ---------
    # Define array names + content to be formatted
    # TODO: have `arrays` dict be generated by the encryption method(s) in use
    #       as only XOR is supported, this is fine for now.
    arrays = {
        "key":key,
        "sh3llc0d3":input_bytes
    }

    # Generate formatted output.
    shellcode_formatter = ShellcodeFormatter()
    output = shellcode_formatter.generate(args.format, arrays)
    
    # --------- Output ---------
    # If no output file specified.
    if args.output is None:
        print(output)
        exit()
    
    # If output file specified.
    with open(args.output, "w") as file_handle:
        file_handle.write(output)
    
    Log.logSuccess(f"Output written to '{args.output}'")
