import base64
import random
import lznt1

from os import urandom
from Crypto.Cipher import AES, ARC4, ChaCha20, Salsa20
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

from itertools import cycle


class ShellcodeFormatter:
    """Generates shellcode output in various formats."""
    def __init__(self):
        self.__format_handlers = {
            "c": self.__output_c,
            "csharp": self.__output_csharp,
            "nim": self.__output_nim,
            "go": self.__output_go,
            "py": self.__output_py,
            "ps1": self.__output_ps1,
            "vba": self.__output_vba,
            "vbscript": self.__output_vbscript,
            "raw": self.__output_raw,
            "rust": self.__output_rust,
            "js": self.__output_js,
            "zig": self.__output_zig
        }

    def __generate_array_contents(self, input_bytes: bytearray, string_format=False) -> str:
        """Generates formatted shellcode from bytearray."""
        output = ""
        if not string_format:
            for i in range(len(input_bytes) - 1):
                if i % 15 == 0:
                    output += "\n\t"
                output += f"0x{input_bytes[i]:0>2x},"
            output += f"0x{input_bytes[-1]:0>2x}"
            # Only strip the leading newline if one was added
            return output.lstrip("\n")
        else:
            for i in range(len(input_bytes) - 1):
                if i % 15 == 0:
                    output += "\n"
                output += f"\\x{input_bytes[i]:0>2x}"
            output += f"\\x{input_bytes[-1]:0>2x}"
            return output.lstrip("\n")

    def __output_format(self, arrays: dict, template: str, array_format="unsigned char") -> str:
        """Generate shellcode in specified format."""
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_format} {array_name}[{len(array)}] = {{\n"
            output += self.__generate_array_contents(array)
            output += "\n};\n\n"
        return output

    def __output_c(self, arrays: dict) -> str:
        return self.__output_format(arrays, "c")

    def __output_rust(self, arrays: dict) -> str:
        return self.__output_format(arrays, "rust", array_format="let")

    def __output_csharp(self, arrays: dict) -> str:
        return self.__output_format(arrays, "csharp", array_format="byte[]")

    def __output_nim(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"var {array_name}: array[{len(array)}, byte] = [\n"
            output += "\tbyte " + self.__generate_array_contents(array)[1:]
            output += "\n]\n\n"
        return output

    def __output_go(self, arrays: dict) -> str:
        return self.__output_format(arrays, "go", array_format="[]byte")

    def __output_py(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_name} = b\"\"\""
            output += self.__generate_array_contents(array, string_format=True)
            output += "\"\"\"\n\n"
        return output

    def __output_ps1(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"[Byte[]] ${array_name} = "
            output += self.__generate_array_contents(array)[1:]
            output += "\n\n"
        return output

    def __output_vba(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_name} = Array("
            line_length = len(output)
            for _, x in enumerate(array):
                if line_length + 5 > 1022:
                    output += "_\n"
                    line_length = 0
                output += f"{x},"
                line_length += len(f"{x},")
            if line_length + 4 > 1023:
                output += "_\n"
            output += f"{x})\n\n"
        return output

    def __output_vbscript(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_name}="
            output += "".join([f"Chr({str(c)})&" for c in array])[:-1]
            output += "\n\n"
        return output

    def __output_js(self, arrays: dict) -> str:
        """JavaScript output."""
        output = ""
        for array_name, array in arrays.items():
            output += f"const {array_name} = new Uint8Array({len(array)}); \n"
            output += f"{array_name}.set(["
            output += self.__generate_array_contents(array)
            output += "]);\n\n"
        return output

    def __output_zig(self, arrays: dict) -> str:
        """Zig output."""
        output = ""
        for array_name, array in arrays.items():
            output += f"var {array_name} = []u8{{\n"
            output += self.__generate_array_contents(array)
            output += "\n};\n\n"
        return output

    def __output_raw(self, arrays: dict) -> str:
        return arrays["sh3llc0d3"]

    def generate(self, output_format: str, arrays: dict) -> str:
        """Generates the formatted shellcode based on the output format."""
        handler = self.__format_handlers.get(output_format)
        if handler is None:
            raise ValueError(f"Unsupported output format: {output_format}. Valid formats: {', '.join(self.__format_handlers.keys())}")
        return handler(arrays)


class Encrypt:
    """ Consolidates encryption into a single class. """
    def __init__(self):
        super(Encrypt, self).__init__()
        self.__encryption_handlers = {
            "xor":         self.__xor,
            "xor_complex": self.__xor_complex,
            "aes_128":     self.__aes_128,
            "aes_ecb":     self.__aes_ecb,
            "aes_cbc":     self.__aes_cbc,
            "rc4":         self.__rc4,
            "chacha20":    self.__chacha20,
            "salsa20":     self.__salsa20
        }
        return

    def __random_key(self) -> int:
        self.seed = random.randint(0, 2**32 - 1)

        LCG_A = 1664525  # Multiplier
        LCG_C = 1013904223  # Increment
        LCG_M = 2**32  # Modulus (2^32)

        self.seed = (LCG_A * self.seed + LCG_C) % LCG_M
        return self.seed & 0xFF

    def encrypt(self, cipher:str, plaintext:bytearray, key:bytearray, nonce:bytearray) -> bytearray:
        """ Encrypts plaintext with the user-specified cipher.
            This has been written this way to support chaining of
            multiple encryption methods in the future.
        :param cipher: cipher to use, e.g. 'xor'/'aes'
        :param plaintext: bytearray containing our plaintext
        :param key: bytearray containing our encryption key
        :param nonce: bytearray containing nonce for aes etc.
                      if none will be generated on the fly
        :return ciphertext: bytearray containing encrypted plaintext
        """
        # If nonce not specified, generate one, otherwise use the specified one.
        self.nonce = urandom(16) if nonce is None else nonce
        self.key = key
        # cipher is already validated (check argument validation section).
        return self.__encryption_handlers[cipher](plaintext)

    def __xor(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext with a repeating XOR key.
        :param plaintext: bytearray containing our plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        return bytearray(a ^ b for (a, b) in zip(plaintext, cycle(self.key)))

    def __xor_complex(self, plaintext: bytearray) -> bytearray:
        """
        XOR Encrypts/Decrypts given shellcode using a Linear Congruential Generator (LCG)
        """
        encrypted_shellcode = bytearray()
        for byte in plaintext:
            random_key = self.__random_key()
            encrypted_shellcode.append(byte ^ random_key)

        return encrypted_shellcode

    def __aes_128(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext with AES-128 in CBC mode.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        aes_cipher = AES.new(self.key, AES.MODE_CBC, self.nonce)
        plaintext = bytearray(pad(plaintext, 16))
        return bytearray(aes_cipher.encrypt(plaintext))

    def __rc4(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via RC4.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        rc4_cipher = ARC4.new(self.key)
        return bytearray(rc4_cipher.encrypt(plaintext))

    def __chacha20(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via ChaCha20.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        chacha20_cipher = ChaCha20.new(key=self.key)
        return bytearray(chacha20_cipher.encrypt(plaintext))

    def __salsa20(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via Salsa20.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        salsa20_cipher = Salsa20.new(key=self.key)
        return bytearray(salsa20_cipher.encrypt(plaintext))

    def __aes_ecb(self, plaintext:bytearray) -> bytearray:
        cipher = AES.new(self.key, AES.MODE_ECB)
        padding_length = 16 - len(plaintext) % 16
        padded_shellcode = plaintext + bytearray([padding_length] * padding_length)
        return bytearray(cipher.encrypt(padded_shellcode))

    def __aes_cbc(self, plaintext:bytearray) -> bytearray:
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        padding_length = 16 - len(plaintext) % 16
        padded_shellcode = plaintext + bytearray([padding_length] * padding_length)

        encrypted_shellcode = cipher.encrypt(padded_shellcode)
        return bytearray(iv) + bytearray(encrypted_shellcode)


class Compress:
    def __init__(self):
        self.__compression_handlers = {
            "lznt": self.__lznt_compress,
            "rle":  self.__rle_compress
        }
        self.__decompression_handlers = {
            "lznt": self.__lznt_decompress,
            "rle":  self.__rle_decompress
        }

    def compress(self, method: str, data: bytes) -> bytes:
        handler = self.__compression_handlers.get(method)
        if handler:
            return handler(data)
        raise ValueError(f"Unsupported compression method: {method}")

    def decompress(self, method: str, data: bytes) -> bytes:
        handler = self.__decompression_handlers.get(method)
        if handler:
            return handler(data)
        raise ValueError(f"Unsupported decompression method: {method}")

    def __lznt_compress(self, data: bytes) -> bytes:
        """LZNT compression via RtlCompressBuffer (LZNT1 + MAXIMUM engine)."""
        return bytearray(lznt1.compress(data))

    def __lznt_decompress(self, data: bytes) -> bytes:
        """LZNT decompression via RtlDecompressBuffer."""
        return bytearray(lznt1.decompress(data))

    def __rle_compress(self, data: bytearray) -> bytearray:
        compressed = bytearray()
        index = 0
        while index < len(data):
            byte = data[index]
            count = 1
            while index + 1 < len(data) and data[index + 1] == byte:
                count += 1
                index += 1
            compressed.extend([byte, count])
            index += 1
        return compressed

    def __rle_decompress(self, data: bytearray) -> bytearray:
        decompressed = bytearray()
        for i in range(0, len(data), 2):
            byte, count = data[i], data[i + 1]
            decompressed.extend([byte] * count)
        return decompressed


class Encode:
    def __init__(self):
        self.__encoding_handlers = {
            "base64": self.__base64_encode,
            "ascii85": self.__ascii85_encode,
            "alpha32": self.__alpha32_encode,
            "words256": self.__words256_encode
        }
        self.__decoding_handlers = {
            "base64": self.__base64_decode,
            "ascii85": self.__ascii85_decode,
            "alpha32": self.__alpha32_decode,
            "words256": self.__words256_decode
        }

    def encode(self, encoding: str, data: bytearray) -> bytearray:
        """Encode data using specified encoding."""
        handler = self.__encoding_handlers.get(encoding)
        if handler:
            return handler(data)
        raise ValueError(f"Unsupported encoding: {encoding}")

    def decode(self, decoding: str, data: bytearray) -> bytearray:
        """Decode data using specified decoding."""
        handler = self.__decoding_handlers.get(decoding)
        if handler:
            return handler(data)
        raise ValueError(f"Unsupported decoding: {decoding}")

    def __base64_encode(self, data: bytearray) -> bytearray:
        """Base64 encoding."""
        return bytearray(base64.b64encode(data))

    def __base64_decode(self, data: bytearray) -> bytearray:
        """Base64 decoding."""
        return bytearray(base64.b64decode(data))

    def __ascii85_encode(self, data: bytearray) -> bytearray:
        """ASCII85 encoding."""
        return bytearray(base64.a85encode(data))

    def __ascii85_decode(self, data: bytearray) -> bytearray:
        """ASCII85 decoding."""
        return bytearray(base64.a85decode(data))

    def __alpha32_encode(self, data: bytearray) -> bytearray:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        encoded = bytearray()
        for byte in data:
            encoded.extend(alphabet[byte % len(alphabet)].encode())
        return encoded

    def __alpha32_decode(self, data: bytearray) -> bytearray:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        decoded = bytearray()
        for char in data:
            decoded.append(alphabet.index(chr(char)))
        return decoded

    def __words256_encode(self, data: bytearray) -> bytearray:
        words = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
                "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike",
                "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
                "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu"]
        encoded = bytearray()
        for byte in data:
            encoded.extend(words[byte % len(words)].encode() + b" ")
        return encoded

    def __words256_decode(self, data: bytearray) -> bytearray:
        words = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
                "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike",
                "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
                "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu"]
        decoded = bytearray()
        word = b""
        for byte in data:
            word += bytes([byte])
            if word.endswith(b" "):  # Word boundary (space)
                decoded.append(words.index(word.decode().strip()))
                word = b""
        return decoded
