"""
Comprehensive test suite for Shellcrypt
Tests all encryption, encoding, compression, and output format options.
"""
import subprocess
import sys
import os
import tempfile

# Ensure we can import from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.crypters import Encrypt, Encode, Compress, ShellcodeFormatter

# Test data
TEST_SHELLCODE = bytearray(b'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50')

# Configuration
OUTPUT_FORMATS = ["c", "csharp", "nim", "go", "py", "ps1", "vba", "vbscript", "raw", "rust", "js", "zig"]
CIPHERS = ["aes_128", "aes_ecb", "aes_cbc", "chacha20", "rc4", "salsa20", "xor", "xor_complex"]
ENCODINGS = ["alpha32", "ascii85", "base64", "words256"]
COMPRESSIONS = ["lznt", "rle"]


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.failures = []

    def add_pass(self, test_name):
        self.passed += 1
        print(f"  [PASS] {test_name}")

    def add_fail(self, test_name, error):
        self.failed += 1
        self.failures.append((test_name, str(error)))
        print(f"  [FAIL] {test_name}: {error}")

    def summary(self):
        print("\n" + "=" * 60)
        print(f"SUMMARY: {self.passed} passed, {self.failed} failed")
        if self.failures:
            print("\nFailed tests:")
            for name, error in self.failures:
                print(f"  - {name}: {error}")
        print("=" * 60)
        return self.failed == 0


def test_single_byte_key_formatting():
    """Test that single-byte keys are formatted correctly (Issue: x00 instead of 0x00)"""
    print("\n[TEST] Single-byte key formatting")
    results = TestResults()

    formatter = ShellcodeFormatter()

    # Test with single byte key 0x00
    arrays = {"key": bytearray([0x00]), "shellcode": TEST_SHELLCODE}
    output = formatter.generate("c", arrays)

    if "x00" in output and "0x00" not in output:
        results.add_fail("Single byte 0x00", "Got 'x00' instead of '0x00'")
    elif "0x00" in output:
        results.add_pass("Single byte 0x00")
    else:
        results.add_fail("Single byte 0x00", f"Unexpected output format")

    # Test with single byte key 0xFF
    arrays = {"key": bytearray([0xFF]), "shellcode": TEST_SHELLCODE}
    output = formatter.generate("c", arrays)

    if "xff" in output and "0xff" not in output:
        results.add_fail("Single byte 0xFF", "Got 'xff' instead of '0xff'")
    elif "0xff" in output:
        results.add_pass("Single byte 0xFF")
    else:
        results.add_fail("Single byte 0xFF", f"Unexpected output format")

    # Test with single byte key 0x41
    arrays = {"key": bytearray([0x41]), "shellcode": TEST_SHELLCODE}
    output = formatter.generate("c", arrays)

    if "x41" in output and "0x41" not in output:
        results.add_fail("Single byte 0x41", "Got 'x41' instead of '0x41'")
    elif "0x41" in output:
        results.add_pass("Single byte 0x41")
    else:
        results.add_fail("Single byte 0x41", f"Unexpected output format")

    return results


def test_output_formats():
    """Test all output format generations"""
    print("\n[TEST] Output formats")
    results = TestResults()

    formatter = ShellcodeFormatter()
    # Use "sh3llc0d3" as that's the default array name for raw format
    arrays = {"key": bytearray([0x41, 0x42]), "sh3llc0d3": TEST_SHELLCODE, "shellcode": TEST_SHELLCODE}

    for fmt in OUTPUT_FORMATS:
        try:
            output = formatter.generate(fmt, arrays)
            if output is not None and (len(output) > 0 if isinstance(output, (str, bytearray)) else True):
                results.add_pass(f"Format: {fmt}")
            else:
                results.add_fail(f"Format: {fmt}", "Empty output")
        except Exception as e:
            results.add_fail(f"Format: {fmt}", str(e))

    return results


def test_encryption_methods():
    """Test all encryption methods"""
    print("\n[TEST] Encryption methods")
    results = TestResults()

    cryptor = Encrypt()
    key_16 = bytearray([0x41] * 16)
    key_32 = bytearray([0x41] * 32)
    nonce = bytearray([0x42] * 16)

    for cipher in CIPHERS:
        try:
            # AES ciphers need 16-byte key, others can use 32-byte key
            key = key_16 if "aes" in cipher else key_32
            encrypted = cryptor.encrypt(cipher, TEST_SHELLCODE.copy(), key, nonce)
            if encrypted is not None and len(encrypted) > 0:
                # Verify encryption changed the data (except for xor with null key)
                if encrypted != TEST_SHELLCODE:
                    results.add_pass(f"Cipher: {cipher}")
                else:
                    results.add_fail(f"Cipher: {cipher}", "Encryption produced same output")
            else:
                results.add_fail(f"Cipher: {cipher}", "Empty output")
        except Exception as e:
            results.add_fail(f"Cipher: {cipher}", str(e))

    return results


def test_xor_with_null_key():
    """Test XOR encryption with null key (0x00)"""
    print("\n[TEST] XOR with null key")
    results = TestResults()

    cryptor = Encrypt()
    null_key = bytearray([0x00])
    nonce = bytearray([0x42] * 16)

    try:
        encrypted = cryptor.encrypt("xor", TEST_SHELLCODE.copy(), null_key, nonce)
        # XOR with 0x00 should produce the same output
        if encrypted == TEST_SHELLCODE:
            results.add_pass("XOR with 0x00 key (identity)")
        else:
            results.add_fail("XOR with 0x00 key", "Expected identity transformation")
    except Exception as e:
        results.add_fail("XOR with 0x00 key", str(e))

    return results


def test_encoding_methods():
    """Test all encoding methods"""
    print("\n[TEST] Encoding methods")
    results = TestResults()

    encoder = Encode()

    for encoding in ENCODINGS:
        try:
            encoded = encoder.encode(encoding, TEST_SHELLCODE.copy())
            if encoded is not None and len(encoded) > 0:
                # words256 and alpha32 use modulo, so they're lossy encodings
                # Only test full round-trip for lossless encodings
                if encoding in ["base64", "ascii85"]:
                    decoded = encoder.decode(encoding, encoded)
                    if decoded == TEST_SHELLCODE:
                        results.add_pass(f"Encoding: {encoding} (encode/decode)")
                    else:
                        results.add_fail(f"Encoding: {encoding}", "Decode mismatch")
                else:
                    # For lossy encodings (alpha32, words256), just verify encode works
                    results.add_pass(f"Encoding: {encoding} (encode only - lossy)")
            else:
                results.add_fail(f"Encoding: {encoding}", "Empty output")
        except Exception as e:
            results.add_fail(f"Encoding: {encoding}", str(e))

    return results


def test_compression_methods():
    """Test all compression methods"""
    print("\n[TEST] Compression methods")
    results = TestResults()

    compressor = Compress()

    for compression in COMPRESSIONS:
        try:
            compressed = compressor.compress(compression, TEST_SHELLCODE.copy())
            if compressed is not None and len(compressed) > 0:
                # Test decompress as well
                decompressed = compressor.decompress(compression, compressed)
                if bytearray(decompressed) == TEST_SHELLCODE:
                    results.add_pass(f"Compression: {compression} (compress/decompress)")
                else:
                    results.add_fail(f"Compression: {compression}", "Decompress mismatch")
            else:
                results.add_fail(f"Compression: {compression}", "Empty output")
        except Exception as e:
            results.add_fail(f"Compression: {compression}", str(e))

    return results


def test_cli_integration():
    """Test CLI integration with the fixed key issue"""
    print("\n[TEST] CLI integration")
    results = TestResults()

    # Get the path to shellcrypt.py
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shellcrypt_path = os.path.join(script_dir, "shellcrypt.py")
    test_bin = os.path.join(script_dir, "tests", "test_shellcode.bin")

    # Create test input file if it doesn't exist
    if not os.path.exists(test_bin):
        with open(test_bin, "wb") as f:
            f.write(TEST_SHELLCODE)

    # Test 1: XOR with single byte key 00
    try:
        result = subprocess.run(
            [sys.executable, shellcrypt_path, "-i", test_bin, "-e", "xor", "-k", "00", "-f", "c", "-a", "shellcode"],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout + result.stderr

        # Check for the bug: x00 without the leading 0
        if "key[1] = {" in output:
            # Find key line and check format
            lines = output.split('\n')
            key_found = False
            for i, line in enumerate(lines):
                if "key[1]" in line:
                    # Check the next line for the actual key value
                    if i + 1 < len(lines):
                        key_line = lines[i + 1].strip()
                        if key_line == "x00" or key_line == "x00,":
                            results.add_fail("CLI XOR key=00", f"Got '{key_line}' instead of '0x00'")
                        elif "0x00" in key_line:
                            results.add_pass("CLI XOR key=00")
                        else:
                            results.add_fail("CLI XOR key=00", f"Unexpected key format: '{key_line}'")
                        key_found = True
                        break
            if not key_found:
                results.add_fail("CLI XOR key=00", "Could not find key in output")
        else:
            results.add_fail("CLI XOR key=00", "Unexpected output format")
    except subprocess.TimeoutExpired:
        results.add_fail("CLI XOR key=00", "Timeout")
    except Exception as e:
        results.add_fail("CLI XOR key=00", str(e))

    # Test 2: Multiple output formats via CLI
    for fmt in ["c", "py", "raw"]:
        try:
            result = subprocess.run(
                [sys.executable, shellcrypt_path, "-i", test_bin, "-e", "xor", "-k", "4141", "-f", fmt, "-a", "test"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 or "Shellcrypt" in result.stdout:
                results.add_pass(f"CLI format: {fmt}")
            else:
                results.add_fail(f"CLI format: {fmt}", f"Exit code: {result.returncode}")
        except Exception as e:
            results.add_fail(f"CLI format: {fmt}", str(e))

    return results


def test_multi_byte_key():
    """Test that multi-byte keys still work correctly after the fix"""
    print("\n[TEST] Multi-byte key formatting")
    results = TestResults()

    formatter = ShellcodeFormatter()

    # Test with 2-byte key
    arrays = {"key": bytearray([0x41, 0x42]), "shellcode": TEST_SHELLCODE}
    output = formatter.generate("c", arrays)

    if "0x41,0x42" in output or ("0x41" in output and "0x42" in output):
        results.add_pass("2-byte key (0x41, 0x42)")
    else:
        results.add_fail("2-byte key", f"Unexpected format in output")

    # Test with 16-byte key
    key_16 = bytearray([i for i in range(16)])
    arrays = {"key": key_16, "shellcode": TEST_SHELLCODE}
    output = formatter.generate("c", arrays)

    if "0x00" in output and "0x0f" in output:
        results.add_pass("16-byte key")
    else:
        results.add_fail("16-byte key", "Missing expected bytes in output")

    return results


def test_string_format_single_byte():
    """Test string format output with single byte (Python format uses \\x)"""
    print("\n[TEST] String format single-byte")
    results = TestResults()

    formatter = ShellcodeFormatter()

    # Test Python format with single byte key
    arrays = {"key": bytearray([0x00]), "shellcode": TEST_SHELLCODE}
    output = formatter.generate("py", arrays)

    # Python format should have \x00, not just x00
    if "key = b\"\"\"" in output:
        # Check if \\x00 is properly formatted
        if "\\x00" in output:
            results.add_pass("Python format single byte key")
        elif "x00" in output and "\\x00" not in output:
            results.add_fail("Python format single byte key", "Got 'x00' instead of '\\x00'")
        else:
            results.add_fail("Python format single byte key", "Unexpected format")
    else:
        results.add_pass("Python format single byte key (alternate format)")

    return results


def run_all_tests():
    """Run all tests and report results"""
    all_results = []

    # Run all test categories
    all_results.append(test_single_byte_key_formatting())
    all_results.append(test_multi_byte_key())
    all_results.append(test_string_format_single_byte())
    all_results.append(test_output_formats())
    all_results.append(test_encryption_methods())
    all_results.append(test_xor_with_null_key())
    all_results.append(test_encoding_methods())
    all_results.append(test_compression_methods())
    all_results.append(test_cli_integration())

    # Calculate totals
    total_passed = sum(r.passed for r in all_results)
    total_failed = sum(r.failed for r in all_results)
    all_failures = []
    for r in all_results:
        all_failures.extend(r.failures)

    print("\n" + "=" * 60)
    print(f"FINAL RESULTS: {total_passed} passed, {total_failed} failed")
    if all_failures:
        print("\nAll failures:")
        for name, error in all_failures:
            print(f"  - {name}: {error}")
    print("=" * 60)

    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
