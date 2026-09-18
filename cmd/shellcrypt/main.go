package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/iilegacyyii/shellcrypt/internal/cipher"
	"github.com/iilegacyyii/shellcrypt/internal/formatter"
	"github.com/spf13/cobra"
)

const Version = "1.0.0"

var (
	input   string
	encrypt string
	key     string
	nonce   string
	format  string
	formats bool
	ciphers bool
	output  string
	version string
)

var rootCmd = cobra.Command{
	Use: "shellcrypt",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ciphers {
			fmt.Println("Valid ciphers:")
			fmt.Println("- " + strings.Join(cipher.Ciphers(), "\n- "))
			return nil
		}

		if formats {
			fmt.Println("Valid formats:")
			fmt.Println("- " + strings.Join(formatter.Formats(), "\n- "))
			return nil
		}

		if input == "" {
			return fmt.Errorf("no input file specified, specify via -i <filepath> / --input <filepath>")
		}

		plaintext, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("invalid input: %w", err)
		}

		// if key or nonce are not specified, generate a random value for each.
		spec, err := cipher.Spec(encrypt)
		if err != nil {
			return err
		}

		if key == "" {
			key = randomHex(spec.KeySize)
		}
		if nonce == "" && spec.NonceSize > 0 {
			nonce = randomHex(spec.NonceSize)
		}

		k, err := hex.DecodeString(key)
		if err != nil {
			return fmt.Errorf("invalid key: %w", err)
		}

		n, err := hex.DecodeString(nonce)
		if err != nil {
			return fmt.Errorf("invalid nonce: %w", err)
		}

		c, err := cipher.NewCipher(encrypt, k, n)
		if err != nil {
			return err
		}

		f, err := formatter.NewFormatter(format)
		if err != nil {
			return err
		}

		buf, err := c.Encrypt(plaintext)
		if err != nil {
			return fmt.Errorf("error during encryption: %w", err)
		}

		result := f.Generate(buf, k, n)

		if output != "" {
			err := os.WriteFile(output, []byte(result), 0644)
			if err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		} else {
			if format == "raw" {
				return fmt.Errorf("raw format requires output file path to be specified")
			}
			fmt.Println(result)
		}

		return nil
	},
}

func init() {
	rootCmd.Flags().StringVarP(&input, "input", "i", "", "path to file to be encrypted")
	rootCmd.Flags().StringVarP(&encrypt, "encrypt", "e", "xor", "encryption method to use")
	rootCmd.Flags().StringVarP(&key, "key", "k", "", "encryption key in hex format (default: random)")
	rootCmd.Flags().StringVarP(&nonce, "nonce", "n", "", "encryption nonce in hex format (default: random)")
	rootCmd.Flags().StringVarP(&format, "format", "f", "", "output format to use")
	rootCmd.Flags().BoolVar(&formats, "formats", false, "show a list of valid formats")
	rootCmd.Flags().BoolVar(&ciphers, "ciphers", false, "show a list of valid ciphers")
	rootCmd.Flags().StringVarP(&output, "output", "o", "", "path to output file")
	rootCmd.Version = version
	rootCmd.SetVersionTemplate("shellcrypt v{{.Version}}\n")
}

func randomHex(length int) string {
	buf := make([]byte, length)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
