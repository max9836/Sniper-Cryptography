package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"main/cryptography/encryption"
	"main/cryptography/hashing"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func getOptionValueSecure(args []string, option string) []byte {
	for i, arg := range args {
		if strings.HasPrefix(arg, option) {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				return []byte(parts[1])
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				return []byte(args[i+1])
			}
		}
	}
	return nil
}

func getOptionFlag(args []string, flag string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, flag) {
			return true
		}
	}
	return false
}

func aeshandler_encrypt(inputType string, args []string) []byte {
	iv := encryption.IVgenbyte(16)
	if len(iv) != aes.BlockSize {
		fmt.Println("Invalid IV length")
		os.Exit(1)
	}
	var encrypted []byte
	if strings.EqualFold(inputType, "text") {
		input := getOptionValueSecure(args, "--in")
		key := getOptionValueSecure(args, "--key")
		var err error
		encrypted, err = encryption.AESEncryptDecrypt(true, input, key, iv)
		if err != nil {
			fmt.Println("Failed to encrypt text:", err)
			os.Exit(1)
		}
	} else if strings.EqualFold(inputType, "file") {
		read, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			fmt.Println("File not found:", err)
			os.Exit(1)
		}
		encrypted, err = encryption.AESEncryptDecrypt(true, read, getOptionValueSecure(args, "--key"), iv)
		if err != nil {
			fmt.Println("Failed to encrypt file:", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Unknown type:", inputType)
		os.Exit(1)
	}
	return append(encrypted, iv...)
}

func aeshandler_decrypt(inputType string, args []string) {
	if strings.EqualFold(inputType, "text") {
		encodedInput := string(getOptionValueSecure(args, "--in"))
		content, err := base64.StdEncoding.DecodeString(encodedInput)
		if err != nil {
			fmt.Println("Failed to decode input:", err)
			return
		}
		iv := content[len(content)-aes.BlockSize:]
		key := getOptionValueSecure(args, "--key")
		content = content[:len(content)-16]
		decrypted, err := encryption.AESEncryptDecrypt(false, content, key, iv)
		if err != nil {
			fmt.Println("Failed to decrypt text:", err)
			return
		}
		fmt.Println("Decrypted text:", string(decrypted))
	} else if strings.EqualFold(inputType, "file") {
		content, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			fmt.Println("Failed to read input file:", err)
			os.Exit(1)
		}
		if err != nil {
			fmt.Println("FAILED TO DECRYPT:", "INVAILD KEY")
			fmt.Println("Sub-error:", err)
			return
		}

		iv := content[len(content)-aes.BlockSize:]
		content = content[:len(content)-aes.BlockSize]

		key := getOptionValueSecure(args, "--key")
		decrypted, err := encryption.AESEncryptDecrypt(false, content, key, iv)
		if err != nil {
			fmt.Println("Failed to decrypt file:", err)
			return
		}

		outputPath := strings.TrimSuffix(string(getOptionValueSecure(args, "--in")), ".enc")
		err = os.WriteFile(filepath.Clean(outputPath), decrypted, 0744)
		if err != nil {
			fmt.Println("Failed to write decrypted file:", err)
		}
	}
}

func rsakeygenhandler(args []string) {
	mode := getOptionValueSecure(args, "--mode")
	if mode == nil {
		panic("value of --mode not found")
	}
	length, lengthPresent := getOptionValue(args, "--length", false)
	if !lengthPresent {
		length = "4096"
	}
	len, err := strconv.Atoi(length)
	if err != nil {
		println("--length contains value that is not a number")
		panic(err)
	}
	println("Generating Keys...")
	publicKeyPEM, privateKeyPEM, err := encryption.RSAKeygen(len)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("private.pem", privateKeyPEM, 0600) // Permissions: read/write for owner only
	if err != nil {
		fmt.Println("Error writing private key to file:", err)
		return
	}
	err = os.WriteFile("public.pem", publicKeyPEM, 0644) // Permissions: read for everyone
	if err != nil {
		fmt.Println("Error writing public key to file:", err)
		return
	}
	println("Key successfully generated and stored in private.pem and public.pem")
}

func Rsahandler_encrypt(inputType string, args []string) []byte {
	var encrypted []byte
	if strings.EqualFold(inputType, "text") {
		key, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--key"))))
		if err != nil {
			panic(err)
		}
		encrypted, err = encryption.RSAencryptdecrypt(true, key, getOptionValueSecure(args, "--in"))
		if err != nil {
			panic(err)
		}
	} else if strings.EqualFold(inputType, "file") {
		println("WARNING: It is not recommented to use RSA encryption for a file.")
		content, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			panic(err)
		}
		key, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--key"))))
		if err != nil {
			panic(err)
		}
		encrypted, err = encryption.RSAencryptdecrypt(true, key, content)
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Unknown type:", inputType)
		os.Exit(1)
	}
	return encrypted
}

func Rsahandler_decrypt(inputType string, args []string) {
	privatekey, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--key"))))
	if err != nil {
		panic(err)
	}
	if strings.EqualFold(inputType, "text") {
		decrypted, err := encryption.RSAencryptdecrypt(false, privatekey, getOptionValueSecure(args, "--in"))
		if err != nil {
			panic(err)
		}
		println("Decrypted string:", string(decrypted))
	} else if strings.EqualFold(inputType, "file") {
		infile, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			panic(err)
		}
		decrypted, err := encryption.RSAencryptdecrypt(false, privatekey, infile)
		if err != nil {
			fmt.Println("Failed to write decrypted file:", err)
		}
		outputPath := strings.TrimSuffix(string(getOptionValueSecure(args, "--in")), ".enc")
		err = os.WriteFile(filepath.Clean(outputPath), decrypted, 0744)
		if err != nil {
			fmt.Println("Failed to write decrypted file:", err)
		}
		return
	}
}

func uachandler_encrypt(inputType string, args []string) []byte {
	iv := encryption.IVgenbyte(32)
	var encrypted []byte
	var err error
	if strings.EqualFold(inputType, "text") {
		encrypted, err = encryption.UacEncryptDecrypt(true, getOptionValueSecure(args, "--in"), getOptionValueSecure(args, "--key"), iv)
		if err != nil {
			panic(err)
		}
	} else if strings.EqualFold(inputType, "file") {
		content, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			panic(err)
		}
		encrypted, err = encryption.UacEncryptDecrypt(true, content, getOptionValueSecure(args, "--key"), iv)
		if err != nil {
			panic(err)
		}
	} else {
		panic("Type can either be text or file")
	}
	return append(encrypted, iv...)
}

func uachandler_decrypt(inputType string, args []string) {
	var decrypted []byte
	if strings.EqualFold(inputType, "text") {
		encodedInput := string(getOptionValueSecure(args, "--in"))
		content, err := base64.StdEncoding.DecodeString(encodedInput)
		if err != nil {
			panic(err)
		}
		iv := content[len(content)-32:]
		key := getOptionValueSecure(args, "--key")
		content = content[:len(content)-32]
		decrypted, err = encryption.UacEncryptDecrypt(false, content, key, iv)
		if err != nil {
			panic(err)
		}
		println("Decrypted Text:", string(decrypted))
	} else if strings.EqualFold(inputType, "file") {
		content, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			fmt.Println("FAILED TO DECRYPT:", "INVAILD KEY")
			fmt.Println("Sub-error:", err)
			return
		}
		iv := content[len(content)-32:]
		content = content[:len(content)-32]
		key := getOptionValueSecure(args, "--key")
		decrypted, err := encryption.UacEncryptDecrypt(false, content, key, iv)
		if err != nil {
			fmt.Println("Failed to decrypt file:", err)
			return
		}
		outputPath := strings.TrimSuffix(string(getOptionValueSecure(args, "--in")), ".enc")
		err = os.WriteFile(filepath.Clean(outputPath), decrypted, 0744)
		if err != nil {
			fmt.Println("Failed to write decrypted file:", err)
		} else {
			fmt.Println("File successfully decrypted and stored at", outputPath)
		}
	}
}

func xorhandler_encrypt(inputType string, args []string) []byte {
	var encrypted []byte
	if strings.EqualFold(inputType, "text") {
		encrypted = encryption.XOREncryptDecrypt(getOptionValueSecure(args, "--in"), getOptionValueSecure(args, "--key"))
	} else if strings.EqualFold(inputType, "file") {
		content, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			fmt.Println("Failed to read input file:", err)
			os.Exit(1)
		}
		encrypted = encryption.XOREncryptDecrypt(content, getOptionValueSecure(args, "--key"))
	} else {
		fmt.Println("Type can either be text or file")
		os.Exit(1)
	}
	return encrypted
}

func xorhandler_decrypt(inputType string, args []string) {
	var decrypted []byte
	if strings.EqualFold(inputType, "text") {
		decrypted = encryption.XOREncryptDecrypt(getOptionValueSecure(args, "--in"), getOptionValueSecure(args, "--key"))
	} else if strings.EqualFold(inputType, "file") {
		content, err := os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			fmt.Println("Failed to read input file:", err)
			os.Exit(1)
		}
		decrypted = encryption.XOREncryptDecrypt(content, getOptionValueSecure(args, "--key"))
		outputPath := strings.TrimSuffix(string(getOptionValueSecure(args, "--in")), ".enc")
		err = os.WriteFile(filepath.Clean(outputPath), decrypted, 0744)
		if err != nil {
			fmt.Println("Failed to write decrypted file:", err)
			os.Exit(1)
		} else {
			fmt.Println("File successfully decrypted and stored at", outputPath)
			return
		}
	} else {
		fmt.Println("Type can either be text or file")
		os.Exit(1)
	}
	fmt.Println("Decrypted Text:", string(decrypted))
}

func sha_handler(inputType string, args []string) []byte {
	mode := string(getOptionValueSecure(args, "--mode"))
	var content []byte
	if strings.EqualFold(inputType, "file") {
		var err error
		content, err = os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			panic(err)
		}
	} else if strings.EqualFold(inputType, "text") {
		content = getOptionValueSecure(args, "--in")
	} else {
		panic("Unknown type: " + inputType)
	}
	var hashed []byte
	switch {
	case strings.EqualFold(mode, "sha3-256"):
		hashed = hashing.HashSHA3_256(content)
	case strings.EqualFold(mode, "sha3-512"):
		hashed = hashing.HashSHA3_512(content)
	case strings.EqualFold(mode, "sha2-256"):
		hashed = hashing.HashSHA2_256(content)
	case strings.EqualFold(mode, "sha2-512"):
		hashed = hashing.HashSHA2_512(content)
	default:
		panic("Unknown mode: " + mode)
	}
	return hashed
}
func shake_handler(inputType string, args []string) []byte {
	length := string(getOptionValueSecure(args, "--length"))
	len, err := strconv.Atoi(length)
	if err != nil {
		panic("The input --length is not a valid number")
	}
	var content []byte
	if strings.EqualFold(inputType, "file") {
		var err error
		content, err = os.ReadFile(path.Clean(string(getOptionValueSecure(args, "--in"))))
		if err != nil {
			panic(err)
		}
	} else if strings.EqualFold(inputType, "text") {
		content = getOptionValueSecure(args, "--in")
	} else {
		panic("Unknown type: " + inputType)
	}
	hashed := hashing.HashSHAKE256(content, len)
	return hashed
}
