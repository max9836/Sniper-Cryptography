package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func getOptionValue(args []string, option string, secr bool) (string, bool) {
	for i, arg := range args {
		if strings.HasPrefix(arg, option) {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				if !secr {
					return parts[1], true
				} else {
					return "", true
				}
			}

			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				if !secr {
					return args[i+1], true
				} else {
					return "", true
				}
			}
		}
	}
	return "", false
}

func waitForExit() {
	fmt.Println("\nPress Enter to exit.")
	var input string
	fmt.Scanln(&input)
}
func main() {
	args := os.Args[1:]
	println(" ")
	if len(args) > 0 {
		command := args[0]
		mode, modePresent := getOptionValue(args, "--mode", false)
		inputType, typePresent := getOptionValue(args, "--type", false)
		_, inputPresent := getOptionValue(args, "--in", true)
		var encrypted = []byte("Failed to encrypt string")
		switch {
		case strings.EqualFold(command, "help") || strings.EqualFold(command, "--help") || strings.EqualFold(command, "-h") || strings.EqualFold(command, "-help"):
			fmt.Print(help)
			return
		case strings.EqualFold(command, "encrypt"):
			_, keyPresent := getOptionValue(args, "--key", true)
			if !modePresent || !typePresent || !inputPresent || !keyPresent {
				fmt.Println("You will need to input --mode, --type, --key, and --in")
				return
			}
			switch {
			case strings.EqualFold(mode, "AES"):
				encrypted = aeshandler_encrypt(inputType, args)
			case strings.EqualFold(mode, "RSA"):
				if string(getOptionValueSecure(args, "--key"))[len(string(getOptionValueSecure(args, "--key")))-4:] != ".pem" {
					panic("Only .pem file is accepted")
				}
				encrypted = Rsahandler_encrypt(inputType, args)
			case strings.EqualFold(mode, "UAC"):
				// Unified Advanced Cipher (UAC)
				encrypted = uachandler_encrypt(inputType, args)
			case strings.EqualFold(mode, "XOR"):
				if len(string(getOptionValueSecure(args, "--key"))) < 16 {
					fmt.Println("The security of XOR operation heavily depends on the key length. Using a key length less than 16 bytes is not recommended.")
					fmt.Println(" ")
				}
				encrypted = xorhandler_encrypt(inputType, args)
			default:
				fmt.Println(string(encrypted))
				panic("--type must be AES / RSA / UAC / XOR")
			}
			if strings.EqualFold(inputType, "file") {
				path := string(getOptionValueSecure(args, "--in"))
				path = fmt.Sprint(path, ".sef")
				os.Create(filepath.Clean(path))
				os.WriteFile(filepath.Clean(path), encrypted, 0744)
				fmt.Println("File successfully encrypted and stored at", path)
			} else if strings.EqualFold(inputType, "text") {
				fmt.Println("Encrypted String:", base64.StdEncoding.EncodeToString(encrypted))
			}
		case strings.EqualFold(command, "decrypt"):
			_, keyPresent := getOptionValue(args, "--key", true)
			if !modePresent || !typePresent || !inputPresent || !keyPresent {
				fmt.Println("You will need to input --mode, --type, --key, and --in")
				return
			}
			switch {
			case strings.EqualFold(mode, "AES"):
				aeshandler_decrypt(inputType, args)
			case strings.EqualFold(mode, "RSA"):
				Rsahandler_decrypt(inputType, args)
			case strings.EqualFold(mode, "UAC"):
				uachandler_decrypt(inputType, args)
			case strings.EqualFold(mode, "XOR"):
				xorhandler_decrypt(inputType, args)
			}
		case strings.EqualFold(command, "keygen"):
			if !modePresent {
				fmt.Println("You will need to input --mode")
				return
			}
			if strings.EqualFold(mode, "rsa") {
				rsakeygenhandler(args)
			} else {
				fmt.Println("Unknown mode:", mode)
			}
		case strings.EqualFold(command, "license"):
			println(license)
			return
		case strings.EqualFold(command, "hash"):
			_, lengthPresent := getOptionValue(args, "--length", false)
			if !modePresent || !typePresent || !inputPresent || (strings.EqualFold(mode, "SHAKE-256") && !lengthPresent) {
				fmt.Print("You will need to input --mode / --type / --in")
				if strings.EqualFold(mode, "SHAKE-256") && !lengthPresent {
					fmt.Print(" / --length")
				}
				fmt.Println()
				return
			}
			sha_regex := regexp.MustCompile(`(?i)sha[23]-(256|512)$`)
			var hashed []byte
			if sha_regex.MatchString(mode) {
				hashed = sha_handler(inputType, args)
			} else if strings.EqualFold(mode, "SHAKE-256") {
				hashed = shake_handler(inputType, args)
			} else {
				panic("Unknown mode:" + mode)
			}
			println("Hashed string: ", hex.EncodeToString(hashed))
		default:
			fmt.Printf("Unknown command: %s\n", command)
		}
	} else {
		fmt.Println("Please input a command.")
		fmt.Println("Try type 'help' for help")
		waitForExit()
	}
	println(" ")
}
